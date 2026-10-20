import fs from "node:fs";
import pg from "pg";
import type { DbCredentials } from "../secrets/types.js";
import { log } from "../utils/logger.js";
import { searchPathValue } from "../policy/schemaGuard.js";

const { Pool } = pg;

let pool: pg.Pool | null = null;
let currentKey: string | null = null;

/** Extra TLS inputs for {@link sslConfigFor}. */
export interface TlsInputs {
  /** PEM CA bundle text (from sslrootcert). Replaces the system store, like libpq. */
  ca?: string;
  /** Hostname to verify (and send as SNI) when the socket targets a pinned IP. */
  servername?: string;
}

/**
 * libpq sslmode → node-pg TLS options.
 * verify-ca / verify-full: certificate chain must validate (rejectUnauthorized).
 * verify-ca skips only the hostname check, matching libpq. require/prefer/allow
 * encrypt without verifying, as in libpq. Unknown modes are refused.
 * With a pinned IP, verify-full checks the certificate against `servername`.
 */
export function sslConfigFor(sslmode: string | undefined, tls: TlsInputs = {}): pg.PoolConfig["ssl"] {
  const mode = (sslmode || "").trim().toLowerCase();
  if (!mode || mode === "disable") return undefined;
  const extra: Record<string, unknown> = {};
  if (tls.ca) extra.ca = tls.ca;
  if (tls.servername) extra.servername = tls.servername;
  if (mode === "verify-full") return { rejectUnauthorized: true, ...extra };
  if (mode === "verify-ca") {
    return { rejectUnauthorized: true, ...extra, checkServerIdentity: () => undefined };
  }
  if (mode === "require" || mode === "prefer" || mode === "allow") return { rejectUnauthorized: false };
  throw new Error(`Unsupported sslmode: ${sslmode}`);
}

function readCa(path: string | undefined): string | undefined {
  if (!path) return undefined;
  try {
    return fs.readFileSync(path, "utf8");
  } catch (e) {
    throw new Error(`Cannot read sslrootcert ${path}: ${e instanceof Error ? e.message : String(e)}`);
  }
}

export function buildConnectionConfig(creds: DbCredentials): pg.PoolConfig {
  const mode = (creds.sslmode || "").trim().toLowerCase();
  const verifying = mode === "verify-full" || mode === "verify-ca";
  const ssl = sslConfigFor(creds.sslmode, {
    ca: verifying ? readCa(creds.sslrootcert) : undefined,
    servername: creds.tlsServername,
  });
  return {
    host: creds.host,
    port: creds.port,
    database: creds.database,
    user: creds.user,
    password: creds.password,
    max: 5,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000,
    ssl,
  };
}

function poolKey(c: DbCredentials): string {
  return JSON.stringify([c.user, c.host, c.port, c.database, c.sslmode ?? "", c.sslrootcert ?? "", c.tlsServername ?? ""]);
}

export async function getPool(creds: DbCredentials): Promise<pg.Pool> {
  const key = poolKey(creds);
  if (pool && currentKey === key) return pool;
  if (pool) {
    await pool.end().catch(() => undefined);
    pool = null;
  }
  pool = new Pool(buildConnectionConfig(creds));
  currentKey = key;
  pool.on("error", (err) => log("error", "pg_pool_error", { error: err.message }));
  return pool;
}

export async function closePool(): Promise<void> {
  if (pool) {
    await pool.end().catch(() => undefined);
    pool = null;
    currentKey = null;
  }
}

/** Timeouts applied with SET LOCAL semantics inside each read transaction (ms; 0 = disabled). */
export interface ReadTxnOptions {
  statementTimeoutMs?: number;
  lockTimeoutMs?: number;
  idleInTransactionSessionTimeoutMs?: number;
}

const GUC_NAME_RE = /^[a-zA-Z_][a-zA-Z0-9_.]*$/;

/**
 * Apply transaction-local GUCs for RLS (never SET ROLE).
 *
 * `set_config(name, value, true)` is the function form of `SET LOCAL`: the value
 * lives until the end of the *current transaction*. Callers must therefore run
 * this after `BEGIN` and run the user's SQL in the same transaction. Outside a
 * transaction block the value is gone as soon as the set_config statement ends.
 */
export async function applySessionGucs(
  client: pg.PoolClient,
  gucs: Record<string, string>,
): Promise<void> {
  for (const [name, value] of Object.entries(gucs)) {
    if (!GUC_NAME_RE.test(name)) {
      throw new Error(`Refusing invalid GUC name: ${name}`);
    }
    await client.query("SELECT set_config($1, $2, true)", [name, value]);
  }
}

function timeoutValue(ms: number | undefined): string | null {
  if (ms === undefined || ms === null) return null;
  const n = Number(ms);
  if (!Number.isFinite(n) || n < 0) {
    throw new Error(`Refusing invalid timeout: ${String(ms)}`);
  }
  return String(Math.floor(n));
}

/** SET LOCAL statement_timeout / lock_timeout / idle_in_transaction_session_timeout. */
export async function applyLocalTimeouts(
  client: pg.PoolClient,
  opts: ReadTxnOptions = {},
): Promise<void> {
  const pairs: [string, number | undefined][] = [
    ["statement_timeout", opts.statementTimeoutMs],
    ["lock_timeout", opts.lockTimeoutMs],
    ["idle_in_transaction_session_timeout", opts.idleInTransactionSessionTimeoutMs],
  ];
  for (const [name, ms] of pairs) {
    const v = timeoutValue(ms);
    if (v === null) continue;
    await client.query("SELECT set_config($1, $2, true)", [name, v]);
  }
}

/**
 * Transaction-local search_path (phase 3). The schema guard assumes unqualified
 * names resolve through exactly these schemas (plus implicit pg_catalog), so
 * PgGuard sets it rather than trusting the role default.
 */
export async function applyLocalSearchPath(client: pg.PoolClient, schemas: readonly string[] | undefined | null): Promise<void> {
  if (!schemas) return;
  await client.query("SELECT set_config('search_path', $1, true)", [searchPathValue(schemas)]);
}

async function rollbackQuietly(client: pg.PoolClient): Promise<Error | undefined> {
  try {
    await client.query("ROLLBACK");
    return undefined;
  } catch (e) {
    return e instanceof Error ? e : new Error(String(e));
  }
}

/**
 * Run `fn` inside `BEGIN READ ONLY ... ROLLBACK` so Postgres itself rejects
 * writes, with transaction-local timeouts and principal GUCs applied in the
 * same transaction as the user's query.
 *
 * Order: BEGIN READ ONLY → timeouts → principal GUCs → fn → ROLLBACK.
 * Always rolls back (reads have nothing to commit). If ROLLBACK itself fails
 * the connection is destroyed instead of being returned to the pool.
 */
export interface ReadTxnCallOptions {
  sessionGucs?: Record<string, string>;
  timeouts?: ReadTxnOptions;
  /** SET LOCAL search_path (schema guard); omitted = role default. */
  searchPath?: readonly string[] | null;
}

export async function withReadOnlyTransaction<T>(
  creds: DbCredentials,
  fn: (client: pg.PoolClient) => Promise<T>,
  opts?: ReadTxnCallOptions,
): Promise<T> {
  return readOnlyTransactionOn(async () => (await getPool(creds)).connect(), fn, opts);
}

/** Same as {@link withReadOnlyTransaction} with an injectable checkout (unit tests). */
export async function readOnlyTransactionOn<T>(
  connect: () => Promise<pg.PoolClient>,
  fn: (client: pg.PoolClient) => Promise<T>,
  opts?: ReadTxnCallOptions,
): Promise<T> {
  const client = await connect();
  let releaseErr: Error | undefined;
  try {
    await client.query("BEGIN READ ONLY");
    try {
      await applyLocalTimeouts(client, opts?.timeouts);
      await applyLocalSearchPath(client, opts?.searchPath);
      if (opts?.sessionGucs && Object.keys(opts.sessionGucs).length > 0) {
        await applySessionGucs(client, opts.sessionGucs);
      }
      return await fn(client);
    } finally {
      releaseErr = await rollbackQuietly(client);
    }
  } finally {
    client.release(releaseErr);
  }
}

/** Options for {@link withClient} / {@link clientOn} (DDL and other write paths). */
export interface ClientOpts {
  sessionGucs?: Record<string, string>;
  /** Transaction-local timeouts (same GUCs as read/DML paths). Applied even on the autocommit path via SET, then reset. */
  timeouts?: ReadTxnOptions;
  /** search_path for the statement (schema guard). Session SET + RESET on autocommit, SET LOCAL in a txn. */
  searchPath?: readonly string[] | null;
}

/**
 * Check out a client for write paths (DML/DDL).
 *
 * When principal GUCs are present the work runs in `BEGIN ... COMMIT` so the
 * transaction-local GUCs are still set when the user's statement runs (RLS
 * sees the principal). Without GUCs the statement runs as before (autocommit),
 * which keeps DDL like `CREATE INDEX CONCURRENTLY` working — timeouts are still
 * applied with session `SET` and cleared in `finally` so the pooled connection
 * is clean.
 */
export async function withClient<T>(
  creds: DbCredentials,
  fn: (client: pg.PoolClient) => Promise<T>,
  opts?: ClientOpts,
): Promise<T> {
  return clientOn(async () => (await getPool(creds)).connect(), fn, opts);
}

/** Apply timeouts outside a transaction (session SET) for autocommit DDL. */
async function applySessionTimeouts(
  client: pg.PoolClient,
  opts: ReadTxnOptions = {},
): Promise<string[]> {
  const restored: string[] = [];
  const pairs: [string, number | undefined][] = [
    ["statement_timeout", opts.statementTimeoutMs],
    ["lock_timeout", opts.lockTimeoutMs],
    ["idle_in_transaction_session_timeout", opts.idleInTransactionSessionTimeoutMs],
  ];
  for (const [name, ms] of pairs) {
    const v = timeoutValue(ms);
    if (v === null) continue;
    await client.query(`SET ${name} = ${quoteTimeout(v)}`);
    restored.push(name);
  }
  return restored;
}

function quoteTimeout(v: string): string {
  // timeoutValue returns a non-negative integer string (ms)
  if (!/^\d+$/.test(v)) throw new Error(`Refusing invalid timeout literal: ${v}`);
  return v === "0" ? "0" : `'${v}ms'`;
}

async function resetSessionTimeouts(client: pg.PoolClient, names: string[]): Promise<void> {
  for (const name of names) {
    await client.query(`RESET ${name}`).catch(() => undefined);
  }
}

/** Same as {@link withClient} with an injectable checkout (unit tests). */
export async function clientOn<T>(
  connect: () => Promise<pg.PoolClient>,
  fn: (client: pg.PoolClient) => Promise<T>,
  opts?: ClientOpts,
): Promise<T> {
  const client = await connect();
  const gucs = opts?.sessionGucs;
  const hasGucs = Boolean(gucs && Object.keys(gucs).length > 0);
  if (!hasGucs) {
    let setNames: string[] = [];
    try {
      if (opts?.timeouts) setNames = await applySessionTimeouts(client, opts.timeouts);
      if (opts?.searchPath) {
        setNames.push("search_path");
        await client.query("SELECT set_config('search_path', $1, false)", [searchPathValue(opts.searchPath)]);
      }
      return await fn(client);
    } finally {
      if (setNames.length) await resetSessionTimeouts(client, setNames);
      client.release();
    }
  }
  let releaseErr: Error | undefined;
  try {
    await client.query("BEGIN");
    try {
      await applyLocalTimeouts(client, opts?.timeouts);
      await applyLocalSearchPath(client, opts?.searchPath);
      await applySessionGucs(client, gucs!);
      const out = await fn(client);
      await client.query("COMMIT");
      return out;
    } catch (e) {
      releaseErr = await rollbackQuietly(client);
      throw e;
    }
  } finally {
    client.release(releaseErr);
  }
}

/** Options for {@link dmlTransactionOn}. */
export interface DmlTxnOptions {
  sessionGucs?: Record<string, string>;
  timeouts?: ReadTxnOptions;
  /** Roll back instead of committing when more rows than this are affected. */
  maxAffectedRows?: number;
  /** Always roll back; report what would have happened. */
  dryRun?: boolean;
  /** Sample rows to return from a RETURNING clause (dry run only). */
  sampleRows?: number;
  /** SET LOCAL search_path (schema guard). */
  searchPath?: readonly string[] | null;
  /**
   * Runs in the same transaction just before the statement (phase 4: consume the
   * approval in the Postgres ledger, so it is spent only if the write commits).
   * Not called for dry runs.
   */
  beforeStatement?: (client: pg.PoolClient) => Promise<void>;
}

export interface DmlTxnResult {
  rowCount: number;
  command: string;
  committed: boolean;
  dryRun: boolean;
  capExceeded: boolean;
  maxAffectedRows?: number;
  sample?: Record<string, unknown>[];
}

/** Raised when a real (non-dry-run) DML would affect more rows than the cap; it was rolled back. */
export class AffectedRowsCapExceeded extends Error {
  constructor(
    public readonly rowCount: number,
    public readonly maxAffectedRows: number,
  ) {
    super(
      `DML would affect ${rowCount} rows, over the max_affected_rows cap of ${maxAffectedRows}; rolled back. ` +
        "Narrow the WHERE clause or use a role with a higher cap.",
    );
    this.name = "AffectedRowsCapExceeded";
  }
}

/**
 * Run one DML statement in `BEGIN ... COMMIT|ROLLBACK`.
 *
 * Order: BEGIN → SET LOCAL timeouts → principal GUCs (RLS) → statement
 * (extended protocol, single statement) → decide. A dry run always rolls back
 * and returns the row count Postgres reported. A real run rolls back and throws
 * {@link AffectedRowsCapExceeded} when the count is over the cap, so the cap is
 * checked on the same snapshot as the write (no preview-then-write race).
 *
 * Rolled-back work is not free: sequences still advance, triggers still run
 * (their writes are undone, external side effects are not) and row locks are
 * held until the rollback. Timeouts bound how long that can take.
 */
export async function dmlTransactionOn(
  connect: () => Promise<pg.PoolClient>,
  sql: string,
  opts: DmlTxnOptions = {},
): Promise<DmlTxnResult> {
  const client = await connect();
  let releaseErr: Error | undefined;
  try {
    await client.query("BEGIN");
    let finished = false;
    try {
      await applyLocalTimeouts(client, opts.timeouts);
      await applyLocalSearchPath(client, opts.searchPath);
      if (opts.sessionGucs && Object.keys(opts.sessionGucs).length > 0) {
        await applySessionGucs(client, opts.sessionGucs);
      }
      if (opts.beforeStatement && !opts.dryRun) await opts.beforeStatement(client);
      const r = await client.query({ text: sql, queryMode: "extended" } as pg.QueryConfig);
      const rowCount = r.rowCount ?? 0;
      const cap = opts.maxAffectedRows;
      const capExceeded = cap !== undefined && cap >= 0 && rowCount > cap;
      const base = {
        rowCount,
        command: String(r.command ?? ""),
        dryRun: Boolean(opts.dryRun),
        capExceeded,
        maxAffectedRows: cap,
      };
      if (opts.dryRun) {
        releaseErr = await rollbackQuietly(client);
        finished = true;
        const n = Math.max(0, opts.sampleRows ?? 5);
        return { ...base, committed: false, sample: (r.rows ?? []).slice(0, n) };
      }
      if (capExceeded) {
        releaseErr = await rollbackQuietly(client);
        finished = true;
        throw new AffectedRowsCapExceeded(rowCount, cap!);
      }
      await client.query("COMMIT");
      finished = true;
      return { ...base, committed: true };
    } catch (e) {
      if (!finished) releaseErr = await rollbackQuietly(client);
      throw e;
    }
  } finally {
    client.release(releaseErr);
  }
}

/** {@link dmlTransactionOn} against the shared pool. */
export async function withDmlTransaction(
  creds: DbCredentials,
  sql: string,
  opts: DmlTxnOptions = {},
): Promise<DmlTxnResult> {
  return dmlTransactionOn(async () => (await getPool(creds)).connect(), sql, opts);
}
