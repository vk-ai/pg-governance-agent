import pg from "pg";
import type { DbCredentials } from "../secrets/types.js";
import { log } from "../utils/logger.js";

const { Pool } = pg;

let pool: pg.Pool | null = null;
let currentUser: string | null = null;

export function buildConnectionConfig(creds: DbCredentials): pg.PoolConfig {
  const ssl =
    creds.sslmode && creds.sslmode !== "disable"
      ? { rejectUnauthorized: creds.sslmode === "verify-full" }
      : undefined;
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

export async function getPool(creds: DbCredentials): Promise<pg.Pool> {
  if (pool && currentUser === creds.user) return pool;
  if (pool) {
    await pool.end().catch(() => undefined);
    pool = null;
  }
  pool = new Pool(buildConnectionConfig(creds));
  currentUser = creds.user;
  pool.on("error", (err) => log("error", "pg_pool_error", { error: err.message }));
  return pool;
}

export async function closePool(): Promise<void> {
  if (pool) {
    await pool.end().catch(() => undefined);
    pool = null;
    currentUser = null;
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
export async function withReadOnlyTransaction<T>(
  creds: DbCredentials,
  fn: (client: pg.PoolClient) => Promise<T>,
  opts?: { sessionGucs?: Record<string, string>; timeouts?: ReadTxnOptions },
): Promise<T> {
  return readOnlyTransactionOn(async () => (await getPool(creds)).connect(), fn, opts);
}

/** Same as {@link withReadOnlyTransaction} with an injectable checkout (unit tests). */
export async function readOnlyTransactionOn<T>(
  connect: () => Promise<pg.PoolClient>,
  fn: (client: pg.PoolClient) => Promise<T>,
  opts?: { sessionGucs?: Record<string, string>; timeouts?: ReadTxnOptions },
): Promise<T> {
  const client = await connect();
  let releaseErr: Error | undefined;
  try {
    await client.query("BEGIN READ ONLY");
    try {
      await applyLocalTimeouts(client, opts?.timeouts);
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

/**
 * Check out a client for write paths (DML/DDL).
 *
 * When principal GUCs are present the work runs in `BEGIN ... COMMIT` so the
 * transaction-local GUCs are still set when the user's statement runs (RLS
 * sees the principal). Without GUCs the statement runs as before (autocommit),
 * which keeps DDL like `CREATE INDEX CONCURRENTLY` working.
 */
export async function withClient<T>(
  creds: DbCredentials,
  fn: (client: pg.PoolClient) => Promise<T>,
  opts?: { sessionGucs?: Record<string, string> },
): Promise<T> {
  return clientOn(async () => (await getPool(creds)).connect(), fn, opts);
}

/** Same as {@link withClient} with an injectable checkout (unit tests). */
export async function clientOn<T>(
  connect: () => Promise<pg.PoolClient>,
  fn: (client: pg.PoolClient) => Promise<T>,
  opts?: { sessionGucs?: Record<string, string> },
): Promise<T> {
  const client = await connect();
  const gucs = opts?.sessionGucs;
  if (!gucs || Object.keys(gucs).length === 0) {
    try {
      return await fn(client);
    } finally {
      client.release();
    }
  }
  let releaseErr: Error | undefined;
  try {
    await client.query("BEGIN");
    try {
      await applySessionGucs(client, gucs);
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
