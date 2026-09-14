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

/** Apply transaction-local GUCs for RLS (never SET ROLE). */
export async function applySessionGucs(
  client: pg.PoolClient,
  gucs: Record<string, string>,
): Promise<void> {
  for (const [name, value] of Object.entries(gucs)) {
    if (!/^[a-zA-Z_][a-zA-Z0-9_.]*$/.test(name)) {
      throw new Error(`Refusing invalid GUC name: ${name}`);
    }
    await client.query("SELECT set_config($1, $2, true)", [name, value]);
  }
}

export async function withClient<T>(
  creds: DbCredentials,
  fn: (client: pg.PoolClient) => Promise<T>,
  opts?: { sessionGucs?: Record<string, string> },
): Promise<T> {
  const p = await getPool(creds);
  const client = await p.connect();
  try {
    if (opts?.sessionGucs && Object.keys(opts.sessionGucs).length > 0) {
      await applySessionGucs(client, opts.sessionGucs);
    }
    return await fn(client);
  } finally {
    client.release();
  }
}
