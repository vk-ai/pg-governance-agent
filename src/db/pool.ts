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

export async function withClient<T>(
  creds: DbCredentials,
  fn: (client: pg.PoolClient) => Promise<T>,
): Promise<T> {
  const p = await getPool(creds);
  const client = await p.connect();
  try {
    return await fn(client);
  } finally {
    client.release();
  }
}
