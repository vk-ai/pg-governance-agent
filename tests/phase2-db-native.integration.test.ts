/**
 * Live Postgres 17: DB-native role controls (phase 2 / plan phase 1).
 *
 * - app_reader rejects writes even when the classifier is bypassed (raw pool/SQL)
 * - role-level statement_timeout cancels long work when the app applies no SET LOCAL
 * - preflight rejects a superuser and accepts a hardened reader
 * - DDL withClient applies statement_timeout
 *
 * Skipped unless PGGUARD_IT_DATABASE_URL points at a superuser connection.
 * 04-agent-roles.sql uses ALTER ROLE (cluster-wide); left in place afterward
 * so the box matches a provisioned demo. The short-timeout sleep test restores
 * statement_timeout=15s when it finishes.
 */
import fs from "node:fs";
import path from "node:path";
import pg from "pg";
import { closePool, withClient } from "../src/db/pool.js";
import { runPreflight, assertPreflight, tierFromAllow } from "../src/db/preflight.js";
import type { DbCredentials } from "../src/secrets/types.js";
import { PHASE2_SQL_FILES } from "./helpers/it-auth.js";

const ADMIN_URL = process.env.PGGUARD_IT_DATABASE_URL;
const d = ADMIN_URL ? describe : describe.skip;
const repo = process.cwd();
const dbName = `pgguard_p2_${process.pid}_${Date.now()}`;

function credsFor(user: string): DbCredentials {
  const u = new URL(ADMIN_URL!);
  const passwords: Record<string, string> = {
    app_reader: "reader_demo_pass",
    app_writer: "writer_demo_pass",
    app_migrator: "migrator_demo_pass",
  };
  return {
    host: u.hostname,
    port: Number(u.port || 5432),
    database: dbName,
    user,
    password: passwords[user]!,
    sslmode: "disable",
  };
}

async function pgErr(p: Promise<unknown>): Promise<{ code?: string; message: string }> {
  try {
    await p;
    return { message: "" };
  } catch (e) {
    const err = e as { code?: string; message?: string };
    return { code: err.code, message: err.message || String(e) };
  }
}

d("phase 2 DB-native controls (live Postgres)", () => {
  beforeAll(async () => {
    const admin = new pg.Client({ connectionString: ADMIN_URL });
    await admin.connect();
    await admin.query(`CREATE DATABASE ${dbName}`);
    await admin.end();

    const u = new URL(ADMIN_URL!);
    u.pathname = `/${dbName}`;
    const db = new pg.Client({ connectionString: u.toString() });
    await db.connect();
    for (const f of PHASE2_SQL_FILES) {
      await db.query(fs.readFileSync(path.join(repo, f), "utf8"));
    }
    await db.end();
  }, 60_000);

  afterAll(async () => {
    await closePool();
    const admin = new pg.Client({ connectionString: ADMIN_URL });
    await admin.connect();
    await admin.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
    await admin.end();
  }, 30_000);

  test("WITH ... DELETE via raw client fails for app_reader (classifier bypassed)", async () => {
    const c = new pg.Client({ ...credsFor("app_reader"), ssl: undefined });
    await c.connect();
    try {
      const err = await pgErr(
        c.query(
          `WITH d AS (DELETE FROM corp.orders WHERE id = -1 RETURNING id) SELECT * FROM d`,
        ),
      );
      // read-only txn (25006) or insufficient privilege (42501)
      expect(["25006", "42501"]).toContain(err.code);
    } finally {
      await c.end();
    }
  });

  test("SET TRANSACTION READ WRITE then DELETE still fails (grants remain)", async () => {
    const c = new pg.Client({ ...credsFor("app_reader"), ssl: undefined });
    await c.connect();
    try {
      // Non-superuser can flip the session default; SELECT-only grants are the hard stop.
      await c.query("SET default_transaction_read_only TO off");
      await c.query("BEGIN");
      await c.query("SET TRANSACTION READ WRITE");
      const err = await pgErr(c.query("DELETE FROM corp.orders WHERE id = -1"));
      await c.query("ROLLBACK").catch(() => undefined);
      expect(err.code).toBe("42501");
    } finally {
      await c.end();
    }
  });

  test("nextval fails for app_reader under role default read-only", async () => {
    const c = new pg.Client({ ...credsFor("app_reader"), ssl: undefined });
    await c.connect();
    try {
      const err = await pgErr(c.query("SELECT nextval('corp.orders_id_seq')"));
      expect(["25006", "42501"]).toContain(err.code);
    } finally {
      await c.end();
    }
  });

  test("role statement_timeout cancels pg_sleep when app applies no SET LOCAL", async () => {
    const admin = new pg.Client({ connectionString: ADMIN_URL });
    await admin.connect();
    await admin.query(`ALTER ROLE app_reader SET statement_timeout = '1s'`);
    await admin.end();

    const c = new pg.Client({ ...credsFor("app_reader"), ssl: undefined });
    await c.connect();
    try {
      const err = await pgErr(c.query("SELECT pg_sleep(30)"));
      expect(err.message).toMatch(/statement timeout/i);
      expect(err.code).toBe("57014");
    } finally {
      await c.end();
      const admin2 = new pg.Client({ connectionString: ADMIN_URL });
      await admin2.connect();
      await admin2.query(`ALTER ROLE app_reader SET statement_timeout = '15s'`);
      await admin2.end();
    }
  }, 15_000);

  test("preflight accepts hardened app_reader", async () => {
    const r = await runPreflight(credsFor("app_reader"), { tier: "reader" });
    expect(r.ok).toBe(true);
    expect(r.checks.find((c) => c.name === "not_superuser")!.ok).toBe(true);
    expect(r.checks.find((c) => c.name === "statement_timeout")!.ok).toBe(true);
    expect(r.checks.find((c) => c.name === "default_transaction_read_only")!.ok).toBe(true);
  });

  test("preflight rejects a superuser connection", async () => {
    const u = new URL(ADMIN_URL!);
    const superCreds: DbCredentials = {
      host: u.hostname,
      port: Number(u.port || 5432),
      database: dbName,
      user: u.username,
      password: decodeURIComponent(u.password),
      sslmode: "disable",
    };
    const r = await runPreflight(superCreds, { tier: "reader" });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/not_superuser|statement_timeout|default_transaction_read_only/);
    await expect(assertPreflight(superCreds, { tier: "reader" })).rejects.toThrow(/preflight failed/);
  });

  test("DDL path applies statement_timeout (withClient)", async () => {
    const err = await pgErr(
      withClient(
        credsFor("app_migrator"),
        (c) => c.query("SELECT pg_sleep(30)"),
        { timeouts: { statementTimeoutMs: 500 } },
      ),
    );
    expect(err.message).toMatch(/statement timeout/i);
  }, 15_000);

  test("tierFromAllow maps policy allow lists", () => {
    expect(tierFromAllow(["health", "select", "whoami"])).toBe("reader");
    expect(tierFromAllow(["select", "dml", "whoami"])).toBe("writer");
  });

  test("writer preflight expects read_only off", async () => {
    const r = await runPreflight(credsFor("app_writer"), { tier: "writer" });
    expect(r.ok).toBe(true);
  });
});
