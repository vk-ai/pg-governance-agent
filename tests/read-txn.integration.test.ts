/**
 * Live-Postgres tests for read-only transactions, SET LOCAL timeouts and
 * principal GUC propagation. Skipped unless PGGUARD_IT_DATABASE_URL points at
 * a superuser connection (e.g. the Compose stack):
 *
 *   docker compose up -d postgres
 *   PGGUARD_IT_DATABASE_URL=postgres://postgres:postgres_dev_only@localhost:5432/postgres npm test
 *
 * The suite creates a throwaway database, applies docker/postgres/init/01-02
 * plus docker/postgres/optional/rls-orders-by-employee.sql, and drops it after.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import pg from "pg";
import { closePool, withReadOnlyTransaction } from "../src/db/pool.js";
import { runUserSql } from "../src/db/queries.js";
import { handleTool } from "../src/mcp/tools.js";
import type { AppContext } from "../src/mcp/context.js";
import { AuditLogger } from "../src/audit/logger.js";
import { loadPolicyConfig, resolveEffectivePolicy } from "../src/policy/loader.js";
import type { DbCredentials } from "../src/secrets/types.js";

const ADMIN_URL = process.env.PGGUARD_IT_DATABASE_URL;
const d = ADMIN_URL ? describe : describe.skip;

const repo = process.cwd(); // jest runs from the repo root
const dbName = `pgguard_it_${process.pid}_${Date.now()}`;

function unsignedJwt(claims: Record<string, unknown>): string {
  const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${enc({ alg: "none", typ: "JWT" })}.${enc(claims)}.`;
}

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

function ctxFor(roleName: string, auditDir: string): AppContext {
  const policy = resolveEffectivePolicy(loadPolicyConfig(path.join(repo, "config", "policy.yaml")), roleName);
  policy.readTxn = { ...policy.readTxn, statementTimeoutMs: 300 };
  return {
    secrets: { getDbCredentials: async (user?: string) => credsFor(user || "app_reader") },
    audit: new AuditLogger(auditDir),
    policy,
  };
}

function parse(res: { content: { text: string }[]; isError?: boolean }) {
  return { isError: Boolean(res.isError), body: JSON.parse(res.content[0]!.text) };
}

async function pgErrorCode(p: Promise<unknown>): Promise<string | undefined> {
  try {
    await p;
    return undefined;
  } catch (e) {
    return (e as { code?: string }).code;
  }
}

d("read-only transactions against live Postgres", () => {
  let auditDir: string;
  const savedSecret = process.env.PGGUARD_JWT_SECRET;
  const savedToken = process.env.PGGUARD_BEARER_TOKEN;

  beforeAll(async () => {
    delete process.env.PGGUARD_JWT_SECRET; // decode-only JWTs for the test
    delete process.env.PGGUARD_BEARER_TOKEN;
    auditDir = fs.mkdtempSync(path.join(os.tmpdir(), "pgguard-it-"));
    const admin = new pg.Client({ connectionString: ADMIN_URL });
    await admin.connect();
    await admin.query(`CREATE DATABASE ${dbName}`);
    await admin.end();
    const u = new URL(ADMIN_URL!);
    u.pathname = `/${dbName}`;
    const db = new pg.Client({ connectionString: u.toString() });
    await db.connect();
    for (const f of [
      "docker/postgres/init/01-schema.sql",
      "docker/postgres/init/02-seed.sql",
      "docker/postgres/optional/rls-orders-by-employee.sql",
    ]) {
      await db.query(fs.readFileSync(path.join(repo, f), "utf8"));
    }
    // A SELECT-shaped call with a write side effect: passes the classifier,
    // must be stopped by Postgres.
    await db.query(`
      CREATE FUNCTION corp.it_write_side_effect() RETURNS int LANGUAGE sql AS
        $$ INSERT INTO corp.orgs (name) VALUES ('sneaky') RETURNING id $$;
      GRANT EXECUTE ON FUNCTION corp.it_write_side_effect() TO app_reader, app_writer;
    `);
    await db.end();
  }, 30_000);

  afterAll(async () => {
    await closePool();
    const admin = new pg.Client({ connectionString: ADMIN_URL });
    await admin.connect();
    await admin.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
    await admin.end();
    fs.rmSync(auditDir, { recursive: true, force: true });
    if (savedSecret !== undefined) process.env.PGGUARD_JWT_SECRET = savedSecret;
    if (savedToken !== undefined) process.env.PGGUARD_BEARER_TOKEN = savedToken;
  });

  test("regression: set_config(..., true) outside a transaction is lost (the old bug)", async () => {
    const c = new pg.Client({ ...credsFor("app_reader"), ssl: undefined });
    await c.connect();
    try {
      await c.query("SELECT set_config('app.user_id', '1', true)");
      const r = await c.query("SELECT current_setting('app.user_id', true) AS uid");
      expect(r.rows[0].uid ?? "").toBe("");
    } finally {
      await c.end();
    }
  });

  test("Postgres rejects writes in the READ ONLY transaction (even for a DML-capable user)", async () => {
    const code = await pgErrorCode(
      withReadOnlyTransaction(credsFor("app_writer"), (c) =>
        runUserSql(c, "INSERT INTO corp.orgs (name) VALUES ('nope')"),
      ),
    );
    expect(code).toBe("25006"); // read_only_sql_transaction
  });

  test("run_select: SELECT calling a writing function is rejected by Postgres", async () => {
    const { isError, body } = parse(
      await handleTool(ctxFor("writer", auditDir), "run_select", {
        sql: "SELECT corp.it_write_side_effect()",
      }),
    );
    expect(isError).toBe(true);
    expect(body.error).toMatch(/read-only transaction/);
    const check = await withReadOnlyTransaction(credsFor("app_writer"), (c) =>
      c.query("SELECT count(*)::int AS n FROM corp.orgs WHERE name = 'sneaky'"),
    );
    expect(check.rows[0].n).toBe(0);
  });

  test("multi-statement strings are rejected by the extended protocol", async () => {
    const code = await pgErrorCode(
      withReadOnlyTransaction(credsFor("app_writer"), (c) =>
        runUserSql(c, "SELECT 1; COMMIT; INSERT INTO corp.orgs (name) VALUES ('nope')"),
      ),
    );
    expect(code).toBe("42601"); // cannot insert multiple commands into a prepared statement
  });

  test("statement_timeout from policy is applied (SET LOCAL)", async () => {
    const { isError, body } = parse(
      await handleTool(ctxFor("reader", auditDir), "run_select", { sql: "SELECT pg_sleep(2)" }),
    );
    expect(isError).toBe(true);
    expect(body.error).toMatch(/statement timeout/);
  });

  test("timeouts and read-only mode do not leak back into the pooled session", async () => {
    await withReadOnlyTransaction(credsFor("app_reader"), async () => undefined, {
      sessionGucs: { "app.user_id": "1" },
      timeouts: { statementTimeoutMs: 123 },
    });
    // Sequential checkouts reuse the idle pooled connection: values are back to defaults.
    const r = await withReadOnlyTransaction(credsFor("app_reader"), (c) =>
      c.query(
        "SELECT current_setting('statement_timeout') AS st, coalesce(current_setting('app.user_id', true), '') AS uid",
      ),
    );
    expect(r.rows[0].st).not.toBe("123ms");
    expect(r.rows[0].uid).toBe("");
  });

  test("principal GUC is visible to the query and RLS filters rows", async () => {
    const ctx = ctxFor("reader", auditDir);
    const token = unsignedJwt({ sub: "1", email: "ada@acme.example" });
    const who = parse(
      await handleTool(ctx, "run_select", {
        sql: "SELECT current_setting('app.user_id', true) AS uid, current_setting('app.user_email', true) AS email",
        bearer_token: token,
      }),
    );
    expect(who.isError).toBe(false);
    expect(who.body.rows).toEqual([{ uid: "1", email: "ada@acme.example" }]);

    const orders = parse(
      await handleTool(ctx, "run_select", {
        sql: "SELECT employee_id FROM corp.orders ORDER BY id",
        bearer_token: token,
      }),
    );
    expect(orders.isError).toBe(false);
    expect(orders.body.rowCount).toBe(2);
    expect(orders.body.rows.every((r: { employee_id: number }) => r.employee_id === 1)).toBe(true);
  });

  test("unset principal: fail-closed RLS policy returns no rows", async () => {
    const res = parse(
      await handleTool(ctxFor("reader", auditDir), "run_select", {
        sql: "SELECT * FROM corp.orders",
      }),
    );
    expect(res.isError).toBe(false);
    expect(res.body.rowCount).toBe(0);
  });

  test("write path: principal reaches RLS inside BEGIN … COMMIT (run_dml)", async () => {
    const ctx = ctxFor("writer", auditDir);
    const res = parse(
      await handleTool(ctx, "run_dml", {
        sql: "UPDATE corp.orders SET status = 'paid' WHERE status = 'pending'",
        confirm: true,
        bearer_token: unsignedJwt({ sub: "2" }),
      }),
    );
    expect(res.isError).toBe(false);
    expect(res.body.rowCount).toBe(1); // employee 2's pending order only
    const none = parse(
      await handleTool(ctx, "run_dml", {
        sql: "UPDATE corp.orders SET status = 'paid'",
        confirm: true,
      }),
    );
    expect(none.isError).toBe(false);
    expect(none.body.rowCount).toBe(0); // no principal → RLS hides every row
  });
});
