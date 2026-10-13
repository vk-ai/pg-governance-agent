/**
 * Live-Postgres tests for run_dml dry_run previews and the max_affected_rows cap. Skipped unless PGGUARD_IT_DATABASE_URL points at
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
import { closePool, getPool } from "../src/db/pool.js";
import { handleTool } from "../src/mcp/tools.js";
import type { AppContext } from "../src/mcp/context.js";
import { AuditLogger } from "../src/audit/logger.js";
import { loadPolicyConfig, resolveEffectivePolicy } from "../src/policy/loader.js";
import type { DbCredentials } from "../src/secrets/types.js";
import { RLS_SQL_FILES, SET_KEY_SQL, TEST_JWT_SECRET, TEST_RLS_KEY_HEX, signedJwt as unsignedJwt } from "./helpers/it-auth.js";

const ADMIN_URL = process.env.PGGUARD_IT_DATABASE_URL;
const d = ADMIN_URL ? describe : describe.skip;

const repo = process.cwd(); // jest runs from the repo root
const dbName = `pgguard_dml_${process.pid}_${Date.now()}`;


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
  // Tokens are always verified here; calls without one exercise the "no principal" path.
  policy.principalPropagation = { ...policy.principalPropagation, require_jwt: false };
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

d("run_dml dry run + max_affected_rows against live Postgres", () => {
  let auditDir: string;
  let adminDb: pg.Client;
  const savedSecret = process.env.PGGUARD_JWT_SECRET;
  const savedToken = process.env.PGGUARD_BEARER_TOKEN;
  const ada = () => unsignedJwt({ sub: "1" });
  const dml = (ctx: AppContext, args: Record<string, unknown>) => handleTool(ctx, "run_dml", args).then(parse);
  const count = async (where: string) =>
    Number((await adminDb.query(`SELECT count(*)::int AS n FROM corp.orders WHERE ${where}`)).rows[0].n);

  beforeAll(async () => {
    process.env.PGGUARD_JWT_SECRET = TEST_JWT_SECRET;
    process.env.PGGUARD_RLS_HMAC_KEY = TEST_RLS_KEY_HEX;
    delete process.env.PGGUARD_BEARER_TOKEN;
    auditDir = fs.mkdtempSync(path.join(os.tmpdir(), "pgguard-dml-"));
    const admin = new pg.Client({ connectionString: ADMIN_URL });
    await admin.connect();
    await admin.query(`CREATE DATABASE ${dbName}`);
    await admin.end();
    const u = new URL(ADMIN_URL!);
    u.pathname = `/${dbName}`;
    adminDb = new pg.Client({ connectionString: u.toString() });
    await adminDb.connect();
    for (const f of RLS_SQL_FILES) {
      await adminDb.query(fs.readFileSync(path.join(repo, f), "utf8"));
    }
    await adminDb.query(SET_KEY_SQL);
    // 120 extra pending orders for employee 1 (Ada): enough to trip the writer cap of 50.
    await adminDb.query(
      "INSERT INTO corp.orders (org_id, employee_id, amount_cents, status) SELECT 1, 1, g, 'pending' FROM generate_series(1, 120) g",
    );
  }, 30_000);

  afterAll(async () => {
    await closePool();
    await adminDb.end();
    const admin = new pg.Client({ connectionString: ADMIN_URL });
    await admin.connect();
    await admin.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
    await admin.end();
    if (savedSecret !== undefined) process.env.PGGUARD_JWT_SECRET = savedSecret;
    else delete process.env.PGGUARD_JWT_SECRET;
    delete process.env.PGGUARD_RLS_HMAC_KEY;
    if (savedToken !== undefined) process.env.PGGUARD_BEARER_TOKEN = savedToken;
  });

  test("dry run reports the real row count, leaves data untouched, needs no confirm", async () => {
    const before = await count("status = 'pending'");
    const res = await dml(ctxFor("writer", auditDir), {
      sql: "DELETE FROM corp.orders WHERE status = 'pending' RETURNING id, amount_cents",
      dry_run: true,
      bearer_token: ada(),
    });
    expect(res.isError).toBe(false);
    expect(res.body).toMatchObject({ dry_run: true, committed: false, rowCount: 120, command: "DELETE" });
    expect(res.body.would_exceed_cap).toBe(true);
    expect(res.body.max_affected_rows).toBe(50);
    expect(res.body.sample).toHaveLength(5);
    expect(await count("status = 'pending'")).toBe(before);
  });

  test("dry run goes through RLS: other principal and no principal see different counts", async () => {
    const ctx = ctxFor("writer", auditDir);
    const sql = "UPDATE corp.orders SET status = 'paid' WHERE status = 'pending'";
    const grace = await dml(ctx, { sql, dry_run: true, bearer_token: unsignedJwt({ sub: "2" }) });
    expect(grace.body.rowCount).toBe(1);
    expect(grace.body.would_exceed_cap).toBe(false);
    const nobody = await dml(ctx, { sql, dry_run: true });
    expect(nobody.body.rowCount).toBe(0); // fail-closed RLS from round 5 still holds
  });

  test("real run over the cap is rolled back with an error and audited", async () => {
    const ctx = ctxFor("writer", auditDir);
    const res = await dml(ctx, {
      sql: "UPDATE corp.orders SET status = 'cancelled' WHERE status = 'pending'",
      confirm: true,
      bearer_token: ada(),
    });
    expect(res.isError).toBe(true);
    expect(res.body.error).toMatch(/affect 120 rows, over the max_affected_rows cap of 50; rolled back/);
    expect(await count("status = 'cancelled' AND employee_id = 1")).toBe(0);
    const last = ctx.audit.tail(1)[0] as { ok: boolean; detail?: { rowCount: number; committed: boolean } };
    expect(last.ok).toBe(false);
    expect(last.detail).toMatchObject({ rowCount: 120, committed: false });
  });

  test("real run under the cap commits", async () => {
    const ctx = ctxFor("writer", auditDir);
    const res = await dml(ctx, {
      sql: "UPDATE corp.orders SET status = 'paid' WHERE status = 'pending' AND amount_cents <= 10",
      confirm: true,
      bearer_token: ada(),
    });
    expect(res.body).toMatchObject({ ok: true, rowCount: 10, committed: true, dry_run: false });
    expect(await count("status = 'paid' AND employee_id = 1 AND amount_cents <= 10")).toBe(10);
  });

  test("the same write commits when the role's cap is high enough", async () => {
    // migrator/admin are not in the demo RLS policy's TO list, so raise the writer's cap instead.
    const ctx = ctxFor("writer", auditDir);
    ctx.policy.maxAffectedRows = 10000;
    const res = await dml(ctx, {
      sql: "UPDATE corp.orders SET status = 'paid' WHERE status = 'pending'",
      confirm: true,
      bearer_token: ada(),
    });
    expect(res.body).toMatchObject({ rowCount: 110, committed: true });
  });

  test("dry run surfaces constraint / RLS WITH CHECK errors without writing", async () => {
    const res = await dml(ctxFor("writer", auditDir), {
      sql: "UPDATE corp.orders SET employee_id = 3 WHERE employee_id = 1",
      dry_run: true,
      bearer_token: ada(),
    });
    expect(res.isError).toBe(true);
    expect(res.body.error).toMatch(/row-level security/);
    expect(await count("employee_id = 3")).toBe(1);
  });

  test("real run without confirm is refused; dry run hint is in the message", async () => {
    const res = await dml(ctxFor("writer", auditDir), { sql: "DELETE FROM corp.orders", bearer_token: ada() });
    expect(res.isError).toBe(true);
    expect(res.body.error).toMatch(/dry_run/);
  });

  test("reader role cannot dry-run DML either", async () => {
    const res = await dml(ctxFor("reader", auditDir), { sql: "DELETE FROM corp.orders", dry_run: true });
    expect(res.isError).toBe(true);
    expect(res.body.error).toMatch(/not allowed to perform 'dml'/);
  });

  test("pooled session is clean after a dry run (no leaked GUC or open transaction)", async () => {
    const ctx = ctxFor("writer", auditDir);
    await dml(ctx, { sql: "UPDATE corp.orders SET status = status", dry_run: true, bearer_token: ada() });
    const pool = await getPool(credsFor("app_writer"));
    const c = await pool.connect();
    try {
      const r = await c.query(
        "SELECT coalesce(current_setting('app.user_id', true), '') AS uid, now() = statement_timestamp() AS fresh",
      );
      expect(r.rows[0].uid).toBe("");
      expect(r.rows[0].fresh).toBe(true);
    } finally {
      c.release();
    }
  });
});
