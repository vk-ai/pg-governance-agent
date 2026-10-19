/**
 * Live Postgres 17: schema allowlist + row/byte/cell result caps (phase 3 /
 * plan phase 2).
 *
 * - a schema with no grants is refused by Postgres even with the gateway guard off
 * - a granted-but-not-allowlisted schema is refused by the guard (and readable with it off,
 *   which shows the two layers are independent)
 * - list_schemas / list_tables only show allowed schemas
 * - 10k-row and large-text results are truncated by rows, bytes and cells; the
 *   agent cannot raise the row cap
 *
 * Skipped unless PGGUARD_IT_DATABASE_URL points at a superuser connection.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import pg from "pg";
import { closePool, withReadOnlyTransaction } from "../src/db/pool.js";
import { fetchCapped, runUserSql } from "../src/db/queries.js";
import { handleTool } from "../src/mcp/tools.js";
import type { AppContext } from "../src/mcp/context.js";
import { AuditLogger } from "../src/audit/logger.js";
import { loadPolicyConfig, resolveEffectivePolicy } from "../src/policy/loader.js";
import type { DbCredentials } from "../src/secrets/types.js";
import { PHASE2_SQL_FILES } from "./helpers/it-auth.js";

const ADMIN_URL = process.env.PGGUARD_IT_DATABASE_URL;
const d = ADMIN_URL ? describe : describe.skip;
const repo = process.cwd();
const dbName = `pgguard_p3_${process.pid}_${Date.now()}`;

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

const parse = (r: { content: { text: string }[]; isError?: boolean }) => ({
  isError: Boolean(r.isError),
  body: JSON.parse(r.content[0]!.text),
});

async function pgErr(p: Promise<unknown>): Promise<{ code?: string; message: string }> {
  try {
    await p;
    return { message: "" };
  } catch (e) {
    const err = e as { code?: string; message?: string };
    return { code: err.code, message: err.message || String(e) };
  }
}

d("phase 3 schema allowlist + result caps (live Postgres)", () => {
  let auditDir: string;

  function ctxFor(roleName: string, guard = true): AppContext {
    const policy = resolveEffectivePolicy(loadPolicyConfig(path.join(repo, "config", "policy.yaml")), roleName);
    policy.principalPropagation = { ...policy.principalPropagation, require_jwt: false, enabled: false };
    if (!guard) {
      policy.allowedSchemas = null;
      policy.searchPath = null;
    }
    return {
      secrets: { getDbCredentials: async (user?: string) => credsFor(user || "app_reader") },
      audit: new AuditLogger(auditDir),
      policy,
    };
  }

  beforeAll(async () => {
    auditDir = fs.mkdtempSync(path.join(os.tmpdir(), "pgguard-p3-"));
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
    await db.query(`
      -- hr: no grants at all for agent roles
      CREATE SCHEMA hr;
      CREATE TABLE hr.salaries (employee_id int, amount_cents bigint);
      INSERT INTO hr.salaries VALUES (1, 9900000), (2, 12000000);
      -- sales: granted to app_reader but NOT in allowed_schemas
      CREATE SCHEMA sales;
      CREATE TABLE sales.leads (id int, email text);
      INSERT INTO sales.leads VALUES (1, 'lead@example.com');
      GRANT USAGE ON SCHEMA sales TO app_reader;
      GRANT SELECT ON sales.leads TO app_reader;
      -- wide rows for the byte cap
      CREATE TABLE corp.notes (id int PRIMARY KEY, body text);
      INSERT INTO corp.notes SELECT g, repeat('n', 2000) FROM generate_series(1, 10000) g;
      GRANT SELECT ON corp.notes TO app_reader;
    `);
    await db.end();
  }, 60_000);

  afterAll(async () => {
    await closePool();
    const admin = new pg.Client({ connectionString: ADMIN_URL });
    await admin.connect();
    await admin.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
    await admin.end();
    fs.rmSync(auditDir, { recursive: true, force: true });
  }, 30_000);

  describe("schemas", () => {
    test("grant-less schema: Postgres denies even with the guard disabled", async () => {
      const off = parse(await handleTool(ctxFor("reader", false), "run_select", { sql: "SELECT * FROM hr.salaries" }));
      expect(off.isError).toBe(true);
      expect(off.body.error).toMatch(/permission denied for schema hr/);
      // Same through the raw pool (no tool layer at all).
      const raw = await pgErr(withReadOnlyTransaction(credsFor("app_reader"), (c) => runUserSql(c, "SELECT * FROM hr.salaries")));
      expect(raw.code).toBe("42501");
    });

    test("grant-less schema: guard denies first with a clear message", async () => {
      const on = parse(await handleTool(ctxFor("reader"), "run_select", { sql: "SELECT * FROM hr.salaries" }));
      expect(on.isError).toBe(true);
      expect(on.body.error).toMatch(/Schema 'hr' is not allowed/);
    });

    test("granted but not allowlisted: guard denies; readable with guard off (layers are independent)", async () => {
      const on = parse(await handleTool(ctxFor("reader"), "run_select", { sql: "SELECT * FROM sales.leads" }));
      expect(on.isError).toBe(true);
      expect(on.body.error).toMatch(/Schema 'sales' is not allowed/);
      const off = parse(await handleTool(ctxFor("reader", false), "run_select", { sql: "SELECT * FROM sales.leads" }));
      expect(off.isError).toBe(false);
      expect(off.body.rowCount).toBe(1);
    });

    test("unqualified pg_authid: guard denies; Postgres also denies with guard off", async () => {
      const on = parse(await handleTool(ctxFor("reader"), "run_select", { sql: "SELECT rolname FROM pg_authid" }));
      expect(on.body.error).toMatch(/resolves to pg_catalog/);
      const off = parse(await handleTool(ctxFor("reader", false), "run_select", { sql: "SELECT rolname FROM pg_authid" }));
      expect(off.isError).toBe(true);
      expect(off.body.error).toMatch(/permission denied/);
    });

    test("allowed schema works, and PgGuard sets search_path to the allowlist", async () => {
      const ok = parse(await handleTool(ctxFor("reader"), "run_select", { sql: "SELECT count(*)::int AS n FROM orgs" }));
      expect(ok.isError).toBe(false);
      expect(ok.body.rows[0].n).toBeGreaterThan(0);
      const sp = parse(await handleTool(ctxFor("reader"), "run_select", { sql: "SELECT current_setting('search_path') AS sp" }));
      expect(sp.body.rows[0].sp).toBe('"corp"');
    });

    test("list_schemas / list_tables are filtered; describe_table on other schemas denied", async () => {
      const all = parse(await handleTool(ctxFor("reader", false), "list_schemas", {}));
      // information_schema already hides hr (no USAGE); sales is visible to the role.
      expect(all.body.schemas).toEqual(expect.arrayContaining(["corp", "sales"]));
      expect(all.body.schemas).not.toContain("hr");
      const s = parse(await handleTool(ctxFor("reader"), "list_schemas", {}));
      expect(s.body.schemas).toEqual(["corp"]);
      const t = parse(await handleTool(ctxFor("reader"), "list_tables", {}));
      expect(t.body.tables.length).toBeGreaterThan(0);
      expect(t.body.tables.every((x: { schema: string }) => x.schema === "corp")).toBe(true);
      const ts = parse(await handleTool(ctxFor("reader"), "list_tables", { schema: "sales" }));
      expect(ts.isError).toBe(true);
      const dt = parse(await handleTool(ctxFor("reader"), "describe_table", { schema: "sales", table: "leads" }));
      expect(dt.isError).toBe(true);
    });

    test("explain_query and run_dml are guarded too", async () => {
      const ex = parse(await handleTool(ctxFor("reader"), "explain_query", { sql: "SELECT * FROM sales.leads" }));
      expect(ex.body.error).toMatch(/'sales'/);
      const dml = parse(await handleTool(ctxFor("writer"), "run_dml", { sql: "DELETE FROM sales.leads", dry_run: true }));
      expect(dml.body.error).toMatch(/'sales'/);
      const exOk = parse(await handleTool(ctxFor("reader"), "explain_query", { sql: "SELECT * FROM corp.orgs" }));
      expect(exOk.isError).toBe(false);
      expect(exOk.body.plan.length).toBeGreaterThan(0);
    });

    test("query_to_xml cannot smuggle another schema in a string", async () => {
      const r = parse(await handleTool(ctxFor("reader"), "run_select", {
        sql: "SELECT query_to_xml('select * from sales.leads', true, false, '') AS x",
      }));
      expect(r.body.error).toMatch(/query_to_xml/);
    });
  });

  describe("result caps", () => {
    test("10k rows: capped at policy max_rows, agent cannot raise it", async () => {
      const r = parse(await handleTool(ctxFor("reader"), "run_select", { sql: "SELECT id FROM corp.notes", max_rows: 1e9 }));
      expect(r.isError).toBe(false);
      expect(r.body.rowCount).toBe(100);
      expect(r.body.truncated).toBe(true);
      expect(r.body.truncated_by).toEqual(["rows"]);
      expect(r.body.max_rows).toBe(100);
      const sub = parse(await handleTool(ctxFor("reader"), "run_select", {
        sql: "SELECT id FROM corp.notes WHERE id IN (SELECT id FROM corp.notes LIMIT 5) OR true",
      }));
      expect(sub.body.rowCount).toBe(100);
      const few = parse(await handleTool(ctxFor("reader"), "run_select", { sql: "SELECT id FROM corp.notes ORDER BY id", max_rows: 3 }));
      expect(few.body.rows.map((x: { id: number }) => x.id)).toEqual([1, 2, 3]);
      expect(few.body.truncated).toBe(true);
    });

    test("exactly max_rows rows is not reported as truncated", async () => {
      const r = parse(await handleTool(ctxFor("reader"), "run_select", { sql: "SELECT id FROM corp.notes WHERE id <= 100" }));
      expect(r.body.rowCount).toBe(100);
      expect(r.body.truncated).toBe(false);
    });

    test("wide rows: truncated by the byte budget before the row cap", async () => {
      const c = ctxFor("reader");
      c.policy.maxRows = 10_000;
      c.policy.maxResultBytes = 100_000;
      const r = parse(await handleTool(c, "run_select", { sql: "SELECT id, body FROM corp.notes ORDER BY id" }));
      expect(r.isError).toBe(false);
      expect(r.body.truncated).toBe(true);
      expect(r.body.truncated_by).toEqual(["bytes"]);
      expect(r.body.result_bytes).toBeLessThanOrEqual(100_000);
      expect(r.body.rowCount).toBeGreaterThan(10);
      expect(r.body.rowCount).toBeLessThan(100);
      expect(Buffer.byteLength(JSON.stringify(r.body.rows))).toBe(r.body.result_bytes);
    });

    test("large text and bytea cells are cut to max_cell_bytes", async () => {
      const r = parse(await handleTool(ctxFor("reader"), "run_select", {
        sql: "SELECT repeat('x', 200000) AS big, 'small' AS small, decode(repeat('ab', 100000), 'hex') AS blob",
      }));
      expect(r.isError).toBe(false);
      expect(r.body.rows[0].big).toHaveLength(65536);
      expect(r.body.rows[0].small).toBe("small");
      expect(r.body.rows[0].blob).toBe("\\x" + "ab".repeat(65536));
      expect(r.body.truncated).toBe(true);
      expect(r.body.truncated_by).toEqual(["cells"]);
      expect(r.body.truncated_cells).toBe(2);
      expect(r.body.truncated_columns.sort()).toEqual(["big", "blob"]);
    });

    test("cursor path is used inside READ ONLY and still rejects writes / multi-statements", async () => {
      const caps = { maxRows: 5, maxResultBytes: 1_000_000, maxCellBytes: 1000 };
      const ok = await withReadOnlyTransaction(credsFor("app_reader"), (c) => fetchCapped(c, "SELECT g FROM generate_series(1, 10) g", caps));
      expect(ok.rowCount).toBe(5);
      const multi = await pgErr(withReadOnlyTransaction(credsFor("app_reader"), (c) => fetchCapped(c, "SELECT 1; SELECT 2", caps)));
      expect(multi.message).toMatch(/multiple commands|syntax/i);
      const cte = await pgErr(withReadOnlyTransaction(credsFor("app_writer"), (c) =>
        fetchCapped(c, "WITH d AS (DELETE FROM corp.notes RETURNING id) SELECT * FROM d", caps)));
      expect(cte.code).toBeDefined();
      expect(cte.message).not.toBe("");
    });

    test("writer max_rows (200) applies; audit records truncation", async () => {
      const r = parse(await handleTool(ctxFor("writer"), "run_select", { sql: "SELECT id FROM corp.notes" }));
      expect(r.body.rowCount).toBe(200);
      const tail = new AuditLogger(auditDir).tail(1)[0] as { detail?: { truncated?: boolean } };
      expect(tail.detail?.truncated).toBe(true);
    });
  });
});
