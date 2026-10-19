/**
 * Phase 4 live-Postgres tests: approvals end to end, both ledgers.
 * Skipped unless PGGUARD_IT_DATABASE_URL points at a superuser connection:
 *
 *   PGGUARD_IT_DATABASE_URL=postgres://postgres:<pw>@localhost:5432/postgres npm test
 *
 * Creates a throwaway database with 01-02 + 04-agent-roles + approval-ledger.sql.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { generateKeyPairSync } from "node:crypto";
import pg from "pg";
import { closePool } from "../src/db/pool.js";
import { handleTool } from "../src/mcp/tools.js";
import type { AppContext } from "../src/mcp/context.js";
import { AuditLogger } from "../src/audit/logger.js";
import { loadPolicyConfig, resolveEffectivePolicy } from "../src/policy/loader.js";
import type { DbCredentials } from "../src/secrets/types.js";
import { createApprovalRuntime } from "../src/approvals/gate.js";
import { RequestQueue } from "../src/approvals/requests.js";
import { approveRequest } from "../src/approvals/cli.js";
import { newJti, signApproval, sqlSha256, type ApprovalClaims, type ApprovalTool } from "../src/approvals/token.js";
import { PHASE2_SQL_FILES } from "./helpers/it-auth.js";

const ADMIN_URL = process.env.PGGUARD_IT_DATABASE_URL;
const d = ADMIN_URL ? describe : describe.skip;
const repo = process.cwd();
const dbName = `pgguard_p4_${process.pid}_${Date.now()}`;
const keys = generateKeyPairSync("ed25519");
const pubPem = keys.publicKey.export({ type: "spki", format: "pem" }).toString();

function credsFor(user: string): DbCredentials {
  const u = new URL(ADMIN_URL!);
  const passwords: Record<string, string> = {
    app_reader: "reader_demo_pass",
    app_writer: "writer_demo_pass",
    app_migrator: "migrator_demo_pass",
  };
  return { host: u.hostname, port: Number(u.port || 5432), database: dbName, user, password: passwords[user]!, sslmode: "disable" };
}

const parse = (r: { content: { text: string }[]; isError?: boolean }) => ({ isError: Boolean(r.isError), body: JSON.parse(r.content[0]!.text) });

async function pgErr(p: Promise<unknown>): Promise<string | undefined> {
  try {
    await p;
    return undefined;
  } catch (e) {
    return (e as { code?: string }).code;
  }
}

d("phase 4 approvals (live Postgres)", () => {
  let dir: string;
  let admin: pg.Client;

  function ctxFor(roleName: string, ledger: "file" | "postgres"): AppContext {
    const policy = resolveEffectivePolicy(loadPolicyConfig(path.join(repo, "config", "policy.yaml")), roleName);
    policy.principalPropagation = { ...policy.principalPropagation, require_jwt: false, enabled: false };
    policy.approvals = { ...policy.approvals, ledger, dir };
    return {
      secrets: { getDbCredentials: async (user?: string) => credsFor(user || "app_reader") },
      audit: new AuditLogger(path.join(dir, "audit")),
      policy,
      approvals: createApprovalRuntime(policy.approvals, { PGGUARD_APPROVAL_PUBLIC_KEY: pubPem }),
    };
  }

  function token(tool: ApprovalTool, role: string, dbUser: string, sql: string, over: Partial<ApprovalClaims> = {}): string {
    const now = Math.floor(Date.now() / 1000);
    return signApproval(
      {
        v: 1,
        jti: newJti(),
        rid: "f".repeat(24),
        tool,
        role,
        db_user: dbUser,
        database: dbName,
        sub: null,
        sql_sha256: sqlSha256(sql),
        approver: "alice",
        iat: now,
        exp: now + 300,
        ...over,
      },
      keys.privateKey,
    );
  }
  const status = async (id: number) => (await admin.query("SELECT status FROM corp.orders WHERE id = $1", [id])).rows[0].status as string;
  const ledgerRows = async () => (await admin.query("SELECT jti, tool, approver, consumed_by FROM pgguard.approval_ledger ORDER BY consumed_at")).rows;

  beforeAll(async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "pgguard-p4it-"));
    const a = new pg.Client({ connectionString: ADMIN_URL });
    await a.connect();
    await a.query(`CREATE DATABASE ${dbName}`);
    await a.end();
    const u = new URL(ADMIN_URL!);
    u.pathname = `/${dbName}`;
    admin = new pg.Client({ connectionString: u.toString() });
    await admin.connect();
    for (const f of [...PHASE2_SQL_FILES, "docker/postgres/optional/approval-ledger.sql"]) {
      await admin.query(fs.readFileSync(path.join(repo, f), "utf8"));
    }
    await admin.query(`
      CREATE TABLE corp.bulk (id int PRIMARY KEY, v int NOT NULL DEFAULT 0);
      INSERT INTO corp.bulk SELECT g FROM generate_series(1, 100) g;
      GRANT SELECT, UPDATE ON corp.bulk TO app_writer;
    `);
  }, 60_000);

  afterAll(async () => {
    await closePool();
    await admin.end();
    const a = new pg.Client({ connectionString: ADMIN_URL });
    await a.connect();
    await a.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
    await a.end();
    fs.rmSync(dir, { recursive: true, force: true });
  }, 30_000);

  test("end to end (file ledger): request → human approves → run once → replay refused", async () => {
    const ctx = ctxFor("writer", "file");
    const sql = "UPDATE corp.orders SET status = 'paid' WHERE id = 2";
    const unapproved = parse(await handleTool(ctx, "run_dml", { sql, confirm: true }));
    expect(unapproved.body.error).toMatch(/\(missing\)/);
    expect(await status(2)).toBe("pending");

    const req = parse(await handleTool(ctx, "request_approval", { tool: "run_dml", sql, reason: "customer paid by wire" }));
    expect(req.body.preview).toEqual({ rowCount: 1, would_exceed_cap: false, max_affected_rows: 50 });
    expect(await status(2)).toBe("pending"); // preview rolled back

    const q = new RequestQueue(dir);
    const { token: t } = approveRequest(q.get(req.body.approval_id)!, { approver: "alice", privateKey: keys.privateKey });
    q.writeToken(req.body.approval_id, t);

    const run = parse(await handleTool(ctx, "run_dml", { sql, confirm: true, approval_id: req.body.approval_id }));
    expect(run.isError).toBe(false);
    expect(run.body).toMatchObject({ rowCount: 1, committed: true, approval: { approver: "alice", consumed: true } });
    expect(await status(2)).toBe("paid");

    await admin.query("UPDATE corp.orders SET status = 'pending' WHERE id = 2");
    const replay = parse(await handleTool(ctx, "run_dml", { sql, confirm: true, approval_id: req.body.approval_id }));
    expect(replay.body.error).toMatch(/replayed/);
    expect(await status(2)).toBe("pending");
    const audit = ctx.audit.tail(10).filter((e) => e.tool === "run_dml" && e.ok);
    expect(audit.at(-1)!.detail).toMatchObject({ approval: { approver: "alice", rid: req.body.approval_id } });
  });

  test("postgres ledger: consumed inside the DML transaction; replay refused by the DB", async () => {
    const ctx = ctxFor("writer", "postgres");
    const sql = "UPDATE corp.orders SET status = 'refunded' WHERE id = 3";
    const t = token("run_dml", "writer", "app_writer", sql);
    const first = parse(await handleTool(ctx, "run_dml", { sql, confirm: true, approval_token: t }));
    expect(first.body).toMatchObject({ rowCount: 1, committed: true });
    const rows = await ledgerRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ tool: "run_dml", approver: "alice", consumed_by: "app_writer" });
    await admin.query("UPDATE corp.orders SET status = 'paid' WHERE id = 3");
    const replay = parse(await handleTool(ctx, "run_dml", { sql, confirm: true, approval_token: t }));
    expect(replay.body.error).toMatch(/replayed/);
    expect(await status(3)).toBe("paid");
  });

  test("postgres ledger: a cap rollback leaves the approval unspent (atomic with the write)", async () => {
    const ctx = ctxFor("writer", "postgres");
    const before = (await ledgerRows()).length;
    const sql = "UPDATE corp.bulk SET v = v + 1";
    const over = parse(await handleTool(ctx, "run_dml", { sql, confirm: true, approval_token: token("run_dml", "writer", "app_writer", sql) }));
    expect(over.body.error).toMatch(/over the max_affected_rows cap of 50/);
    expect((await ledgerRows()).length).toBe(before);
    expect(Number((await admin.query("SELECT sum(v)::int AS s FROM corp.bulk")).rows[0].s)).toBe(0);
  });

  test("approver row cap tighter than the policy: 1-row update approved for 0 rows is rolled back", async () => {
    const ctx = ctxFor("writer", "postgres");
    const sql = "UPDATE corp.orders SET status = 'cancelled' WHERE id = 1";
    const r = parse(await handleTool(ctx, "run_dml", { sql, confirm: true, approval_token: token("run_dml", "writer", "app_writer", sql, { max_affected_rows: 0 }) }));
    expect(r.body.error).toMatch(/cap of 0/);
    expect(await status(1)).toBe("paid");
  });

  test("token for different SQL or another database never reaches the DB", async () => {
    const ctx = ctxFor("writer", "postgres");
    const sql = "UPDATE corp.orders SET status = 'cancelled' WHERE id = 1";
    const before = (await ledgerRows()).length;
    const wrongSql = parse(await handleTool(ctx, "run_dml", { sql: "UPDATE corp.orders SET status = 'cancelled'", confirm: true, approval_token: token("run_dml", "writer", "app_writer", sql) }));
    expect(wrongSql.body.error).toMatch(/sql_mismatch/);
    const wrongDb = parse(await handleTool(ctx, "run_dml", { sql, confirm: true, approval_token: token("run_dml", "writer", "app_writer", sql, { database: "prod" }) }));
    expect(wrongDb.body.error).toMatch(/scope_mismatch/);
    expect(await status(1)).toBe("paid");
    expect((await ledgerRows()).length).toBe(before);
  });

  test("ledger is DB-enforced: agent roles cannot read or write it; DB clock rejects expired", async () => {
    const w = new pg.Client(credsFor("app_writer"));
    await w.connect();
    try {
      expect(await pgErr(w.query("SELECT * FROM pgguard.approval_ledger"))).toBe("42501");
      expect(await pgErr(w.query("DELETE FROM pgguard.approval_ledger"))).toBe("42501");
      expect(
        await pgErr(w.query("SELECT pgguard.consume_approval($1, $2, 'run_dml', 'alice', now() - interval '1 second')", [newJti(), sqlSha256("x")])),
      ).toBe("22023");
      const reader = new pg.Client(credsFor("app_reader"));
      await reader.connect();
      expect(await pgErr(reader.query("SELECT pgguard.consume_approval($1, $2, 'run_dml', 'alice', now() + interval '1 minute')", [newJti(), sqlSha256("x")]))).toBe("42501");
      await reader.end();
    } finally {
      await w.end();
    }
  });

  test("run_ddl (postgres ledger): approved once; burn-then-run means a failing DDL still spends it", async () => {
    const ctx = ctxFor("migrator", "postgres");
    const sql = "CREATE TABLE corp.p4_approved (id int PRIMARY KEY)";
    const t = token("run_ddl", "migrator", "app_migrator", sql);
    const ok = parse(await handleTool(ctx, "run_ddl", { sql, confirm: true, approval_token: t }));
    expect(ok.body).toMatchObject({ ok: true, approval: { consumed: true } });
    expect((await admin.query("SELECT to_regclass('corp.p4_approved') IS NOT NULL AS ok")).rows[0].ok).toBe(true);
    expect(parse(await handleTool(ctx, "run_ddl", { sql, confirm: true, approval_token: t })).body.error).toMatch(/replayed/);

    const bad = "CREATE TABLE corp.p4_approved (id int)"; // already exists
    const t2 = token("run_ddl", "migrator", "app_migrator", bad);
    const failed = parse(await handleTool(ctx, "run_ddl", { sql: bad, confirm: true, approval_token: t2 }));
    expect(failed.body.error).toMatch(/already exists/);
    expect(parse(await handleTool(ctx, "run_ddl", { sql: bad, confirm: true, approval_token: t2 })).body.error).toMatch(/replayed/);
  });

  test("a writer token cannot be replayed as the migrator role", async () => {
    const sql = "UPDATE corp.orders SET status = 'cancelled' WHERE id = 5";
    const t = token("run_dml", "writer", "app_writer", sql);
    const r = parse(await handleTool(ctxFor("migrator", "postgres"), "run_dml", { sql, confirm: true, approval_token: t }));
    expect(r.body.error).toMatch(/scope_mismatch/);
    expect(await status(5)).toBe("refunded");
  });
});
