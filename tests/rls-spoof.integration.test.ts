/**
 * Live Postgres 17: reproduce the cross-tenant read via set_config inside agent SQL,
 * and show both layers now stop it:
 *   1. the gateway classifier rejects set_config / "set_config" / pg_catalog.set_config;
 *   2. even with the classifier bypassed (raw SQL in the same READ ONLY txn), the RLS
 *      policy reads pgguard.current_user_id(), which ignores an app.user_id whose HMAC
 *      does not verify.
 * Skipped unless PGGUARD_IT_DATABASE_URL points at a superuser connection.
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
import { gucsForPrincipal, principalFromClaims, principalMac } from "../src/auth/principal.js";
import type { DbCredentials } from "../src/secrets/types.js";
import { RLS_SQL_FILES, SET_KEY_SQL, TEST_JWT_SECRET, TEST_RLS_KEY_HEX, signedJwt, unsignedJwt } from "./helpers/it-auth.js";

const ADMIN_URL = process.env.PGGUARD_IT_DATABASE_URL;
const d = ADMIN_URL ? describe : describe.skip;
const repo = process.cwd();
const dbName = `pgguard_spoof_${process.pid}_${Date.now()}`;

const SPOOF = "SELECT employee_id FROM corp.orders WHERE set_config('app.user_id', '2', true) IS NOT NULL";

function creds(): DbCredentials {
  const u = new URL(ADMIN_URL!);
  return { host: u.hostname, port: Number(u.port || 5432), database: dbName, user: "app_reader", password: "reader_demo_pass", sslmode: "disable" };
}

function ctx(auditDir: string): AppContext {
  const policy = resolveEffectivePolicy(loadPolicyConfig(path.join(repo, "config", "policy.yaml")), "reader");
  return { secrets: { getDbCredentials: async () => creds() }, audit: new AuditLogger(auditDir), policy };
}

const parse = (res: { content: { text: string }[]; isError?: boolean }) => ({
  isError: Boolean(res.isError),
  body: JSON.parse(res.content[0]!.text),
});

d("RLS principal spoofing (live Postgres)", () => {
  let auditDir: string;
  let adminDb: pg.Client;

  beforeAll(async () => {
    process.env.PGGUARD_JWT_SECRET = TEST_JWT_SECRET;
    process.env.PGGUARD_RLS_HMAC_KEY = TEST_RLS_KEY_HEX;
    auditDir = fs.mkdtempSync(path.join(os.tmpdir(), "pgguard-spoof-"));
    const admin = new pg.Client({ connectionString: ADMIN_URL });
    await admin.connect();
    await admin.query(`CREATE DATABASE ${dbName}`);
    await admin.end();
    const u = new URL(ADMIN_URL!);
    u.pathname = `/${dbName}`;
    adminDb = new pg.Client({ connectionString: u.toString() });
    await adminDb.connect();
    // Seed files first, then reproduce the OLD policy to prove the bug exists.
    for (const f of RLS_SQL_FILES.slice(0, 2)) await adminDb.query(fs.readFileSync(path.join(repo, f), "utf8"));
    await adminDb.query(`
      ALTER TABLE corp.orders ENABLE ROW LEVEL SECURITY;
      CREATE POLICY old_unverified ON corp.orders FOR ALL TO app_reader, app_writer
        USING (employee_id::text = nullif(current_setting('app.user_id', true), ''));`);
  }, 30_000);

  afterAll(async () => {
    await closePool();
    await adminDb.end();
    const admin = new pg.Client({ connectionString: ADMIN_URL });
    await admin.connect();
    await admin.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
    await admin.end();
    fs.rmSync(auditDir, { recursive: true, force: true });
    delete process.env.PGGUARD_JWT_SECRET;
    delete process.env.PGGUARD_RLS_HMAC_KEY;
  });

  const rawAs = (sub: string, sql: string) =>
    withReadOnlyTransaction(creds(), async (c) => (await runUserSql(c, sql)).rows, {
      sessionGucs: gucsForPrincipal(principalFromClaims({ sub })),
    });

  test("before the fix: the old GUC-trusting policy leaks user 2's rows to user 1", async () => {
    const own = await rawAs("1", "SELECT DISTINCT employee_id FROM corp.orders");
    expect(own.map((r) => r.employee_id)).toEqual([1]);
    const spoofed = await rawAs("1", SPOOF);
    expect(spoofed.length).toBeGreaterThan(0);
    expect(new Set(spoofed.map((r) => r.employee_id))).toEqual(new Set([2]));
  });

  describe("after the fix", () => {
    beforeAll(async () => {
      await adminDb.query("DROP POLICY old_unverified ON corp.orders");
      for (const f of RLS_SQL_FILES.slice(2)) await adminDb.query(fs.readFileSync(path.join(repo, f), "utf8"));
      await adminDb.query(SET_KEY_SQL);
    });

    test("verified principal still sees only its own rows", async () => {
      const own = await rawAs("1", "SELECT DISTINCT employee_id FROM corp.orders");
      expect(own.map((r) => r.employee_id)).toEqual([1]);
    });

    test("DB layer: set_config spoof in the same txn yields no rows (classifier bypassed)", async () => {
      expect(await rawAs("1", SPOOF)).toEqual([]);
      // Rewriting the MAC too does not help without the key.
      const both = await rawAs(
        "1",
        "SELECT employee_id FROM corp.orders WHERE set_config('app.user_id','2',true) IS NOT NULL AND set_config('app.user_id_mac', repeat('0',64), true) IS NOT NULL",
      );
      expect(both).toEqual([]);
    });

    test("DB layer: a MAC made with a different key is rejected", async () => {
      const wrong = principalMac("2", "ff".repeat(32));
      const rows = await withReadOnlyTransaction(creds(), async (c) => (await runUserSql(c, "SELECT employee_id FROM corp.orders")).rows, {
        sessionGucs: { "app.user_id": "2", "app.user_id_mac": wrong },
      });
      expect(rows).toEqual([]);
    });

    test("DB layer: agent role cannot read the key or call the verifier internals", async () => {
      await expect(rawAs("1", "SELECT key FROM pgguard.rls_key")).rejects.toMatchObject({ code: "42501" });
      await expect(rawAs("1", "SELECT pgguard.hmac_sha256('\\x00'::bytea, '\\x00'::bytea)")).rejects.toMatchObject({ code: "42501" });
    });

    test("SQL HMAC matches Node's HMAC", async () => {
      const r = await adminDb.query(
        "SELECT encode(pgguard.hmac_sha256(decode($1,'hex'), convert_to('pgguard:v1:42','UTF8')),'hex') AS m",
        [TEST_RLS_KEY_HEX],
      );
      expect(r.rows[0].m).toBe(principalMac("42", TEST_RLS_KEY_HEX));
    });

    test("gateway layer: run_select rejects the spoof, quoted and qualified forms", async () => {
      const token = signedJwt({ sub: "1" });
      for (const sql of [
        SPOOF,
        `SELECT employee_id FROM corp.orders WHERE "set_config"('app.user_id','2',true) IS NOT NULL`,
        `SELECT employee_id FROM corp.orders WHERE pg_catalog.SET_CONFIG('app.user_id','2',true) IS NOT NULL`,
      ]) {
        const res = parse(await handleTool(ctx(auditDir), "run_select", { sql, bearer_token: token }));
        expect(res.isError).toBe(true);
        expect(res.body.error).toMatch(/set_config/);
      }
    });

    test("gateway layer: forged / unsigned tokens are refused", async () => {
      const forged = parse(await handleTool(ctx(auditDir), "run_select", {
        sql: "SELECT 1", bearer_token: signedJwt({ sub: "2" }, "attacker"),
      }));
      expect(forged.isError).toBe(true);
      const none = parse(await handleTool(ctx(auditDir), "run_select", { sql: "SELECT 1", bearer_token: unsignedJwt({ sub: "2" }) }));
      expect(none.isError).toBe(true);
      const missing = parse(await handleTool(ctx(auditDir), "run_select", { sql: "SELECT 1" }));
      expect(missing.isError).toBe(true);
    });

    test("row cap: max_rows above policy and subquery LIMIT cannot raise it", async () => {
      await adminDb.query("INSERT INTO corp.orders (org_id, employee_id, amount_cents, status) SELECT 1, 1, g, 'pending' FROM generate_series(1, 150) g");
      const c = ctx(auditDir);
      c.policy.maxRows = 10;
      const token = signedJwt({ sub: "1" });
      const big = parse(await handleTool(c, "run_select", { sql: "SELECT id FROM corp.orders", max_rows: 1e9, bearer_token: token }));
      expect(big.body.rowCount).toBe(10);
      const sub = parse(await handleTool(c, "run_select", {
        sql: "SELECT id FROM corp.orders WHERE id IN (SELECT id FROM corp.orders LIMIT 5) OR true", bearer_token: token,
      }));
      expect(sub.body.rowCount).toBe(10);
      const small = parse(await handleTool(c, "run_select", { sql: "SELECT id FROM corp.orders", max_rows: 3, bearer_token: token }));
      expect(small.body.rowCount).toBe(3);
    });
  });
});
