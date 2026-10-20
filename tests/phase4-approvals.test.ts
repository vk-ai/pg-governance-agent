/**
 * Phase 4 offline tests: signed, single-use, expiring, SQL-bound approvals.
 * No database: tools are pointed at port 1, so any DB access would fail loudly.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { handleTool } from "../src/mcp/tools.js";
import type { AppContext } from "../src/mcp/context.js";
import { AuditLogger } from "../src/audit/logger.js";
import { loadPolicyConfig, resolveApprovalPolicy, resolveEffectivePolicy, validatePolicyFile } from "../src/policy/loader.js";
import type { PolicyConfig } from "../src/policy/types.js";
import {
  ApprovalError,
  newJti,
  signApproval,
  sqlSha256,
  verifyApproval,
  type ApprovalClaims,
  type ApprovalScope,
} from "../src/approvals/token.js";
import { FileLedger } from "../src/approvals/ledger.js";
import { RequestQueue } from "../src/approvals/requests.js";
import { createApprovalRuntime, effectiveAffectedCap, loadServerPublicKey, privateKeyInServerEnv } from "../src/approvals/gate.js";
import { approveRequest, keygen } from "../src/approvals/cli.js";

const repo = process.cwd();
const cfg = loadPolicyConfig(path.join(repo, "config", "policy.yaml"));
const keys = generateKeyPairSync("ed25519");
const otherKeys = generateKeyPairSync("ed25519");
const pubPem = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
const NOW = 1_800_000_000;
const SQL = "UPDATE corp.orders SET status = 'paid' WHERE id = 7";

const scope: ApprovalScope = {
  tool: "run_dml",
  role: "writer",
  db_user: "app_writer",
  database: "pgguard",
  sub: "2",
  sql_sha256: sqlSha256(SQL),
};

function claims(over: Partial<ApprovalClaims> = {}): ApprovalClaims {
  return { v: 1, jti: newJti(), rid: "a".repeat(24), approver: "alice", iat: NOW, exp: NOW + 600, ...scope, ...over };
}
const opts = (publicKey: KeyObject = keys.publicKey, now = NOW) => ({ publicKey, now, maxTtlSeconds: 900, clockSkewSeconds: 30 });

function codeOf(fn: () => unknown): string | undefined {
  try {
    fn();
    return undefined;
  } catch (e) {
    return e instanceof ApprovalError ? e.code : `non-approval: ${(e as Error).message}`;
  }
}

describe("approval tokens", () => {
  test("round trip verifies and returns claims", () => {
    const c = claims();
    expect(verifyApproval(signApproval(c, keys.privateKey), scope, opts())).toEqual(c);
  });

  test("tampered claims break the signature", () => {
    const t = signApproval(claims(), keys.privateKey);
    const [p, body, sig] = t.split(".");
    const forged = JSON.parse(Buffer.from(body!, "base64url").toString());
    forged.sql_sha256 = sqlSha256("DELETE FROM corp.orders");
    const t2 = [p, Buffer.from(JSON.stringify(forged)).toString("base64url"), sig].join(".");
    expect(codeOf(() => verifyApproval(t2, { ...scope, sql_sha256: forged.sql_sha256 }, opts()))).toBe("bad_signature");
  });

  test("token signed by another key is rejected", () => {
    expect(codeOf(() => verifyApproval(signApproval(claims(), otherKeys.privateKey), scope, opts()))).toBe("bad_signature");
  });

  test("expiry has no grace; one second before is fine", () => {
    const t = signApproval(claims(), keys.privateKey);
    expect(codeOf(() => verifyApproval(t, scope, opts(keys.publicKey, NOW + 599)))).toBeUndefined();
    expect(codeOf(() => verifyApproval(t, scope, opts(keys.publicKey, NOW + 600)))).toBe("expired");
  });

  test("iat in the future: tolerated within clock skew, rejected beyond", () => {
    expect(codeOf(() => verifyApproval(signApproval(claims({ iat: NOW + 20, exp: NOW + 620 }), keys.privateKey), scope, opts()))).toBeUndefined();
    expect(codeOf(() => verifyApproval(signApproval(claims({ iat: NOW + 60, exp: NOW + 660 }), keys.privateKey), scope, opts()))).toBe("not_yet_valid");
  });

  test("lifetime above max_ttl_seconds is rejected even if signed", () => {
    expect(codeOf(() => verifyApproval(signApproval(claims({ exp: NOW + 901 }), keys.privateKey), scope, opts()))).toBe("ttl_too_long");
  });

  test.each([
    ["trailing space", SQL + " "],
    ["different id", SQL.replace("7", "8")],
    ["added clause", SQL + " OR true"],
  ])("SQL bound by hash: %s needs a new approval", (_n, other) => {
    const t = signApproval(claims(), keys.privateKey);
    expect(codeOf(() => verifyApproval(t, { ...scope, sql_sha256: sqlSha256(other) }, opts()))).toBe("sql_mismatch");
  });

  test.each([
    ["tool", { tool: "run_ddl" }],
    ["role", { role: "admin" }],
    ["db_user", { db_user: "app_migrator" }],
    ["database", { database: "prod" }],
    ["sub", { sub: "3" }],
    ["sub null", { sub: null }],
  ] as [string, Partial<ApprovalScope>][])("scope bound: %s", (_n, diff) => {
    const t = signApproval(claims(), keys.privateKey);
    expect(codeOf(() => verifyApproval(t, { ...scope, ...diff }, opts()))).toBe("scope_mismatch");
  });

  test("approver equal to the requesting principal is rejected", () => {
    expect(codeOf(() => verifyApproval(signApproval(claims({ approver: "2" }), keys.privateKey), scope, opts()))).toBe("self_approval");
  });

  test.each([
    ["wrong prefix", "pgx1.a.b"],
    ["two parts", "pga1.abc"],
    ["empty", ""],
  ])("malformed: %s", (_n, t) => {
    expect(codeOf(() => verifyApproval(t, scope, opts()))).toBe("malformed");
  });

  test("signed but badly shaped claims are rejected", () => {
    expect(codeOf(() => verifyApproval(signApproval(claims({ jti: "../../etc" }), keys.privateKey), scope, opts()))).toBe("malformed");
    expect(codeOf(() => verifyApproval(signApproval(claims({ max_affected_rows: -1 }), keys.privateKey), scope, opts()))).toBe("malformed");
  });

  test("approver row cap is min()'d with the policy cap", () => {
    expect(effectiveAffectedCap(50, claims({ max_affected_rows: 1 }))).toBe(1);
    expect(effectiveAffectedCap(50, claims({ max_affected_rows: 500 }))).toBe(50);
    expect(effectiveAffectedCap(50, null)).toBe(50);
  });
});

describe("file ledger + request queue", () => {
  let dir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "pgguard-p4-"));
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  test("a jti is accepted once", async () => {
    const l = new FileLedger(path.join(dir, "used"));
    const c = claims();
    await l.consume(c);
    expect(l.isConsumed(c.jti)).toBe(true);
    await expect(l.consume(c)).rejects.toMatchObject({ code: "replayed" });
  });

  test("ten ledger instances sharing one directory: exactly one consume wins", async () => {
    const c = claims();
    const ledgers = Array.from({ length: 10 }, () => new FileLedger(path.join(dir, "used")));
    const r = await Promise.allSettled(ledgers.map((l) => l.consume(c)));
    expect(r.filter((x) => x.status === "fulfilled")).toHaveLength(1);
  });

  test("queue status: pending → approved / denied; ids are validated", () => {
    const q = new RequestQueue(dir);
    const r1 = q.create({ ...scope, sql: SQL });
    expect(r1.sql_sha256).toBe(sqlSha256(SQL));
    expect(q.status(r1.rid)).toBe("pending");
    expect(codeOf(() => q.tokenFor(r1.rid))).toBe("pending");
    q.writeToken(r1.rid, "pga1.x.y");
    expect(q.tokenFor(r1.rid)).toBe("pga1.x.y");
    const r2 = q.create({ ...scope, sql: SQL });
    q.writeDenial(r2.rid, "bob", "too broad");
    expect(codeOf(() => q.tokenFor(r2.rid))).toBe("denied");
    expect(codeOf(() => q.tokenFor("0".repeat(24)))).toBe("missing");
    expect(codeOf(() => q.status("../../../etc/passwd"))).toBe("malformed");
  });
});

describe("approver CLI", () => {
  let dir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "pgguard-p4cli-"));
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  test("approve signs a token the server accepts; defaults the row cap to the dry-run count", () => {
    const q = new RequestQueue(dir);
    const req = q.create({ ...scope, sql: SQL, preview: { rowCount: 1, would_exceed_cap: false, max_affected_rows: 50 } });
    const { token, claims: c } = approveRequest(req, { approver: "alice", privateKey: keys.privateKey, now: NOW, ttlSeconds: 300 });
    expect(c.max_affected_rows).toBe(1);
    expect(c.exp - c.iat).toBe(300);
    expect(verifyApproval(token, scope, opts()).rid).toBe(req.rid);
  });

  test("refuses a queue file whose SQL was edited after the request", () => {
    const q = new RequestQueue(dir);
    const req = q.create({ ...scope, sql: SQL });
    const edited = { ...req, sql: "DELETE FROM corp.orders" };
    expect(() => approveRequest(edited, { approver: "alice", privateKey: keys.privateKey })).toThrow(/edited/);
  });

  test("refuses self-approval and an empty approver", () => {
    const req = new RequestQueue(dir).create({ ...scope, sql: SQL });
    expect(() => approveRequest(req, { approver: "2", privateKey: keys.privateKey })).toThrow(/self_approval/);
    expect(() => approveRequest(req, { approver: " ", privateKey: keys.privateKey })).toThrow(/--approver/);
  });

  test("keygen writes a 0600 private key and a public key the server can load", () => {
    const k = keygen(path.join(dir, "keys"));
    expect(fs.statSync(k.privatePath).mode & 0o777).toBe(0o600);
    const pol = resolveApprovalPolicy(cfg, cfg.roles.writer!, "writer");
    expect(loadServerPublicKey(pol, { PGGUARD_APPROVAL_PUBLIC_KEY_FILE: k.publicPath })).not.toBeNull();
    expect(loadServerPublicKey(pol, { PGGUARD_APPROVAL_PUBLIC_KEY: pubPem.replace(/\n/g, "\\n") })).not.toBeNull();
    expect(loadServerPublicKey(pol, {})).toBeNull();
  });
});

describe("policy", () => {
  test("shipped policy requires approvals for dml and ddl with a file ledger", () => {
    const p = resolveEffectivePolicy(cfg, "writer").approvals;
    expect(p.requiredFor).toEqual(["dml", "ddl"]);
    expect(p.ledger).toBe("file");
    expect(p.maxTtlSeconds).toBe(900);
    expect(validatePolicyFile(path.join(repo, "config", "policy.yaml"))).toEqual({ ok: true, errors: [] });
  });

  test("role override and validation", () => {
    const c: PolicyConfig = JSON.parse(JSON.stringify(cfg));
    c.roles.writer!.approvals_required_for = [];
    expect(resolveEffectivePolicy(c, "writer").approvals.requiredFor).toEqual([]);
    c.roles.writer!.approvals_required_for = ["select" as never];
    expect(() => resolveEffectivePolicy(c, "writer")).toThrow(/unknown kind/);
    const c2: PolicyConfig = JSON.parse(JSON.stringify(cfg));
    c2.approvals = { ...c2.approvals, ledger: "redis" as never };
    expect(() => resolveEffectivePolicy(c2, "writer")).toThrow(/ledger/);
    c2.approvals = { ...c2.approvals, ledger: "file", max_ttl_seconds: 0 };
    expect(() => resolveEffectivePolicy(c2, "writer")).toThrow(/max_ttl_seconds/);
  });

  test("private key env in the server environment is detected", () => {
    expect(privateKeyInServerEnv({ PGGUARD_APPROVAL_PRIVATE_KEY_FILE: "/x" })).toEqual(["PGGUARD_APPROVAL_PRIVATE_KEY_FILE"]);
    expect(privateKeyInServerEnv({ PGGUARD_APPROVAL_PUBLIC_KEY: "x" })).toEqual([]);
  });
});

describe("tools: approval gate runs before the statement", () => {
  let dir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "pgguard-p4tools-"));
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  function ctx(role = "writer", withKey = true): AppContext {
    const policy = resolveEffectivePolicy(cfg, role);
    policy.principalPropagation = { ...policy.principalPropagation, require_jwt: false, enabled: false };
    policy.approvals = { ...policy.approvals, dir };
    return {
      secrets: {
        // Port 1: any connection attempt fails with ECONNREFUSED.
        getDbCredentials: async (user?: string) => ({ host: "127.0.0.1", port: 1, database: "pgguard", user: user || "app_writer", password: "x", sslmode: "disable" }),
      },
      audit: new AuditLogger(path.join(dir, "audit")),
      policy,
      approvals: createApprovalRuntime(policy.approvals, withKey ? { PGGUARD_APPROVAL_PUBLIC_KEY: pubPem } : {}),
    };
  }
  const parse = (r: { content: { text: string }[]; isError?: boolean }) => ({ isError: Boolean(r.isError), body: JSON.parse(r.content[0]!.text) });
  const noSub: ApprovalScope = { ...scope, sub: null };
  const now = () => Math.floor(Date.now() / 1000);
  const tok = (over: Partial<ApprovalClaims> = {}) =>
    signApproval(claims({ ...noSub, iat: now(), exp: now() + 300, ...over }), keys.privateKey);

  test("confirm:true alone is not enough", async () => {
    const r = parse(await handleTool(ctx(), "run_dml", { sql: SQL, confirm: true }));
    expect(r.isError).toBe(true);
    expect(r.body.error).toMatch(/Approval rejected \(missing\)/);
  });

  test("fails closed when no public key is configured", async () => {
    const r = parse(await handleTool(ctx("writer", false), "run_dml", { sql: SQL, confirm: true, approval_token: tok() }));
    expect(r.body.error).toMatch(/not_configured/);
  });

  test("token for other SQL is refused and not consumed", async () => {
    const c = ctx();
    const t = tok({ sql_sha256: sqlSha256("DELETE FROM corp.orders WHERE id = 1") });
    const r = parse(await handleTool(c, "run_dml", { sql: SQL, confirm: true, approval_token: t }));
    expect(r.body.error).toMatch(/sql_mismatch/);
    expect(fs.existsSync(path.join(dir, "used")) ? fs.readdirSync(path.join(dir, "used")) : []).toEqual([]);
  });

  test("token for another role is refused", async () => {
    const r = parse(await handleTool(ctx(), "run_dml", { sql: SQL, confirm: true, approval_token: tok({ role: "admin" }) }));
    expect(r.body.error).toMatch(/scope_mismatch/);
  });

  test("valid token is consumed before the DB call; the replay is refused", async () => {
    const c = ctx();
    const t = tok();
    const first = parse(await handleTool(c, "run_dml", { sql: SQL, confirm: true, approval_token: t }));
    // Approval passed and was spent; then the (unreachable) DB failed.
    expect(first.body.error).toMatch(/ECONNREFUSED|connect/);
    expect(fs.readdirSync(path.join(dir, "used"))).toHaveLength(1);
    const again = parse(await handleTool(c, "run_dml", { sql: SQL, confirm: true, approval_token: t }));
    expect(again.body.error).toMatch(/replayed/);
  });

  test("approval_id: pending, then denied", async () => {
    const c = ctx("migrator");
    const ddl = "CREATE INDEX orders_status_idx ON corp.orders (status)";
    const req = parse(await handleTool(c, "request_approval", { tool: "run_ddl", sql: ddl, reason: "speed up status filter" }));
    expect(req.isError).toBe(false);
    expect(req.body.status).toBe("pending");
    expect(req.body.sql_sha256).toBe(sqlSha256(ddl));
    const pending = parse(await handleTool(c, "run_ddl", { sql: ddl, confirm: true, approval_id: req.body.approval_id }));
    expect(pending.body.error).toMatch(/\(pending\)/);
    new RequestQueue(dir).writeDenial(req.body.approval_id, "bob");
    const denied = parse(await handleTool(c, "run_ddl", { sql: ddl, confirm: true, approval_id: req.body.approval_id }));
    expect(denied.body.error).toMatch(/\(denied\)/);
  });

  test("request_approval checks capability, statement kind and schema before queueing", async () => {
    expect(parse(await handleTool(ctx("reader"), "request_approval", { tool: "run_dml", sql: SQL })).body.error).toMatch(/not allowed to perform 'dml'/);
    expect(parse(await handleTool(ctx("migrator"), "request_approval", { tool: "run_ddl", sql: "SELECT 1" })).body.error).toMatch(/Expected DDL/);
    expect(parse(await handleTool(ctx("migrator"), "request_approval", { tool: "run_ddl", sql: "DROP TABLE hr.salaries" })).body.error).toMatch(/'hr'/);
    expect(fs.existsSync(path.join(dir, "pending")) ? fs.readdirSync(path.join(dir, "pending")) : []).toEqual([]);
  });

  test("dry_run needs no approval (reaches the DB)", async () => {
    const r = parse(await handleTool(ctx(), "run_dml", { sql: SQL, dry_run: true }));
    expect(r.body.error).toMatch(/ECONNREFUSED|connect/);
  });

  test("whoami reports approval settings without exposing keys", async () => {
    const r = parse(await handleTool(ctx(), "whoami", {}));
    expect(r.body.approvals).toEqual({
      required_for: ["dml", "ddl"],
      public_key_configured: true,
      ledger: "file",
      max_ttl_seconds: 900,
      private_key_env_in_server: [],
    });
  });
});
