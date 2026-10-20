/**
 * Phase 5 (offline): DB network allowlist, DNS pinning, verify-full requirement,
 * hash-chained audit log and the audit:verify CLI. No database needed.
 */
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  NetworkPolicyError,
  enforceNetworkPolicy,
  hostAllowed,
  hostEntryError,
  normAddress,
  type LookupFn,
  type NetworkPolicy,
} from "../src/net/allowlist.js";
import { buildConnectionConfig, sslConfigFor } from "../src/db/pool.js";
import { AuditLogger, GENESIS, auditKeyFromEnv, chainHash, verifyAuditFile } from "../src/audit/logger.js";
import {
  loadPolicyConfig,
  resolveAuditPolicy,
  resolveEffectivePolicy,
  resolveNetworkPolicy,
  hasCapability,
} from "../src/policy/loader.js";
import type { PolicyConfig } from "../src/policy/types.js";
import { handleTool } from "../src/mcp/tools.js";
import { credsForPolicy, type AppContext } from "../src/mcp/context.js";
import type { DbCredentials } from "../src/secrets/types.js";

const repo = process.cwd();
const shipped = () => loadPolicyConfig(path.join(repo, "config", "policy.yaml"));

function policy(over: Partial<NetworkPolicy> = {}): NetworkPolicy {
  return {
    enforced: true,
    allowedDbHosts: ["db.corp.internal", "*.rds.example.com", "10.0.0.5", "192.168.10.0/24", "localhost"],
    allowedDbCidrs: [],
    requireSslmode: "verify-full",
    plaintextLoopbackOk: true,
    pinResolvedIp: true,
    ...over,
  };
}

function creds(host: string, sslmode = "verify-full"): DbCredentials {
  return { host, port: 5432, database: "corpdb", user: "app_reader", password: "x", sslmode };
}

function fakeLookup(map: Record<string, string[]>): LookupFn & { calls: string[] } {
  const calls: string[] = [];
  const fn = (async (h: string) => {
    calls.push(h);
    const a = map[h];
    if (!a) throw new Error(`ENOTFOUND ${h}`);
    return a.map((address) => ({ address, family: address.includes(":") ? 6 : 4 }));
  }) as LookupFn & { calls: string[] };
  fn.calls = calls;
  return fn;
}

async function refusal(p: Promise<unknown>): Promise<NetworkPolicyError> {
  try {
    await p;
  } catch (e) {
    if (e instanceof NetworkPolicyError) return e;
    throw e;
  }
  throw new Error("expected a NetworkPolicyError");
}

describe("phase 5 network allowlist", () => {
  test("allowed_db_hosts entry validation", () => {
    for (const ok of ["db.corp.internal", "*.rds.example.com", "10.0.0.5", "::1", "10.0.0.0/8", "fd00::/8", "localhost", "pg_primary"]) {
      expect(hostEntryError(ok)).toBeNull();
    }
    expect(hostEntryError("")).toMatch(/non-empty/);
    expect(hostEntryError("db.*.internal")).toMatch(/leading/);
    expect(hostEntryError("*.*.example.com")).toMatch(/one leading wildcard/);
    expect(hostEntryError("*.com")).toMatch(/two labels/);
    expect(hostEntryError("10.0.0.0/33")).toMatch(/invalid CIDR/);
    expect(hostEntryError("bad host")).toMatch(/invalid host name/);
    expect(hostEntryError(42)).toMatch(/non-empty strings/);
  });

  test("host matching: exact, case/trailing dot, wildcard suffix, IPs and CIDRs", () => {
    const allow = policy().allowedDbHosts;
    expect(hostAllowed("db.corp.internal", allow)).toBe(true);
    expect(hostAllowed("DB.Corp.Internal.", allow)).toBe(true);
    expect(hostAllowed("a.rds.example.com", allow)).toBe(true);
    expect(hostAllowed("a.b.rds.example.com", allow)).toBe(true);
    expect(hostAllowed("rds.example.com", allow)).toBe(false); // wildcard needs a label
    expect(hostAllowed("evilrds.example.com", allow)).toBe(false);
    expect(hostAllowed("db.corp.internal.evil.io", allow)).toBe(false);
    expect(hostAllowed("xdb.corp.internal", allow)).toBe(false);
    expect(hostAllowed("10.0.0.5", allow)).toBe(true);
    expect(hostAllowed("10.0.0.6", allow)).toBe(false);
    expect(hostAllowed("192.168.10.77", allow)).toBe(true);
    expect(hostAllowed("192.168.11.1", allow)).toBe(false);
    expect(hostAllowed("::ffff:10.0.0.5", allow)).toBe(true);
    // A name never matches an IP/CIDR entry, and an IP never matches a name entry.
    expect(hostAllowed("10.0.0.5.nip.io", allow)).toBe(false);
    expect(normAddress("[::FFFF:10.0.0.5]")).toBe("10.0.0.5");
  });

  test("host not on the list is refused before DNS is even asked", async () => {
    const lookup = fakeLookup({ "db.evil.io": ["10.0.0.5"] });
    const e = await refusal(enforceNetworkPolicy(creds("db.evil.io"), policy(), lookup));
    expect(e.code).toBe("host_not_allowed");
    expect(lookup.calls).toEqual([]);
  });

  test("link-local / metadata and unspecified addresses are always refused", async () => {
    for (const addr of ["169.254.169.254", "::ffff:169.254.169.254", "fe80::1", "0.0.0.0", "::"]) {
      const lookup = fakeLookup({ "db.corp.internal": [addr] });
      const e = await refusal(enforceNetworkPolicy(creds("db.corp.internal"), policy({ allowedDbCidrs: ["0.0.0.0/0", "::/0"] }), lookup));
      expect(e.code).toBe("address_forbidden");
    }
  });

  test("allowed_db_cidrs: every resolved address must be inside", async () => {
    const p = policy({ allowedDbCidrs: ["10.20.0.0/16"] });
    const okLookup = fakeLookup({ "db.corp.internal": ["10.20.1.1", "10.20.9.9"] });
    const r = await enforceNetworkPolicy(creds("db.corp.internal"), p, okLookup);
    expect(r.decision!.resolved).toEqual(["10.20.1.1", "10.20.9.9"]);
    // One good answer does not excuse a bad one (round-robin to an attacker host).
    const mixed = fakeLookup({ "db.corp.internal": ["10.20.1.1", "203.0.113.9"] });
    const e = await refusal(enforceNetworkPolicy(creds("db.corp.internal"), p, mixed));
    expect(e.code).toBe("address_not_allowed");
    expect(e.message).toMatch(/203\.0\.113\.9/);
  });

  test("non-loopback hosts need sslmode=verify-full", async () => {
    const lookup = fakeLookup({ "db.corp.internal": ["10.0.0.9"] });
    for (const mode of ["disable", "require", "prefer", "verify-ca"]) {
      const e = await refusal(enforceNetworkPolicy(creds("db.corp.internal", mode), policy(), lookup));
      expect(e.code).toBe("tls_required");
    }
    const ok = await enforceNetworkPolicy(creds("db.corp.internal", "verify-full"), policy(), lookup);
    expect(ok.decision!.sslmode).toBe("verify-full");
  });

  test("plaintext is allowed only for loopback-only targets, and only when enabled", async () => {
    const lookup = fakeLookup({ localhost: ["::1", "127.0.0.1"] });
    const r = await enforceNetworkPolicy(creds("localhost", "disable"), policy(), lookup);
    expect(r.decision!.loopbackOnly).toBe(true);
    const off = await refusal(enforceNetworkPolicy(creds("localhost", "disable"), policy({ plaintextLoopbackOk: false }), lookup));
    expect(off.code).toBe("tls_required");
    // A name that resolves to loopback AND a remote address is not loopback-only.
    const mixed = fakeLookup({ localhost: ["127.0.0.1", "10.0.0.9"] });
    expect((await refusal(enforceNetworkPolicy(creds("localhost", "disable"), policy(), mixed))).code).toBe("tls_required");
  });

  test("DNS pinning: connect to the checked IP, verify TLS against the original name", async () => {
    let n = 0;
    const rebinding: LookupFn = async () => [{ address: n++ === 0 ? "10.0.0.9" : "203.0.113.66", family: 4 }];
    const r = await enforceNetworkPolicy(creds("db.corp.internal"), policy(), rebinding);
    expect(n).toBe(1); // resolved once; a later (rebound) answer is never used
    expect(r.creds.host).toBe("10.0.0.9");
    expect(r.creds.tlsServername).toBe("db.corp.internal");
    const cfg = buildConnectionConfig(r.creds);
    expect(cfg.host).toBe("10.0.0.9");
    expect(cfg.ssl).toEqual({ rejectUnauthorized: true, servername: "db.corp.internal" });
  });

  test("IP literal: no DNS, no servername; pinning off keeps the name", async () => {
    const lookup = fakeLookup({});
    const r = await enforceNetworkPolicy(creds("10.0.0.5"), policy(), lookup);
    expect(lookup.calls).toEqual([]);
    expect(r.creds.host).toBe("10.0.0.5");
    expect(r.creds.tlsServername).toBeUndefined();
    const nopin = await enforceNetworkPolicy(creds("db.corp.internal"), policy({ pinResolvedIp: false }), fakeLookup({ "db.corp.internal": ["10.0.0.9"] }));
    expect(nopin.creds.host).toBe("db.corp.internal");
  });

  test("DNS failure is a refusal, not a fallback", async () => {
    const e = await refusal(enforceNetworkPolicy(creds("db.corp.internal"), policy(), fakeLookup({})));
    expect(e.code).toBe("dns_failed");
  });

  test("no network block = not enforced (passthrough)", async () => {
    const off = resolveNetworkPolicy({ roles: {} } as unknown as PolicyConfig);
    expect(off.enforced).toBe(false);
    const c = creds("anything.example", "disable");
    const r = await enforceNetworkPolicy(c, off, fakeLookup({}));
    expect(r.creds).toBe(c);
    expect(r.decision).toBeNull();
  });

  test("network block validation", () => {
    const base = { roles: {} } as unknown as PolicyConfig;
    const v = (network: unknown) => () => resolveNetworkPolicy({ ...base, network } as PolicyConfig);
    expect(v({})).toThrow(/non-empty list/);
    expect(v({ allowed_db_hosts: [] })).toThrow(/non-empty list/);
    expect(v({ allowed_db_hosts: ["db.*.x"] })).toThrow(/leading/);
    expect(v({ allowed_db_hosts: ["a.b"], allowed_db_cidrs: ["10.0.0.1"] })).toThrow(/invalid CIDR/);
    expect(v({ allowed_db_hosts: ["a.b"], require_sslmode: "require" })).toThrow(/verify-full/);
    expect(v({ allowed_db_hosts: ["a.b"], plaintext_loopback_ok: "yes" })).toThrow(/true or false/);
    const ok = resolveNetworkPolicy({ ...base, network: { allowed_db_hosts: ["a.b"] } } as PolicyConfig);
    expect(ok).toMatchObject({ enforced: true, plaintextLoopbackOk: false, pinResolvedIp: true });
  });

  test("shipped policy: allowlist on, loopback-only plaintext, reader has no audit_read", () => {
    const eff = resolveEffectivePolicy(shipped(), "reader");
    expect(eff.network.enforced).toBe(true);
    expect(eff.network.allowedDbHosts).toEqual(["localhost", "127.0.0.1", "::1"]);
    expect(eff.network.requireSslmode).toBe("verify-full");
    expect(eff.audit).toEqual({ hashChain: true, hmacKeyEnv: "PGGUARD_AUDIT_HMAC_KEY", verifyOnStart: true });
    expect(hasCapability(eff, "audit_read")).toBe(false);
    expect(hasCapability(resolveEffectivePolicy(shipped(), "writer"), "audit_read")).toBe(true);
  });

  test("sslConfigFor passes the CA and servername for verifying modes only", () => {
    expect(sslConfigFor("verify-full", { ca: "PEM", servername: "db" })).toEqual({ rejectUnauthorized: true, ca: "PEM", servername: "db" });
    const vca = sslConfigFor("verify-ca", { ca: "PEM" }) as Record<string, unknown>;
    expect(vca.ca).toBe("PEM");
    expect(sslConfigFor("require", { ca: "PEM" })).toEqual({ rejectUnauthorized: false });
    expect(() => buildConnectionConfig({ ...creds("db"), sslrootcert: "/nonexistent/ca.pem" })).toThrow(/Cannot read sslrootcert/);
  });
});

describe("phase 5 tools: refused before any DB access", () => {
  let dir: string;
  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "pgguard-p5-"));
  });
  afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));

  function ctx(host: string, sslmode = "disable"): AppContext {
    const p = resolveEffectivePolicy(shipped(), "reader");
    p.principalPropagation = { ...p.principalPropagation, require_jwt: false, enabled: false };
    return {
      secrets: { getDbCredentials: async () => ({ ...creds(host, sslmode), port: 1 }) },
      audit: new AuditLogger(path.join(dir, "audit")),
      policy: p,
      lookup: async () => {
        throw new Error("DNS must not be consulted for a host that is not allowlisted");
      },
    };
  }

  test("every DB tool refuses a non-allowlisted host and audits it", async () => {
    const c = ctx("db.attacker.example");
    for (const [tool, args] of [
      ["db_health", {}],
      ["list_schemas", {}],
      ["run_select", { sql: "SELECT 1" }],
      ["explain_query", { sql: "SELECT 1" }],
    ] as const) {
      const r = await handleTool(c, tool, { ...args });
      expect(r.isError).toBe(true);
      expect(r.content[0]!.text).toMatch(/not in network.allowed_db_hosts/);
    }
    const tail = c.audit.tail(1)[0]!;
    expect(tail.ok).toBe(false);
    expect(c.audit.verify().ok).toBe(true);
  });

  test("remote IP with sslmode=disable is refused (tls_required)", async () => {
    const p = resolveEffectivePolicy(shipped(), "reader");
    p.network = { ...p.network, allowedDbHosts: [...p.network.allowedDbHosts, "10.9.9.9"] };
    const c: AppContext = { ...ctx("10.9.9.9"), policy: p };
    await expect(credsForPolicy(c)).rejects.toThrow(/requires sslmode=verify-full/);
  });

  test("reader cannot read the audit log by default", async () => {
    const r = await handleTool(ctx("localhost"), "get_audit_tail", { n: 5 });
    expect(r.isError).toBe(true);
    expect(r.content[0]!.text).toMatch(/not allowed to perform 'audit_read'/);
  });

  test("whoami reports network and audit settings", async () => {
    const r = await handleTool(ctx("localhost"), "whoami", {});
    const body = JSON.parse(r.content[0]!.text);
    expect(body.network).toMatchObject({ enforced: true, require_sslmode: "verify-full", pin_resolved_ip: true });
    expect(body.audit).toMatchObject({ hash_chain: true, alg: "sha256" });
  });
});

describe("phase 5 tamper-evident audit", () => {
  let dir: string;
  const KEY = crypto.randomBytes(32);
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "pgguard-audit-"));
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  const file = () => path.join(dir, "events.jsonl");
  const lines = () => fs.readFileSync(file(), "utf8").trim().split("\n");
  const write = (ls: string[]) => fs.writeFileSync(file(), ls.join("\n") + "\n");

  function seed(n: number, key: Buffer | null = null): AuditLogger {
    const a = new AuditLogger(dir, { hmacKey: key });
    for (let i = 0; i < n; i++) a.append({ tool: "run_select", role: "reader", ok: i % 2 === 0, sqlPreview: `SELECT ${i}` });
    return a;
  }

  test("chain links: seq, prev, hash; head reported", () => {
    const a = seed(4);
    const evs = lines().map((l) => JSON.parse(l));
    expect(evs.map((e) => e.seq)).toEqual([0, 1, 2, 3]);
    expect(evs[0].prev).toBe(GENESIS);
    for (let i = 1; i < 4; i++) expect(evs[i].prev).toBe(evs[i - 1].hash);
    const { hash, ...body } = evs[2];
    expect(chainHash(evs[2].prev, body, null)).toBe(hash);
    const v = a.verify();
    expect(v).toMatchObject({ ok: true, chained: 4, legacy: 0, alg: "sha256", head: { seq: 3, hash: evs[3].hash } });
  });

  test("full SQL hash is recorded even though the preview is cut at 500 chars", () => {
    const a = new AuditLogger(dir, { hmacKey: null });
    const sql = `SELECT '${"x".repeat(2000)}'`;
    const ev = a.append({ tool: "run_select", role: "reader", ok: true, sqlPreview: sql });
    expect(ev.sqlPreview!.length).toBe(500);
    expect(ev.sql_sha256).toBe(crypto.createHash("sha256").update(sql).digest("hex"));
  });

  test("edited field is caught at that line", () => {
    seed(5);
    const ls = lines();
    const ev = JSON.parse(ls[1]!);
    ev.ok = true;
    ev.error = undefined;
    ls[1] = JSON.stringify(ev);
    write(ls);
    expect(verifyAuditFile(file()).error).toEqual({ line: 2, reason: expect.stringMatching(/hash mismatch/) });
  });

  test("deleted, reordered and inserted lines are caught", () => {
    seed(5);
    const orig = lines();
    write([orig[0]!, orig[2]!, orig[3]!, orig[4]!]);
    expect(verifyAuditFile(file()).error!.line).toBe(2);
    write([orig[0]!, orig[2]!, orig[1]!, orig[3]!, orig[4]!]);
    expect(verifyAuditFile(file()).error!.line).toBe(2);
    write([orig[0]!, orig[1]!, JSON.stringify({ ts: "x", tool: "t", role: "r", ok: true }), ...orig.slice(2)]);
    expect(verifyAuditFile(file()).error).toEqual({ line: 3, reason: expect.stringMatching(/unchained line after/) });
    write(["{not json", ...orig]);
    expect(verifyAuditFile(file()).error!.reason).toMatch(/not valid JSON/);
  });

  test("dropping the oldest lines breaks the chain (first line must start at GENESIS)", () => {
    seed(3);
    write(lines().slice(1));
    expect(verifyAuditFile(file()).error!.line).toBe(1);
  });

  test("truncating the tail is only caught against a recorded head", () => {
    const a = seed(5);
    const head = a.verify().head!;
    write(lines().slice(0, 3));
    expect(verifyAuditFile(file()).ok).toBe(true); // honest limit
    const r = verifyAuditFile(file(), null, { expectHead: head });
    expect(r.ok).toBe(false);
    expect(r.error!.reason).toMatch(/not in the log/);
  });

  test("without a key a full rewrite verifies; with an HMAC key it does not", () => {
    // Attacker rewrites line 1 and recomputes the plain sha256 chain.
    seed(3);
    const evs = lines().map((l) => JSON.parse(l));
    evs[1].ok = !evs[1].ok;
    let prev = GENESIS;
    for (const e of evs) {
      e.prev = prev;
      delete e.hash;
      e.hash = chainHash(prev, JSON.parse(JSON.stringify(e)), null);
      prev = e.hash;
    }
    write(evs.map((e) => JSON.stringify(e)));
    expect(verifyAuditFile(file()).ok).toBe(true); // why the HMAC key exists

    fs.rmSync(file());
    seed(3, KEY);
    const hm = lines().map((l) => JSON.parse(l));
    expect(hm[0].alg).toBe("hmac-sha256");
    hm[1].ok = !hm[1].ok;
    let p2 = GENESIS;
    for (const e of hm) {
      e.prev = p2;
      delete e.hash;
      e.hash = chainHash(p2, JSON.parse(JSON.stringify(e)), crypto.randomBytes(32)); // attacker lacks KEY
      p2 = e.hash;
    }
    write(hm.map((e) => JSON.stringify(e)));
    expect(verifyAuditFile(file(), KEY).error!.line).toBe(1);
  });

  test("HMAC chain needs the key; a plain chain is refused when a key is given (downgrade)", () => {
    seed(2, KEY);
    expect(verifyAuditFile(file(), KEY).ok).toBe(true);
    expect(verifyAuditFile(file()).error!.reason).toMatch(/set the audit HMAC key/);
    fs.rmSync(file());
    seed(2);
    expect(verifyAuditFile(file(), KEY).error!.reason).toMatch(/downgrade/);
  });

  test("restart continues the chain; two writers on one file stay consistent", () => {
    seed(2);
    const b = new AuditLogger(dir, { hmacKey: null, verifyOnStart: true });
    const c = new AuditLogger(dir, { hmacKey: null });
    b.append({ tool: "x", role: "r", ok: true });
    c.append({ tool: "y", role: "r", ok: true });
    b.append({ tool: "z", role: "r", ok: true });
    const v = verifyAuditFile(file());
    expect(v).toMatchObject({ ok: true, chained: 5, head: { seq: 4 } });
  });

  test("legacy (pre-phase-5) lines are counted, then the chain starts", () => {
    write([JSON.stringify({ ts: "t", tool: "old", role: "reader", ok: true }), JSON.stringify({ ts: "t", tool: "old", role: "reader", ok: false })]);
    const a = new AuditLogger(dir, { hmacKey: null, verifyOnStart: true });
    a.append({ tool: "new", role: "reader", ok: true });
    expect(a.verify()).toMatchObject({ ok: true, legacy: 2, chained: 1 });
  });

  test("verify_on_start refuses a tampered log", () => {
    seed(3);
    const ls = lines();
    ls[0] = ls[0]!.replace('"role":"reader"', '"role":"admin"');
    write(ls);
    expect(() => new AuditLogger(dir, { hmacKey: null, verifyOnStart: true })).toThrow(/failed verification at line 1/);
  });

  test("audit key env: must be hex and at least 32 bytes", () => {
    process.env.PGGUARD_TEST_AUDIT_KEY = "abcd";
    expect(() => auditKeyFromEnv("PGGUARD_TEST_AUDIT_KEY")).toThrow(/at least 32 bytes/);
    process.env.PGGUARD_TEST_AUDIT_KEY = "zz".repeat(32);
    expect(() => auditKeyFromEnv("PGGUARD_TEST_AUDIT_KEY")).toThrow(/hex/);
    process.env.PGGUARD_TEST_AUDIT_KEY = "ab".repeat(32);
    expect(auditKeyFromEnv("PGGUARD_TEST_AUDIT_KEY")!.length).toBe(32);
    delete process.env.PGGUARD_TEST_AUDIT_KEY;
    expect(auditKeyFromEnv("PGGUARD_TEST_AUDIT_KEY")).toBeNull();
  });

  test("audit block validation", () => {
    const base = { roles: {} } as unknown as PolicyConfig;
    expect(() => resolveAuditPolicy({ ...base, audit: { hash_chain: "yes" } } as unknown as PolicyConfig)).toThrow(/true or false/);
    expect(() => resolveAuditPolicy({ ...base, audit: { hmac_key_env: "lower" } } as PolicyConfig)).toThrow(/env var name/);
    expect(resolveAuditPolicy(base)).toEqual({ hashChain: true, hmacKeyEnv: "PGGUARD_AUDIT_HMAC_KEY", verifyOnStart: true });
  });

  test("audit:verify CLI exit codes", () => {
    const a = seed(3);
    const head = a.verify().head!;
    const run = (...args: string[]) =>
      spawnSync(process.execPath, [path.join(repo, "node_modules", "tsx", "dist", "cli.mjs"), "src/audit/verify-cli.ts", ...args], {
        cwd: repo,
        encoding: "utf8",
        env: { ...process.env, PGGUARD_AUDIT_HMAC_KEY: "" },
      });
    const ok = run(file(), "--expect-head", `${head.seq}:${head.hash}`);
    expect(ok.status).toBe(0);
    expect(JSON.parse(ok.stdout)).toMatchObject({ ok: true, chained: 3 });
    write(lines().slice(0, 2));
    expect(run(file(), "--expect-head", `${head.seq}:${head.hash}`).status).toBe(1);
    expect(run(file(), "--expect-head", "nope").status).toBe(2);
  }, 30_000);
});
