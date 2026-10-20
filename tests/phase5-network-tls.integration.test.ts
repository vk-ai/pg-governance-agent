/**
 * Live Postgres 17: phase 5 network allowlist, DNS pinning, verify-full TLS and
 * the hash-chained audit log through real tool calls.
 *
 * TLS tests need the server's certificate: PGGUARD_IT_TLS_CA=<pem> (CI copies
 * it out of the container), or a readable ssl_cert_file on the same host. The
 * certificate's DNS name is mapped to the server address with an injected
 * resolver, so no /etc/hosts edits are needed. They skip when ssl is off,
 * unless PGGUARD_IT_REQUIRE_TLS=1 (CI), which turns a skip into a failure.
 *
 * Skipped unless PGGUARD_IT_DATABASE_URL points at a superuser connection.
 */
import { X509Certificate } from "node:crypto";
import dns from "node:dns";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import pg from "pg";
import { closePool } from "../src/db/pool.js";
import { runPreflight } from "../src/db/preflight.js";
import { handleTool } from "../src/mcp/tools.js";
import { credsForPolicy, type AppContext } from "../src/mcp/context.js";
import { AuditLogger, verifyAuditFile } from "../src/audit/logger.js";
import { loadPolicyConfig, resolveEffectivePolicy } from "../src/policy/loader.js";
import type { LookupFn } from "../src/net/allowlist.js";
import type { DbCredentials } from "../src/secrets/types.js";
import { PHASE2_SQL_FILES } from "./helpers/it-auth.js";

const ADMIN_URL = process.env.PGGUARD_IT_DATABASE_URL;
const d = ADMIN_URL ? describe : describe.skip;
const repo = process.cwd();
const dbName = `pgguard_p5_${process.pid}_${Date.now()}`;

const parse = (r: { content: { text: string }[]; isError?: boolean }) => ({
  isError: Boolean(r.isError),
  body: JSON.parse(r.content[0]!.text),
});

d("phase 5 network + TLS + audit chain (live Postgres)", () => {
  let auditDir: string;
  let serverIp: string;
  let tls: { caPath: string; name: string } | null = null;

  function rawCreds(host: string, over: Partial<DbCredentials> = {}): DbCredentials {
    const u = new URL(ADMIN_URL!);
    return {
      host,
      port: Number(u.port || 5432),
      database: dbName,
      user: "app_reader",
      password: "reader_demo_pass",
      sslmode: "disable",
      ...over,
    };
  }

  function ctxWith(
    c: DbCredentials,
    opts: { hosts?: string[]; plaintextLoopbackOk?: boolean; lookup?: LookupFn; audit?: AuditLogger; schemaGuard?: boolean } = {},
  ): AppContext {
    const policy = resolveEffectivePolicy(loadPolicyConfig(path.join(repo, "config", "policy.yaml")), "reader");
    policy.principalPropagation = { ...policy.principalPropagation, require_jwt: false, enabled: false };
    if (opts.schemaGuard === false) {
      // pg_stat_ssl lives in pg_catalog, which the phase 3 guard (rightly) blocks.
      policy.allowedSchemas = null;
      policy.searchPath = null;
    }
    policy.network = {
      ...policy.network,
      allowedDbHosts: [...policy.network.allowedDbHosts, ...(opts.hosts ?? [])],
      plaintextLoopbackOk: opts.plaintextLoopbackOk ?? policy.network.plaintextLoopbackOk,
    };
    return {
      secrets: { getDbCredentials: async () => c },
      audit: opts.audit ?? new AuditLogger(auditDir, { hmacKey: null }),
      policy,
      lookup: opts.lookup,
    };
  }

  beforeAll(async () => {
    auditDir = fs.mkdtempSync(path.join(os.tmpdir(), "pgguard-p5-it-"));
    const u = new URL(ADMIN_URL!);
    serverIp = (await dns.promises.lookup(u.hostname, { family: 4 }).catch(() => dns.promises.lookup(u.hostname))).address;
    const admin = new pg.Client({ connectionString: ADMIN_URL });
    await admin.connect();
    await admin.query(`CREATE DATABASE ${dbName}`);
    const ssl = (await admin.query("SHOW ssl")).rows[0].ssl === "on";
    const certFile = (await admin.query("SHOW ssl_cert_file")).rows[0].ssl_cert_file as string;
    await admin.end();
    const caPath = process.env.PGGUARD_IT_TLS_CA || certFile;
    if (ssl && caPath && fs.existsSync(caPath)) {
      try {
        const cert = new X509Certificate(fs.readFileSync(caPath));
        const san = /DNS:([^,\s]+)/.exec(cert.subjectAltName ?? "")?.[1];
        const cn = /CN=([^\n,]+)/.exec(cert.subject)?.[1];
        const name = san || cn;
        if (name && !name.includes("*")) tls = { caPath, name };
      } catch {
        tls = null;
      }
    }
    u.pathname = `/${dbName}`;
    const db = new pg.Client({ connectionString: u.toString() });
    await db.connect();
    for (const f of PHASE2_SQL_FILES) await db.query(fs.readFileSync(path.join(repo, f), "utf8"));
    await db.end();
  }, 60_000);

  afterEach(async () => {
    await closePool();
  });

  afterAll(async () => {
    await closePool();
    const admin = new pg.Client({ connectionString: ADMIN_URL });
    await admin.connect();
    await admin.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
    await admin.end();
    fs.rmSync(auditDir, { recursive: true, force: true });
  }, 30_000);

  test("DNS pinning: a name only the injected resolver knows still connects (to the checked IP)", async () => {
    const lookups: string[] = [];
    const lookup: LookupFn = async (h) => {
      lookups.push(h);
      return [{ address: serverIp, family: serverIp.includes(":") ? 6 : 4 }];
    };
    // pgguard-db.invalid does not exist in real DNS: this only works because the
    // socket goes to the address PgGuard checked, not to a fresh lookup.
    const c = ctxWith(rawCreds("pgguard-db.invalid"), { hosts: ["pgguard-db.invalid"], lookup });
    const r = parse(await handleTool(c, "run_select", { sql: "SELECT current_user AS u, inet_server_addr()::text AS addr" }));
    expect(r.isError).toBe(false);
    expect(r.body.rows[0].u).toBe("app_reader");
    expect(lookups).toEqual(["pgguard-db.invalid"]);
    expect(c.network).toMatchObject({ host: "pgguard-db.invalid", connectHost: serverIp, loopbackOnly: true });
  });

  test("allowlist refuses a real, reachable server under a non-allowlisted name", async () => {
    const c = ctxWith(rawCreds("pgguard-other.invalid"), {
      lookup: async () => [{ address: serverIp, family: 4 }],
    });
    const r = parse(await handleTool(c, "db_health", {}));
    expect(r.isError).toBe(true);
    expect(r.body.error).toMatch(/not in network.allowed_db_hosts/);
  });

  test("plaintext to loopback is refused once plaintext_loopback_ok is off", async () => {
    const c = ctxWith(rawCreds("localhost"), { plaintextLoopbackOk: false });
    const r = parse(await handleTool(c, "db_health", {}));
    expect(r.isError).toBe(true);
    expect(r.body.error).toMatch(/requires sslmode=verify-full/);
  });

  describe("verify-full TLS", () => {
    test("TLS target found (required when PGGUARD_IT_REQUIRE_TLS=1, as in CI)", () => {
      if (process.env.PGGUARD_IT_REQUIRE_TLS === "1") expect(tls).not.toBeNull();
    });

    const t = () => {
      if (!tls) {
        // eslint-disable-next-line no-console
        console.warn("phase5 TLS tests skipped: server ssl off or certificate not readable (set PGGUARD_IT_TLS_CA)");
      }
      return tls;
    };
    const lookupTo = (): LookupFn => async () => [{ address: serverIp, family: 4 }];

    test("verify-full with the right CA + name connects over TLS through the pinned IP", async () => {
      const x = t();
      if (!x) return;
      const c = ctxWith(rawCreds(x.name, { sslmode: "verify-full", sslrootcert: x.caPath }), {
        hosts: [x.name],
        plaintextLoopbackOk: false,
        lookup: lookupTo(),
        schemaGuard: false,
      });
      const r = parse(await handleTool(c, "run_select", { sql: "SELECT ssl, version FROM pg_stat_ssl WHERE pid = pg_backend_pid()" }));
      expect(r.isError).toBe(false);
      expect(r.body.rows[0].ssl).toBe(true);
      expect(r.body.rows[0].version).toMatch(/^TLSv1\.[23]$/);
      expect(c.network).toMatchObject({ connectHost: serverIp, tlsServername: x.name.toLowerCase() });
      // Startup preflight also checks pg_stat_ssl when sslmode=verify-full.
      const pf = await runPreflight(await credsForPolicy(c), { tier: "reader", requireSsl: true });
      expect(pf.checks.find((k) => k.name === "ssl_in_use")).toMatchObject({ ok: true });
      expect(pf.ok).toBe(true);
    });

    test("certificate for another name is rejected (hostname check is on)", async () => {
      const x = t();
      if (!x) return;
      const c = ctxWith(rawCreds("pgguard-wrong-name.invalid", { sslmode: "verify-full", sslrootcert: x.caPath }), {
        hosts: ["pgguard-wrong-name.invalid"],
        plaintextLoopbackOk: false,
        lookup: lookupTo(),
      });
      const r = parse(await handleTool(c, "db_health", {}));
      expect(r.isError).toBe(true);
      expect(r.body.error).toMatch(/Hostname\/IP does not match certificate's altnames|ERR_TLS_CERT_ALTNAME_INVALID/);
    });

    test("a CA bundle that did not sign the server cert is rejected", async () => {
      const x = t();
      if (!x) return;
      // sslrootcert replaces the default trust store (as in libpq), so an unrelated
      // CA must fail even on hosts whose system store trusts the server cert.
      const c = ctxWith(rawCreds(x.name, { sslmode: "verify-full", sslrootcert: path.join(repo, "tests", "fixtures", "untrusted-ca.pem") }), {
        hosts: [x.name],
        plaintextLoopbackOk: false,
        lookup: lookupTo(),
      });
      const r = parse(await handleTool(c, "db_health", {}));
      expect(r.isError).toBe(true);
      expect(r.body.error).toMatch(/self[- ]signed|unable to verify|unable to get local issuer/i);
    });
  });

  test("preflight ssl_in_use fails for a plaintext session", async () => {
    const pf = await runPreflight(rawCreds(serverIp), { tier: "reader", requireSsl: true });
    expect(pf.checks.find((k) => k.name === "ssl_in_use")).toMatchObject({ ok: false });
    expect(pf.ok).toBe(false);
  });

  test("audit chain over real tool calls verifies, records the SQL hash, and catches an edit", async () => {
    const dir = fs.mkdtempSync(path.join(auditDir, "chain-"));
    const audit = new AuditLogger(dir, { hmacKey: null, verifyOnStart: true });
    const c = ctxWith(rawCreds("localhost"), { audit });
    const sql = "SELECT count(*)::int AS n FROM corp.employees";
    expect(parse(await handleTool(c, "run_select", { sql })).isError).toBe(false);
    expect(parse(await handleTool(c, "run_select", { sql: "DELETE FROM corp.employees" })).isError).toBe(true);
    expect(parse(await handleTool(c, "list_tables", { schema: "corp" })).isError).toBe(false);
    const file = path.join(dir, "events.jsonl");
    const v = verifyAuditFile(file);
    expect(v).toMatchObject({ ok: true, chained: 3, alg: "sha256" });
    const evs = fs.readFileSync(file, "utf8").trim().split("\n").map((l) => JSON.parse(l));
    expect(evs[0].sql_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(evs[1].ok).toBe(false);
    // Hide the refused DELETE.
    evs[1].ok = true;
    delete evs[1].error;
    fs.writeFileSync(file, evs.map((e) => JSON.stringify(e)).join("\n") + "\n");
    expect(verifyAuditFile(file).error).toEqual({ line: 2, reason: expect.stringMatching(/hash mismatch/) });
    expect(() => new AuditLogger(dir, { hmacKey: null, verifyOnStart: true })).toThrow(/failed verification at line 2/);
  });
});
