/**
 * Offline tests for phase 3 (plan phase 2): schema allowlist guard and
 * row/byte/cell result caps. No database needed.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type pg from "pg";
import {
  checkSchemas,
  filterSchemas,
  isSchemaAllowed,
  searchPathValue,
  stripExplain,
} from "../src/policy/schemaGuard.js";
import {
  loadPolicyConfig,
  resolveEffectivePolicy,
  resolveSchemaPolicy,
  validatePolicyFile,
  DEFAULT_MAX_CELL_BYTES,
} from "../src/policy/loader.js";
import { capRows, fetchCapped, truncateUtf8 } from "../src/db/queries.js";
import { handleTool } from "../src/mcp/tools.js";
import type { AppContext } from "../src/mcp/context.js";
import { AuditLogger } from "../src/audit/logger.js";

const ALLOWED = ["corp"];

describe("schemaGuard.checkSchemas", () => {
  const allow: [string, string][] = [
    ["qualified allowed table", "SELECT * FROM corp.orgs"],
    ["unqualified table (resolves via search_path)", "SELECT * FROM orgs o JOIN employees e ON e.org_id = o.id"],
    ["CTE name", "WITH x AS (SELECT id FROM corp.orgs) SELECT * FROM x"],
    ["pg_catalog function", "SELECT pg_catalog.now(), version(), count(*) FROM corp.orders"],
    ["unqualified pg_* function is not a relation", "SELECT pg_size_pretty(1024::bigint)"],
    ["generate_series", "SELECT g FROM generate_series(1, 3) g"],
    ["schema.table.column ref", "SELECT corp.orgs.id FROM corp.orgs"],
    ["VALUES", "VALUES (1), (2)"],
    ["DML target in allowed schema", "UPDATE corp.orders SET status = 'paid' WHERE id = 1"],
    ["pg_catalog type cast", "SELECT 1::pg_catalog.int4"],
    ["upper-case unquoted folds to lower", "SELECT * FROM CORP.ORGS"],
  ];
  test.each(allow)("allows: %s", (_label, sql) => {
    const r = checkSchemas(sql, ALLOWED);
    expect(r.reason).toBeUndefined();
    expect(r.ok).toBe(true);
  });

  const deny: [string, string, RegExp][] = [
    ["qualified non-allowed table", "SELECT * FROM hr.salaries", /'hr' is not allowed/],
    ["non-allowed schema in subquery", "SELECT * FROM corp.orgs WHERE id IN (SELECT org_id FROM hr.t)", /'hr'/],
    ["non-allowed schema in CTE body", "WITH x AS (SELECT * FROM hr.salaries) SELECT * FROM x", /'hr'/],
    ["UNION branch", "SELECT id FROM corp.orgs UNION SELECT id FROM hr.t", /'hr'/],
    ["LATERAL", "SELECT * FROM corp.orgs o, LATERAL (SELECT * FROM hr.t WHERE t.a = o.id) z", /'hr'/],
    ["quoted schema is case-sensitive", 'SELECT * FROM "Corp".orgs', /'Corp'/],
    ["pg_catalog relation qualified", "SELECT * FROM pg_catalog.pg_authid", /'pg_catalog'/],
    ["unqualified pg_* relation", "SELECT rolname FROM pg_authid", /resolves to pg_catalog/],
    ["unqualified pg_* in subquery", "SELECT (SELECT count(*) FROM pg_stat_activity) FROM corp.orgs", /pg_catalog/],
    ["information_schema", "SELECT * FROM information_schema.tables", /'information_schema'/],
    ["function in non-allowed schema", "SELECT hr.raise_salary(1)", /'hr'/],
    ["table function in non-allowed schema", "SELECT * FROM hr.fn() f", /'hr'/],
    ["type in non-allowed schema", "SELECT 1::hr.money_t", /'hr'/],
    ["schema.table.column ref elsewhere", "SELECT hr.t.a FROM t", /'hr'/],
    ["INSERT target", "INSERT INTO hr.t (a) SELECT id FROM corp.orgs", /'hr'/],
    ["UPDATE target", "UPDATE hr.t SET a = 1", /'hr'/],
    ["DDL target", "CREATE TABLE hr.t2 (a int)", /'hr'/],
    ["DROP list", "DROP TABLE corp.x, hr.t", /'hr'/],
    ["view over other schema", "CREATE VIEW corp.v AS SELECT * FROM hr.t", /'hr'/],
    ["SQL-in-string: query_to_xml", "SELECT query_to_xml('select * from hr.salaries', true, false, '')", /query_to_xml/],
    ["SQL-in-string: table_to_xml", "SELECT table_to_xml('hr.salaries', true, false, '')", /table_to_xml/],
    ["SQL-in-string: ts_stat", "SELECT * FROM ts_stat('select v from hr.docs')", /ts_stat/],
    ["unparseable SQL fails closed", "TABLE hr.t", /could not parse/],
    ["three-part name fails closed", "SELECT * FROM db.hr.t", /could not parse/],
  ];
  test.each(deny)("denies: %s", (_label, sql, re) => {
    const r = checkSchemas(sql, ALLOWED);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(re);
  });

  test("guard off (null allowlist) allows anything", () => {
    expect(checkSchemas("SELECT * FROM hr.salaries", null).ok).toBe(true);
    expect(checkSchemas("not even sql", null).ok).toBe(true);
  });

  test("pg_catalog / information_schema only when listed", () => {
    expect(checkSchemas("SELECT * FROM pg_authid", ["corp", "pg_catalog"]).ok).toBe(true);
    expect(checkSchemas("SELECT * FROM information_schema.tables", ["corp", "information_schema"]).ok).toBe(true);
  });

  test("empty allowlist denies every qualified relation", () => {
    expect(checkSchemas("SELECT * FROM corp.orgs", []).ok).toBe(false);
    expect(checkSchemas("SELECT 1", []).ok).toBe(true);
  });

  test("reports relations it saw", () => {
    const r = checkSchemas("SELECT * FROM corp.orgs o JOIN employees e ON true", ALLOWED);
    expect(r.relations).toEqual([
      { schema: "corp", name: "orgs" },
      { schema: null, name: "employees" },
    ]);
  });
});

describe("schemaGuard helpers", () => {
  test("isSchemaAllowed / filterSchemas", () => {
    expect(isSchemaAllowed("hr", null)).toBe(true);
    expect(isSchemaAllowed("hr", ALLOWED)).toBe(false);
    expect(isSchemaAllowed("corp", ALLOWED)).toBe(true);
    expect(filterSchemas(["corp", "hr", "public"], ALLOWED, (s) => s)).toEqual(["corp"]);
    expect(filterSchemas(["corp", "hr"], null, (s) => s)).toEqual(["corp", "hr"]);
  });

  test("stripExplain", () => {
    expect(stripExplain("EXPLAIN SELECT * FROM hr.t")).toBe("SELECT * FROM hr.t");
    expect(stripExplain("explain (analyze, buffers) select 1")).toBe("select 1");
    expect(stripExplain("EXPLAIN ANALYZE VERBOSE SELECT 1")).toBe("SELECT 1");
    expect(stripExplain("SELECT 1")).toBe("SELECT 1");
  });

  test("searchPathValue quotes and validates", () => {
    expect(searchPathValue(["corp", "sales"])).toBe('"corp", "sales"');
    expect(searchPathValue([])).toBe("");
    expect(() => searchPathValue(['corp", public --'])).toThrow(/invalid schema/);
  });
});

describe("policy: allowed_schemas / search_path / byte caps", () => {
  const cfg = loadPolicyConfig(path.join(process.cwd(), "config", "policy.yaml"));

  test("shipped policy: every role allowlists corp and has byte caps", () => {
    for (const role of ["reader", "writer", "migrator", "admin"]) {
      const eff = resolveEffectivePolicy(cfg, role);
      expect(eff.allowedSchemas).toEqual(["corp"]);
      expect(eff.searchPath).toEqual(["corp"]);
      expect(eff.maxResultBytes).toBeGreaterThan(0);
      expect(eff.maxCellBytes).toBe(DEFAULT_MAX_CELL_BYTES);
    }
    expect(resolveEffectivePolicy(cfg, "reader").maxResultBytes).toBe(524288);
    expect(validatePolicyFile(path.join(process.cwd(), "config", "policy.yaml"))).toEqual({ ok: true, errors: [] });
  });

  test("no allowed_schemas anywhere = guard off", () => {
    const d = { ...cfg.defaults, allowed_schemas: undefined };
    expect(resolveSchemaPolicy({ ...cfg.roles.reader!, allowed_schemas: undefined }, d)).toEqual({
      allowedSchemas: null,
      searchPath: null,
    });
  });

  test("search_path outside allowed_schemas is rejected", () => {
    expect(() =>
      resolveSchemaPolicy({ ...cfg.roles.reader!, allowed_schemas: ["corp"], search_path: ["corp", "public"] }, cfg.defaults, "reader"),
    ).toThrow(/search_path schema 'public' is not in allowed_schemas/);
  });

  test("search_path defaults to allowed_schemas minus system schemas", () => {
    expect(
      resolveSchemaPolicy({ ...cfg.roles.reader!, allowed_schemas: ["corp", "pg_catalog", "sales"] }, cfg.defaults).searchPath,
    ).toEqual(["corp", "sales"]);
  });

  test("invalid schema names are rejected", () => {
    expect(() => resolveSchemaPolicy({ ...cfg.roles.reader!, allowed_schemas: ["Corp"] }, cfg.defaults)).toThrow(/invalid schema/);
  });

  test("validatePolicyFile flags bad caps and bad search_path", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pgguard-pol-"));
    const p = path.join(dir, "policy.yaml");
    const raw = fs.readFileSync(path.join(process.cwd(), "config", "policy.yaml"), "utf8").replace(
      "    allowed_schemas: [corp]\n    max_result_bytes: 524288",
      "    allowed_schemas: [corp]\n    search_path: [public]\n    max_result_bytes: -5",
    );
    fs.writeFileSync(p, raw);
    const v = validatePolicyFile(p);
    expect(v.ok).toBe(false);
    expect(v.errors.join("\n")).toMatch(/max_result_bytes must be a positive integer/);
    expect(v.errors.join("\n")).toMatch(/search_path schema 'public'/);
    fs.rmSync(dir, { recursive: true, force: true });
  });
});

describe("result caps (in memory)", () => {
  const caps = { maxRows: 3, maxResultBytes: 10_000, maxCellBytes: 8 };

  test("truncateUtf8 never splits a code point", () => {
    expect(truncateUtf8("abcdef", 3)).toBe("abc");
    expect(truncateUtf8("ééé", 3)).toBe("é"); // é is 2 bytes
    expect(truncateUtf8("😀x", 3)).toBe("");
    expect(truncateUtf8("short", 100)).toBe("short");
  });

  test("row cap", () => {
    const r = capRows([{ a: 1 }, { a: 2 }, { a: 3 }, { a: 4 }], caps);
    expect(r.rowCount).toBe(3);
    expect(r.truncated).toBe(true);
    expect(r.truncatedBy).toEqual(["rows"]);
  });

  test("exactly max_rows is not truncated", () => {
    const r = capRows([{ a: 1 }, { a: 2 }, { a: 3 }], caps);
    expect(r.truncated).toBe(false);
    expect(r.resultBytes).toBe(Buffer.byteLength(JSON.stringify(r.rows)));
  });

  test("cell cap on text, bytea and json", () => {
    const r = capRows(
      [{ t: "0123456789abc", b: Buffer.from("0123456789"), j: { k: "0123456789" }, n: 42, d: new Date(0) }],
      caps,
    );
    const row = r.rows[0]!;
    expect(row.t).toBe("01234567");
    expect(row.b).toBe("\\x" + Buffer.from("01234567").toString("hex"));
    expect(typeof row.j).toBe("string");
    expect(Buffer.byteLength(String(row.j))).toBeLessThanOrEqual(8);
    expect(row.n).toBe(42);
    expect(r.truncatedBy).toEqual(["cells"]);
    expect(r.truncatedCells).toBe(3);
    expect(r.truncatedColumns.sort()).toEqual(["b", "j", "t"]);
  });

  test("byte budget stops before the row that would exceed it", () => {
    const rows = Array.from({ length: 50 }, (_, i) => ({ i, s: "x".repeat(100) }));
    const r = capRows(rows, { maxRows: 1000, maxResultBytes: 1000, maxCellBytes: 1000 });
    expect(r.truncatedBy).toEqual(["bytes"]);
    expect(r.resultBytes).toBeLessThanOrEqual(1000);
    expect(Buffer.byteLength(JSON.stringify(r.rows))).toBe(r.resultBytes);
    expect(r.rowCount).toBeGreaterThan(0);
    expect(r.rowCount).toBeLessThan(50);
  });
});

describe("fetchCapped (mock client)", () => {
  function mockClient(totalRows: number) {
    const calls: string[] = [];
    let served = 0;
    const client = {
      query: async (q: string | { text: string }) => {
        const text = typeof q === "string" ? q : q.text;
        calls.push(text);
        const m = /^FETCH FORWARD (\d+)/.exec(text);
        if (m) {
          const k = Number(m[1]);
          const n = Math.min(k, totalRows - served);
          const rows = Array.from({ length: n }, (_, i) => ({ g: served + i + 1 }));
          served += n;
          return { rows };
        }
        return { rows: [] };
      },
    } as unknown as pg.PoolClient;
    return { client, calls };
  }

  test("DECLARE cursor, FETCH max_rows+1 in batches, CLOSE", async () => {
    const { client, calls } = mockClient(1_000_000);
    const r = await fetchCapped(client, "SELECT g FROM t;", { maxRows: 120, maxResultBytes: 1e9, maxCellBytes: 100 }, 50);
    expect(calls[0]).toBe("DECLARE pgguard_result NO SCROLL CURSOR WITHOUT HOLD FOR SELECT g FROM t");
    expect(calls.slice(1, -1)).toEqual([
      "FETCH FORWARD 50 FROM pgguard_result",
      "FETCH FORWARD 50 FROM pgguard_result",
      "FETCH FORWARD 21 FROM pgguard_result",
    ]);
    expect(calls[calls.length - 1]).toBe("CLOSE pgguard_result");
    expect(r.rowCount).toBe(120);
    expect(r.truncated).toBe(true);
    expect(r.truncatedBy).toEqual(["rows"]);
  });

  test("short result: stops when the cursor is drained, not truncated", async () => {
    const { client, calls } = mockClient(7);
    const r = await fetchCapped(client, "SELECT 1", { maxRows: 100, maxResultBytes: 1e9, maxCellBytes: 100 }, 50);
    expect(r.rowCount).toBe(7);
    expect(r.truncated).toBe(false);
    expect(calls.filter((c) => c.startsWith("FETCH"))).toHaveLength(1);
  });

  test("byte budget stops fetching early", async () => {
    const { client, calls } = mockClient(1_000_000);
    const r = await fetchCapped(client, "SELECT 1", { maxRows: 100_000, maxResultBytes: 500, maxCellBytes: 100 }, 50);
    expect(r.truncatedBy).toEqual(["bytes"]);
    expect(r.resultBytes).toBeLessThanOrEqual(500);
    // ~9 bytes per row: stops in the second batch instead of reading 100k rows.
    expect(calls.filter((c) => c.startsWith("FETCH")).length).toBeLessThanOrEqual(2);
  });
});

describe("tools: schema guard runs before any DB access", () => {
  const cfg = loadPolicyConfig(path.join(process.cwd(), "config", "policy.yaml"));
  const auditDir = fs.mkdtempSync(path.join(os.tmpdir(), "pgguard-sg-"));
  afterAll(() => fs.rmSync(auditDir, { recursive: true, force: true }));

  function ctx(role = "reader"): AppContext {
    const policy = resolveEffectivePolicy(cfg, role);
    policy.principalPropagation = { ...policy.principalPropagation, require_jwt: false };
    return {
      secrets: {
        getDbCredentials: async () => {
          throw new Error("DB must not be reached");
        },
      },
      audit: new AuditLogger(auditDir),
      policy,
    };
  }
  const parse = (r: { content: { text: string }[]; isError?: boolean }) => ({ isError: Boolean(r.isError), body: JSON.parse(r.content[0]!.text) });

  test.each([
    ["run_select", { sql: "SELECT * FROM hr.salaries" }, "reader"],
    ["explain_query", { sql: "EXPLAIN SELECT * FROM hr.salaries" }, "reader"],
    ["list_tables", { schema: "hr" }, "reader"],
    ["describe_table", { schema: "hr", table: "salaries" }, "reader"],
    ["run_dml", { sql: "DELETE FROM hr.salaries WHERE id = 1", dry_run: true }, "writer"],
    ["run_ddl", { sql: "DROP TABLE hr.salaries", confirm: true }, "migrator"],
  ] as [string, Record<string, unknown>, string][])("%s denies schema hr", async (tool, args, role) => {
    const r = parse(await handleTool(ctx(role), tool, args));
    expect(r.isError).toBe(true);
    expect(r.body.error).toMatch(/'hr'.* is not allowed/);
  });

  test("whoami reports allowlist and caps", async () => {
    const r = parse(await handleTool(ctx(), "whoami", {}));
    expect(r.body.allowed_schemas).toEqual(["corp"]);
    expect(r.body.search_path).toEqual(["corp"]);
    expect(r.body.max_result_bytes).toBe(524288);
    expect(r.body.max_cell_bytes).toBe(65536);
  });
});
