/** Offline Phase 1 bypass cases: AST/lexer function checks, row cap, TLS modes. */
import { classifySql } from "../src/policy/classifier.js";
import { lexFunctionNames } from "../src/policy/sqlscan.js";
import { effectiveMaxRows } from "../src/db/queries.js";
import { buildConnectionConfig, sslConfigFor } from "../src/db/pool.js";

const blocked = (sql: string) => {
  const r = classifySql(sql);
  return r.ok ? null : r.reason ?? "blocked";
};

describe("dangerous functions are caught by AST + quote-aware lexer", () => {
  test.each([
    ["set_config WHERE trick", "SELECT * FROM corp.orders WHERE set_config('app.user_id','2',true) IS NOT NULL", "set_config"],
    ["quoted set_config", `SELECT "set_config"('app.user_id','2',true)`, "set_config"],
    ["mixed case + schema", "SELECT pg_catalog.SeT_CoNfIg('a','b',true)", "set_config"],
    ["quoted schema + name", `SELECT "pg_catalog"."set_config"('a','b',true)`, "set_config"],
    ["quoted dblink", `SELECT * FROM "dblink"('host=evil', 'select 1') AS t(x int)`, "dblink"],
    ["dblink_connect", "SELECT dblink_connect('c', 'host=evil')", "dblink_connect"],
    ["dblink_open", "SELECT dblink_open('c', 'select 1')", "dblink_open"],
    ["dblink_exec in CTE", "WITH x AS (SELECT dblink_exec('c','DROP TABLE t')) SELECT * FROM x", "dblink_exec"],
    ["comment between name and paren", "SELECT dblink/* hi */('x','y')", "dblink"],
    ["postgres_fdw function", "SELECT postgres_fdw_disconnect_all()", "postgres_fdw"],
    ["any fdw handler", "SELECT file_fdw_handler()", "fdw"],
    ["pg_terminate_backend", "SELECT pg_terminate_backend(pid) FROM pg_stat_activity", "pg_terminate_backend"],
    ["pg_cancel_backend in subquery", "SELECT * FROM (SELECT pg_cancel_backend(1)) s", "pg_cancel_backend"],
    ["advisory lock", "SELECT pg_advisory_lock(1)", "pg_advisory_lock"],
    ["try advisory xact shared", "SELECT pg_try_advisory_xact_lock_shared(1)", "pg_try_advisory"],
    ["pg_sleep", "SELECT pg_sleep(100)", "pg_sleep"],
    ["pg_sleep_for in WHERE", "SELECT 1 WHERE pg_sleep_for('1 hour') IS NULL", "pg_sleep_for"],
    ["unparseable SQL still lexed", "SELECT xmlserialize(DOCUMENT set_config('a','b',true) AS text) ::: weird", "set_config"],
    ["explain hides call", "EXPLAIN SELECT set_config('app.user_id','2',true)", "set_config"],
  ])("%s", (_label, sql, needle) => {
    const reason = blocked(sql);
    expect(reason).not.toBeNull();
    expect(reason!.toLowerCase()).toContain(needle);
  });

  test("policy.yaml extras still apply", () => {
    expect(classifySql("SELECT my_custom_fn()", ["my_custom_fn"]).ok).toBe(false);
  });

  test("FDW / server / extension DDL and U& escapes are blocked", () => {
    expect(blocked("CREATE FOREIGN TABLE x (a int) SERVER s")).not.toBeNull();
    expect(blocked("CREATE SERVER s FOREIGN DATA WRAPPER postgres_fdw")).not.toBeNull();
    expect(blocked("CREATE EXTENSION dblink")).not.toBeNull();
    expect(blocked(`SELECT U&"d\\0062link"('a','b')`)).not.toBeNull();
  });

  test("names inside strings, comments and dollar quotes are not function calls", () => {
    expect(lexFunctionNames("SELECT 'set_config(' AS a -- dblink(\n /* pg_sleep( */")).toEqual([]);
    expect(lexFunctionNames("SELECT $q$ pg_sleep(1) $q$, E'it''s dblink(' ")).toEqual([]);
    expect(classifySql("SELECT note FROM corp.orders WHERE note = 'call set_config(x)'").ok).toBe(true);
  });

  test("ordinary queries still pass", () => {
    for (const sql of [
      "SELECT count(*), max(amount_cents) FROM corp.orders",
      "SELECT current_setting('app.user_id', true)",
      "WITH a AS (SELECT lower(name) n FROM corp.orgs) SELECT * FROM a",
      `SELECT "name" FROM "corp"."orgs"`,
    ]) {
      expect(classifySql(sql).ok).toBe(true);
    }
  });
});

describe("row cap is min(arg, policy)", () => {
  test.each([
    [undefined, 100, 100],
    [1e9, 100, 100],
    [5, 100, 5],
    ["7", 100, 7],
    [-1, 100, 100],
    ["abc", 100, 100],
    [Infinity, 100, 100],
  ])("requested %p, policy %p → %p", (req, pol, want) => {
    expect(effectiveMaxRows(req, pol)).toBe(want);
  });
});

describe("TLS sslmode mapping", () => {
  test("verify-ca validates the chain (was rejectUnauthorized:false)", () => {
    const ssl = sslConfigFor("verify-ca") as { rejectUnauthorized: boolean; checkServerIdentity: () => unknown };
    expect(ssl.rejectUnauthorized).toBe(true);
    expect(ssl.checkServerIdentity()).toBeUndefined(); // hostname not checked, as in libpq
  });
  test("verify-full validates chain and hostname", () => {
    expect(sslConfigFor("verify-full")).toEqual({ rejectUnauthorized: true });
  });
  test("require encrypts without verification; disable → no TLS; unknown refused", () => {
    expect(sslConfigFor("require")).toEqual({ rejectUnauthorized: false });
    expect(sslConfigFor("disable")).toBeUndefined();
    expect(sslConfigFor(undefined)).toBeUndefined();
    expect(() => sslConfigFor("verify-maybe")).toThrow(/Unsupported/);
  });
  test("buildConnectionConfig uses it", () => {
    const c = buildConnectionConfig({ host: "h", port: 5432, database: "d", user: "u", password: "p", sslmode: "verify-ca" });
    expect((c.ssl as { rejectUnauthorized: boolean }).rejectUnauthorized).toBe(true);
  });
});
