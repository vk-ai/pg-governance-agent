/**
 * Unit tests for the read-only transaction wrapper using a fake pg client.
 * They pin the SQL order (BEGIN READ ONLY → timeouts → principal GUCs → query
 * → ROLLBACK). Live-Postgres behavior is covered by
 * tests/read-txn.integration.test.ts (runs when PGGUARD_IT_DATABASE_URL is set).
 */
import type pg from "pg";
import {
  readOnlyTransactionOn,
  clientOn,
  applyLocalTimeouts,
} from "../src/db/pool.js";
import { runUserSql } from "../src/db/queries.js";
import { resolveEffectivePolicy, DEFAULT_READ_TXN } from "../src/policy/loader.js";
import type { PolicyConfig } from "../src/policy/types.js";

type Call = { text: string; values?: unknown[]; queryMode?: string };

function fakeClient(opts: { failOn?: (text: string) => boolean } = {}) {
  const calls: Call[] = [];
  const released: (Error | boolean | undefined)[] = [];
  const client = {
    query: async (textOrCfg: string | { text: string; queryMode?: string }, values?: unknown[]) => {
      const call: Call =
        typeof textOrCfg === "string"
          ? { text: textOrCfg, values }
          : { text: textOrCfg.text, queryMode: textOrCfg.queryMode };
      calls.push(call);
      if (opts.failOn?.(call.text)) throw new Error(`boom: ${call.text}`);
      return { rows: [{ ok: 1 }], rowCount: 1, command: "SELECT" };
    },
    release: (err?: Error | boolean) => {
      released.push(err);
    },
  } as unknown as pg.PoolClient;
  return { client, calls, released };
}

const summarize = (calls: Call[]) =>
  calls.map((c) => (c.values ? `${c.text} ${JSON.stringify(c.values)}` : c.text));

describe("readOnlyTransactionOn", () => {
  test("BEGIN READ ONLY → SET LOCAL timeouts → principal GUCs → query → ROLLBACK", async () => {
    const { client, calls, released } = fakeClient();
    const rows = await readOnlyTransactionOn(
      async () => client,
      async (c) => (await c.query("SELECT current_setting('app.user_id', true)")).rows,
      {
        sessionGucs: { "app.user_id": "42", "app.user_email": "a@example.com" },
        timeouts: { statementTimeoutMs: 1500, lockTimeoutMs: 200, idleInTransactionSessionTimeoutMs: 0 },
      },
    );
    expect(rows).toEqual([{ ok: 1 }]);
    expect(summarize(calls)).toEqual([
      "BEGIN READ ONLY",
      'SELECT set_config($1, $2, true) ["statement_timeout","1500"]',
      'SELECT set_config($1, $2, true) ["lock_timeout","200"]',
      'SELECT set_config($1, $2, true) ["idle_in_transaction_session_timeout","0"]',
      'SELECT set_config($1, $2, true) ["app.user_id","42"]',
      'SELECT set_config($1, $2, true) ["app.user_email","a@example.com"]',
      "SELECT current_setting('app.user_id', true)",
      "ROLLBACK",
    ]);
    expect(released).toEqual([undefined]);
  });

  test("always rolls back and releases when the query fails", async () => {
    const { client, calls, released } = fakeClient({ failOn: (t) => t.startsWith("INSERT") });
    await expect(
      readOnlyTransactionOn(async () => client, (c) => c.query("INSERT INTO t VALUES (1)")),
    ).rejects.toThrow("boom: INSERT");
    expect(calls.map((c) => c.text)).toEqual(["BEGIN READ ONLY", "INSERT INTO t VALUES (1)", "ROLLBACK"]);
    expect(released).toEqual([undefined]);
  });

  test("destroys the connection when ROLLBACK fails", async () => {
    const { client, released } = fakeClient({ failOn: (t) => t === "ROLLBACK" });
    await readOnlyTransactionOn(async () => client, async () => "ok");
    expect(released).toHaveLength(1);
    expect(released[0]).toBeInstanceOf(Error);
  });

  test("rejects invalid GUC names before running the user query", async () => {
    const { client, calls } = fakeClient();
    await expect(
      readOnlyTransactionOn(async () => client, (c) => c.query("SELECT 1"), {
        sessionGucs: { "bad name; drop": "x" },
      }),
    ).rejects.toThrow("Refusing invalid GUC name");
    expect(calls.map((c) => c.text)).toEqual(["BEGIN READ ONLY", "ROLLBACK"]);
  });
});

describe("clientOn (write paths)", () => {
  test("no GUCs: autocommit, no transaction wrapper", async () => {
    const { client, calls } = fakeClient();
    await clientOn(async () => client, (c) => c.query("CREATE INDEX CONCURRENTLY i ON t(a)"));
    expect(calls.map((c) => c.text)).toEqual(["CREATE INDEX CONCURRENTLY i ON t(a)"]);
  });

  test("with GUCs: set inside BEGIN … COMMIT so RLS sees the principal", async () => {
    const { client, calls } = fakeClient();
    await clientOn(async () => client, (c) => c.query("UPDATE t SET a = 1"), {
      sessionGucs: { "app.user_id": "7" },
    });
    expect(summarize(calls)).toEqual([
      "BEGIN",
      'SELECT set_config($1, $2, true) ["app.user_id","7"]',
      "UPDATE t SET a = 1",
      "COMMIT",
    ]);
  });

  test("with GUCs: rolls back on failure", async () => {
    const { client, calls } = fakeClient({ failOn: (t) => t.startsWith("UPDATE") });
    await expect(
      clientOn(async () => client, (c) => c.query("UPDATE t SET a = 1"), {
        sessionGucs: { "app.user_id": "7" },
      }),
    ).rejects.toThrow();
    expect(calls.map((c) => c.text)).toEqual([
      "BEGIN",
      "SELECT set_config($1, $2, true)",
      "UPDATE t SET a = 1",
      "ROLLBACK",
    ]);
  });
});

describe("timeouts and user SQL", () => {
  test("applyLocalTimeouts skips undefined and rejects negatives", async () => {
    const { client, calls } = fakeClient();
    await applyLocalTimeouts(client, { statementTimeoutMs: 100 });
    expect(calls).toHaveLength(1);
    await expect(applyLocalTimeouts(client, { lockTimeoutMs: -1 })).rejects.toThrow("invalid timeout");
  });

  test("runUserSql uses the extended query protocol", async () => {
    const { client, calls } = fakeClient();
    await runUserSql(client, "SELECT 1");
    expect(calls[0]).toEqual({ text: "SELECT 1", queryMode: "extended" });
  });

  test("policy resolves read-transaction timeouts with role > defaults > built-in", () => {
    const base: PolicyConfig = {
      version: 1,
      defaults: {
        max_rows: 100,
        require_confirm_dml: true,
        require_confirm_ddl: true,
        allow_explain_analyze: false,
        audit_retention_days: 90,
        lock_timeout_ms: 500,
      },
      blocked_patterns: [],
      dangerous_functions: [],
      roles: {
        reader: {
          description: "r",
          db_user: "app_reader",
          allow: ["select"],
          deny: [],
          statement_timeout_ms: 3000,
        },
      },
    };
    const eff = resolveEffectivePolicy(base, "reader");
    expect(eff.readTxn).toEqual({
      statementTimeoutMs: 3000,
      lockTimeoutMs: 500,
      idleInTransactionSessionTimeoutMs: DEFAULT_READ_TXN.idleInTransactionSessionTimeoutMs,
    });
  });
});
