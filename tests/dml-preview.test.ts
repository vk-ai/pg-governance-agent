/**
 * Unit tests for the DML transaction wrapper (dry run + max_affected_rows) with
 * a fake pg client. Live behavior: tests/dml-preview.integration.test.ts.
 */
import type pg from "pg";
import { AffectedRowsCapExceeded, dmlTransactionOn } from "../src/db/pool.js";
import { resolveEffectivePolicy, validatePolicyFile } from "../src/policy/loader.js";
import { loadPolicyConfig } from "../src/policy/loader.js";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

type Call = { text: string; values?: unknown[]; queryMode?: string };

function fakeClient(rowCount: number, rows: Record<string, unknown>[] = [], failOn?: (t: string) => boolean) {
  const calls: Call[] = [];
  const released: unknown[] = [];
  const client = {
    query: async (q: string | { text: string; queryMode?: string }, values?: unknown[]) => {
      const call: Call = typeof q === "string" ? { text: q, values } : { text: q.text, queryMode: q.queryMode };
      calls.push(call);
      if (failOn?.(call.text)) throw new Error(`boom: ${call.text}`);
      if (/^(BEGIN|COMMIT|ROLLBACK)/.test(call.text) || call.text.startsWith("SELECT set_config")) {
        return { rows: [], rowCount: 0, command: call.text.split(" ")[0] };
      }
      return { rows, rowCount, command: "UPDATE" };
    },
    release: (e?: unknown) => released.push(e),
  } as unknown as pg.PoolClient;
  return { client, calls, released };
}

const texts = (calls: Call[]) => calls.map((c) => (c.values ? `${c.text} ${JSON.stringify(c.values)}` : c.text));

describe("dmlTransactionOn", () => {
  test("dry run: BEGIN → timeouts → GUCs → statement (extended) → ROLLBACK, never COMMIT", async () => {
    const { client, calls, released } = fakeClient(7, [{ id: 1 }, { id: 2 }, { id: 3 }]);
    const r = await dmlTransactionOn(async () => client, "UPDATE t SET a = 1 RETURNING id", {
      dryRun: true,
      maxAffectedRows: 5,
      sampleRows: 2,
      sessionGucs: { "app.user_id": "9" },
      timeouts: { statementTimeoutMs: 1000 },
    });
    expect(r).toMatchObject({ rowCount: 7, committed: false, dryRun: true, capExceeded: true, maxAffectedRows: 5 });
    expect(r.sample).toEqual([{ id: 1 }, { id: 2 }]);
    expect(texts(calls)).toEqual([
      "BEGIN",
      'SELECT set_config($1, $2, true) ["statement_timeout","1000"]',
      'SELECT set_config($1, $2, true) ["app.user_id","9"]',
      "UPDATE t SET a = 1 RETURNING id",
      "ROLLBACK",
    ]);
    expect(calls[3]!.queryMode).toBe("extended");
    expect(released).toEqual([undefined]);
  });

  test("real run under the cap commits", async () => {
    const { client, calls } = fakeClient(3);
    const r = await dmlTransactionOn(async () => client, "DELETE FROM t WHERE a = 1", { maxAffectedRows: 3 });
    expect(r).toMatchObject({ rowCount: 3, committed: true, capExceeded: false });
    expect(texts(calls).at(-1)).toBe("COMMIT");
  });

  test("real run over the cap rolls back and throws", async () => {
    const { client, calls } = fakeClient(4);
    await expect(
      dmlTransactionOn(async () => client, "DELETE FROM t", { maxAffectedRows: 3 }),
    ).rejects.toBeInstanceOf(AffectedRowsCapExceeded);
    expect(texts(calls)).toEqual(["BEGIN", "DELETE FROM t", "ROLLBACK"]);
  });

  test("statement error rolls back once and releases the client", async () => {
    const { client, calls, released } = fakeClient(1, [], (t) => t.startsWith("UPDATE"));
    await expect(dmlTransactionOn(async () => client, "UPDATE t SET a = 1")).rejects.toThrow("boom");
    expect(texts(calls)).toEqual(["BEGIN", "UPDATE t SET a = 1", "ROLLBACK"]);
    expect(released).toEqual([undefined]);
  });

  test("failed ROLLBACK destroys the connection instead of returning it to the pool", async () => {
    const { client, released } = fakeClient(10, [], (t) => t === "ROLLBACK");
    await dmlTransactionOn(async () => client, "UPDATE t SET a = 1", { dryRun: true });
    expect(released[0]).toBeInstanceOf(Error);
  });

  test("cap 0 blocks every real write that touches a row", async () => {
    const { client } = fakeClient(1);
    await expect(dmlTransactionOn(async () => client, "UPDATE t SET a=1", { maxAffectedRows: 0 })).rejects.toThrow(
      /over the max_affected_rows cap of 0/,
    );
  });
});

describe("max_affected_rows policy", () => {
  const cfgPath = path.join(process.cwd(), "config", "policy.yaml");

  test("role overrides default; writer is capped tighter than admin", () => {
    const cfg = loadPolicyConfig(cfgPath);
    expect(resolveEffectivePolicy(cfg, "writer").maxAffectedRows).toBe(50);
    expect(resolveEffectivePolicy(cfg, "admin").maxAffectedRows).toBe(10000);
    delete cfg.roles.writer!.max_affected_rows;
    expect(resolveEffectivePolicy(cfg, "writer").maxAffectedRows).toBe(cfg.defaults.max_affected_rows);
  });

  test("policy check rejects a negative cap", () => {
    const bad = fs.readFileSync(cfgPath, "utf8").replace("max_affected_rows: 50", "max_affected_rows: -1");
    const p = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "pgguard-pol-")), "policy.yaml");
    fs.writeFileSync(p, bad);
    const r = validatePolicyFile(p);
    expect(r.ok).toBe(false);
    expect(r.errors.join(" ")).toMatch(/max_affected_rows/);
  });
});
