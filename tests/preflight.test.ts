/** Offline unit tests for DB preflight checks. */
import { runPreflight, tierFromAllow, type PreflightOptions } from "../src/db/preflight.js";
import type { DbCredentials } from "../src/secrets/types.js";

const creds: DbCredentials = {
  host: "127.0.0.1",
  port: 5432,
  database: "corpdb",
  user: "app_reader",
  password: "x",
  sslmode: "disable",
};

type Row = Record<string, unknown>;

function mockConnect(responses: Row[][]) {
  let i = 0;
  return async () => ({
    query: async () => {
      const rows = responses[i++] ?? [];
      return { rows };
    },
    end: async () => undefined,
  });
}

describe("tierFromAllow", () => {
  test("reader when no dml/ddl", () => {
    expect(tierFromAllow(["health", "select", "whoami"])).toBe("reader");
  });
  test("writer when dml or ddl present", () => {
    expect(tierFromAllow(["select", "dml"])).toBe("writer");
    expect(tierFromAllow(["ddl"])).toBe("writer");
  });
});

describe("runPreflight (mocked)", () => {
  const roleOk = {
    usename: "app_reader",
    rolsuper: false,
    rolbypassrls: false,
    rolconfig: ["statement_timeout=15s"],
  };
  const settingsReader = [
    { name: "default_transaction_read_only", setting: "on" },
    { name: "statement_timeout", setting: "15s" },
  ];
  const settingsWriter = [
    { name: "default_transaction_read_only", setting: "off" },
    { name: "statement_timeout", setting: "15s" },
  ];

  test("passes for a hardened reader role", async () => {
    const r = await runPreflight(creds, {
      tier: "reader",
      connect: mockConnect([[roleOk], settingsReader, []]) as PreflightOptions["connect"],
    });
    expect(r.ok).toBe(true);
    expect(r.checks.every((c) => c.ok)).toBe(true);
  });

  test("rejects superuser", async () => {
    const r = await runPreflight(creds, {
      tier: "reader",
      connect: mockConnect([
        [{ ...roleOk, rolsuper: true, usename: "postgres" }],
        settingsReader,
        [],
      ]) as PreflightOptions["connect"],
    });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/not_superuser/);
  });

  test("rejects BYPASSRLS", async () => {
    const r = await runPreflight(creds, {
      tier: "reader",
      connect: mockConnect([
        [{ ...roleOk, rolbypassrls: true }],
        settingsReader,
        [],
      ]) as PreflightOptions["connect"],
    });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/no_bypassrls/);
  });

  test("rejects reader without default_transaction_read_only", async () => {
    const r = await runPreflight(creds, {
      tier: "reader",
      connect: mockConnect([[roleOk], settingsWriter, []]) as PreflightOptions["connect"],
    });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/default_transaction_read_only/);
  });

  test("rejects statement_timeout = 0", async () => {
    const r = await runPreflight(creds, {
      tier: "reader",
      connect: mockConnect([
        [roleOk],
        [
          { name: "default_transaction_read_only", setting: "on" },
          { name: "statement_timeout", setting: "0" },
        ],
        [],
      ]) as PreflightOptions["connect"],
    });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/statement_timeout/);
  });

  test("rejects dblink / postgres_fdw extensions", async () => {
    const r = await runPreflight(creds, {
      tier: "reader",
      connect: mockConnect([
        [roleOk],
        settingsReader,
        [{ extname: "dblink" }, { extname: "postgres_fdw" }],
      ]) as PreflightOptions["connect"],
    });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/no_forbidden_extensions/);
    expect(r.checks.find((c) => c.name === "no_forbidden_extensions")!.detail).toMatch(/dblink/);
  });

  test("writable tier expects read_only off", async () => {
    const r = await runPreflight(
      { ...creds, user: "app_writer" },
      {
        tier: "writer",
        connect: mockConnect([
          [{ ...roleOk, usename: "app_writer" }],
          settingsWriter,
          [],
        ]) as PreflightOptions["connect"],
      },
    );
    expect(r.ok).toBe(true);
  });
});
