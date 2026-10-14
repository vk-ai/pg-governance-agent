/**
 * Startup / whoami checks that the connected DB role is a safe agent principal.
 * Fail closed: any failed check refuses to start (or returns ok:false for whoami).
 *
 * DB-native settings from docker/postgres/init/04-agent-roles.sql (and
 * scripts/provision-roles.sql) are the primary guarantee; this verifies they
 * are present before the MCP server accepts tool calls.
 */
import pg from "pg";
import type { DbCredentials } from "../secrets/types.js";
import { buildConnectionConfig } from "./pool.js";

const { Pool } = pg;

export type AgentTier = "reader" | "writer";

export interface PreflightCheck {
  name: string;
  ok: boolean;
  detail: string;
}

export interface PreflightResult {
  ok: boolean;
  db_user: string;
  tier: AgentTier;
  checks: PreflightCheck[];
  /** Human-readable summary of the first failure (if any). */
  error?: string;
}

export interface PreflightOptions {
  /** Expected tier: reader requires default_transaction_read_only=on. */
  tier: AgentTier;
  /** Optional injectable client factory (tests). */
  connect?: () => Promise<{
    query: pg.PoolClient["query"];
    end?: () => Promise<void>;
    release?: (err?: Error | boolean) => void;
  }>;
}

const FORBIDDEN_EXTENSIONS = ["dblink", "postgres_fdw"];

function parseTimeoutMs(raw: string): number {
  const s = (raw || "").trim().toLowerCase();
  if (!s || s === "0" || s === "0s" || s === "0ms") return 0;
  const m = /^(\d+(?:\.\d+)?)\s*(ms|s|min|us)?$/.exec(s);
  if (!m) return -1;
  const n = Number(m[1]);
  const unit = m[2] || "ms";
  if (unit === "ms") return n;
  if (unit === "s") return n * 1000;
  if (unit === "min") return n * 60_000;
  if (unit === "us") return n / 1000;
  return -1;
}

/**
 * Infer agent tier from effective policy capabilities.
 * Reader = no DML/DDL. Writer/migrator/admin = writable tier.
 */
export function tierFromAllow(allow: string[]): AgentTier {
  if (allow.includes("dml") || allow.includes("ddl")) return "writer";
  return "reader";
}

export async function runPreflight(
  creds: DbCredentials,
  opts: PreflightOptions,
): Promise<PreflightResult> {
  const checks: PreflightCheck[] = [];
  let client: {
    query: pg.PoolClient["query"];
    end?: () => Promise<void>;
    release?: (err?: Error | boolean) => void;
  };
  let pool: pg.Pool | null = null;

  if (opts.connect) {
    client = await opts.connect();
  } else {
    pool = new Pool({ ...buildConnectionConfig(creds), max: 1 });
    client = await pool.connect();
  }

  try {
    const roleR = await client.query<{
      usename: string;
      rolsuper: boolean;
      rolbypassrls: boolean;
      rolconfig: string[] | null;
    }>(
      `SELECT current_user AS usename,
              r.rolsuper,
              r.rolbypassrls,
              r.rolconfig
         FROM pg_roles r
        WHERE r.rolname = current_user`,
    );
    const row = roleR.rows[0];
    if (!row) {
      checks.push({ name: "role_exists", ok: false, detail: "current_user not found in pg_roles" });
    } else {
      checks.push({
        name: "not_superuser",
        ok: !row.rolsuper,
        detail: row.rolsuper ? "connected role is a superuser" : "ok",
      });
      checks.push({
        name: "no_bypassrls",
        ok: !row.rolbypassrls,
        detail: row.rolbypassrls ? "connected role has BYPASSRLS" : "ok",
      });
    }

    const settings = await client.query<{ name: string; setting: string }>(
      `SELECT name, setting FROM pg_settings
        WHERE name IN (
          'default_transaction_read_only',
          'statement_timeout'
        )`,
    );
    const byName = Object.fromEntries(settings.rows.map((r) => [r.name, r.setting]));

    const dro = (byName.default_transaction_read_only || "").toLowerCase();
    const droOn = dro === "on" || dro === "true" || dro === "1";
    if (opts.tier === "reader") {
      checks.push({
        name: "default_transaction_read_only",
        ok: droOn,
        detail: droOn
          ? "on (reader tier)"
          : `expected on for reader tier, got ${byName.default_transaction_read_only ?? "(unset)"}`,
      });
    } else {
      checks.push({
        name: "default_transaction_read_only",
        ok: !droOn,
        detail: !droOn
          ? "off (writable tier)"
          : "writable tier unexpectedly has default_transaction_read_only=on",
      });
    }

    const timeoutMs = parseTimeoutMs(byName.statement_timeout ?? "0");
    checks.push({
      name: "statement_timeout",
      ok: timeoutMs > 0,
      detail:
        timeoutMs > 0
          ? `${byName.statement_timeout} (${timeoutMs}ms)`
          : `statement_timeout must be > 0 (got ${byName.statement_timeout ?? "(unset)"})`,
    });

    const ext = await client.query<{ extname: string }>(
      `SELECT extname FROM pg_extension WHERE extname = ANY($1::text[])`,
      [FORBIDDEN_EXTENSIONS],
    );
    const found = ext.rows.map((r) => r.extname);
    checks.push({
      name: "no_forbidden_extensions",
      ok: found.length === 0,
      detail:
        found.length === 0
          ? "dblink/postgres_fdw not installed"
          : `forbidden extensions present: ${found.join(", ")}`,
    });

    const ok = checks.every((c) => c.ok);
    const firstFail = checks.find((c) => !c.ok);
    return {
      ok,
      db_user: creds.user,
      tier: opts.tier,
      checks,
      error: firstFail
        ? `preflight failed: ${firstFail.name} — ${firstFail.detail}`
        : undefined,
    };
  } finally {
    if (client.release) client.release();
    else if (client.end) await client.end().catch(() => undefined);
    if (pool) await pool.end().catch(() => undefined);
  }
}

/** Throw if preflight is not ok (startup fail-closed). */
export async function assertPreflight(
  creds: DbCredentials,
  opts: PreflightOptions,
): Promise<PreflightResult> {
  const result = await runPreflight(creds, opts);
  if (!result.ok) {
    throw new Error(result.error || "preflight failed");
  }
  return result;
}
