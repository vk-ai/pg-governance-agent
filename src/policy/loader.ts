import fs from "node:fs";
import path from "node:path";
import YAML from "yaml";
import type { Capability, PolicyConfig, RolePolicy } from "./types.js";
import {
  DEFAULT_PRINCIPAL_PROPAGATION,
  type PrincipalPropagationConfig,
} from "../auth/principal.js";
import type { ReadTxnOptions } from "../db/pool.js";
import { log } from "../utils/logger.js";
import { SCHEMA_IDENT_RE } from "./schemaGuard.js";

/** Defaults used when policy.yaml does not set read-transaction timeouts. */
export const DEFAULT_READ_TXN: Required<ReadTxnOptions> = {
  statementTimeoutMs: 15_000,
  lockTimeoutMs: 2_000,
  idleInTransactionSessionTimeoutMs: 30_000,
};

/** Result caps used when policy.yaml does not set them. */
export const DEFAULT_MAX_RESULT_BYTES = 1_048_576; // 1 MiB
export const DEFAULT_MAX_CELL_BYTES = 65_536; // 64 KiB

export type AgentRoleName = "reader" | "writer" | "migrator" | "admin" | string;

export interface EffectivePolicy {
  roleName: AgentRoleName;
  role: RolePolicy;
  config: PolicyConfig;
  maxRows: number;
  maxAffectedRows: number;
  requireConfirmDml: boolean;
  requireConfirmDdl: boolean;
  allowExplainAnalyze: boolean;
  dualControlDdl: boolean;
  principalPropagation: PrincipalPropagationConfig;
  /** SET LOCAL timeouts for read tools (run inside BEGIN READ ONLY). */
  readTxn: Required<ReadTxnOptions>;
  /** Schema allowlist; null = guard off (no allowed_schemas in policy). */
  allowedSchemas: string[] | null;
  /** search_path set in every transaction when the guard is on (subset of allowedSchemas). */
  searchPath: string[] | null;
  /** Result byte budget for run_select / explain_query (compact JSON). */
  maxResultBytes: number;
  /** Per-cell byte cap; longer values are truncated and reported. */
  maxCellBytes: number;
}

function positiveInt(v: unknown, fallback: number): number {
  const n = Number(v);
  return Number.isInteger(n) && n > 0 ? n : fallback;
}

/**
 * Resolve allowed_schemas / search_path for a role. Throws on invalid names or
 * a search_path that would let unqualified names resolve outside the allowlist.
 */
export function resolveSchemaPolicy(
  role: RolePolicy,
  d: PolicyConfig["defaults"],
  roleName = "?",
): { allowedSchemas: string[] | null; searchPath: string[] | null } {
  const allowed = role.allowed_schemas ?? d.allowed_schemas;
  if (allowed === undefined || allowed === null) return { allowedSchemas: null, searchPath: null };
  if (!Array.isArray(allowed)) throw new Error(`Role ${roleName}: allowed_schemas must be a list`);
  for (const s of allowed) {
    if (typeof s !== "string" || !SCHEMA_IDENT_RE.test(s)) {
      throw new Error(`Role ${roleName}: invalid schema name in allowed_schemas: ${String(s)}`);
    }
  }
  const sp = role.search_path ?? d.search_path ?? allowed.filter((s) => s !== "pg_catalog" && s !== "information_schema");
  if (!Array.isArray(sp)) throw new Error(`Role ${roleName}: search_path must be a list`);
  for (const s of sp) {
    if (typeof s !== "string" || !SCHEMA_IDENT_RE.test(s)) {
      throw new Error(`Role ${roleName}: invalid schema name in search_path: ${String(s)}`);
    }
    if (!allowed.includes(s)) {
      throw new Error(`Role ${roleName}: search_path schema '${s}' is not in allowed_schemas`);
    }
  }
  return { allowedSchemas: [...allowed], searchPath: [...sp] };
}

export function loadPolicyConfig(policyPath?: string): PolicyConfig {
  const p =
    policyPath ||
    process.env.PGGUARD_POLICY_PATH ||
    path.join(process.cwd(), "config", "policy.yaml");
  const raw = fs.readFileSync(p, "utf8");
  const cfg = YAML.parse(raw) as PolicyConfig;
  if (!cfg?.roles || typeof cfg.roles !== "object") {
    throw new Error(`Invalid policy file: ${p}`);
  }
  return cfg;
}

export function resolveEffectivePolicy(
  config: PolicyConfig,
  roleName?: string,
): EffectivePolicy {
  const name = (roleName || process.env.PGGUARD_ROLE || "reader").toLowerCase();
  const role = config.roles[name];
  if (!role) {
    throw new Error(`Unknown PGGUARD_ROLE: ${name}. Known: ${Object.keys(config.roles).join(", ")}`);
  }
  const d = config.defaults;
  const pp = config.principal_propagation || {};
  const principalPropagation: PrincipalPropagationConfig = {
    ...DEFAULT_PRINCIPAL_PROPAGATION,
    ...pp,
    session_gucs: {
      ...DEFAULT_PRINCIPAL_PROPAGATION.session_gucs,
      ...(pp.session_gucs || {}),
    },
    enabled: pp.enabled ?? DEFAULT_PRINCIPAL_PROPAGATION.enabled,
  };
  const schemaPolicy = resolveSchemaPolicy(role, d, name);
  return {
    roleName: name,
    role,
    config,
    maxRows: role.max_rows ?? d.max_rows ?? 100,
    maxAffectedRows: role.max_affected_rows ?? d.max_affected_rows ?? 100,
    requireConfirmDml: role.require_confirm_dml ?? d.require_confirm_dml ?? true,
    requireConfirmDdl: role.require_confirm_ddl ?? d.require_confirm_ddl ?? true,
    allowExplainAnalyze: role.allow_explain_analyze ?? d.allow_explain_analyze ?? false,
    dualControlDdl: role.dual_control_ddl ?? false,
    principalPropagation,
    readTxn: {
      statementTimeoutMs:
        role.statement_timeout_ms ?? d.statement_timeout_ms ?? DEFAULT_READ_TXN.statementTimeoutMs,
      lockTimeoutMs: role.lock_timeout_ms ?? d.lock_timeout_ms ?? DEFAULT_READ_TXN.lockTimeoutMs,
      idleInTransactionSessionTimeoutMs:
        role.idle_in_transaction_session_timeout_ms ??
        d.idle_in_transaction_session_timeout_ms ??
        DEFAULT_READ_TXN.idleInTransactionSessionTimeoutMs,
    },
    allowedSchemas: schemaPolicy.allowedSchemas,
    searchPath: schemaPolicy.searchPath,
    maxResultBytes: positiveInt(role.max_result_bytes ?? d.max_result_bytes, DEFAULT_MAX_RESULT_BYTES),
    maxCellBytes: positiveInt(role.max_cell_bytes ?? d.max_cell_bytes, DEFAULT_MAX_CELL_BYTES),
  };
}

export function hasCapability(eff: EffectivePolicy, cap: Capability): boolean {
  if (eff.role.deny?.includes(cap)) return false;
  return eff.role.allow?.includes(cap) ?? false;
}

export function assertCapability(eff: EffectivePolicy, cap: Capability): void {
  if (!hasCapability(eff, cap)) {
    throw new Error(`Role '${eff.roleName}' is not allowed to perform '${cap}'`);
  }
}

export function validatePolicyFile(policyPath?: string): { ok: boolean; errors: string[] } {
  const errors: string[] = [];
  try {
    const cfg = loadPolicyConfig(policyPath);
    const requiredCaps: Capability[] = [
      "health",
      "introspect",
      "select",
      "dml",
      "ddl",
      "explain",
      "audit_read",
      "whoami",
    ];
    for (const [name, role] of Object.entries(cfg.roles)) {
      if (!role.db_user) errors.push(`Role ${name}: missing db_user`);
      if (!Array.isArray(role.allow)) errors.push(`Role ${name}: allow must be array`);
      if (role.max_affected_rows !== undefined && !(Number.isInteger(role.max_affected_rows) && role.max_affected_rows >= 0)) {
        errors.push(`Role ${name}: max_affected_rows must be a non-negative integer`);
      }
      for (const k of ["max_result_bytes", "max_cell_bytes"] as const) {
        const v = role[k];
        if (v !== undefined && !(Number.isInteger(v) && v > 0)) errors.push(`Role ${name}: ${k} must be a positive integer`);
      }
      try {
        resolveSchemaPolicy(role, cfg.defaults || ({} as PolicyConfig["defaults"]), name);
      } catch (e) {
        errors.push(e instanceof Error ? e.message : String(e));
      }
      for (const a of role.allow || []) {
        if (!requiredCaps.includes(a as Capability) && !["health","introspect","select","dml","ddl","explain","audit_read","whoami"].includes(a)) {
          // soft warn only
          log("warn", "unknown_capability", { role: name, capability: a });
        }
      }
    }
    if (!cfg.roles.reader) errors.push("Missing required role: reader");
  } catch (e) {
    errors.push(e instanceof Error ? e.message : String(e));
  }
  return { ok: errors.length === 0, errors };
}
