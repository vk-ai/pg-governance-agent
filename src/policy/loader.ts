import fs from "node:fs";
import path from "node:path";
import YAML from "yaml";
import type { Capability, PolicyConfig, RolePolicy } from "./types.js";
import { log } from "../utils/logger.js";

export type AgentRoleName = "reader" | "writer" | "migrator" | "admin" | string;

export interface EffectivePolicy {
  roleName: AgentRoleName;
  role: RolePolicy;
  config: PolicyConfig;
  maxRows: number;
  requireConfirmDml: boolean;
  requireConfirmDdl: boolean;
  allowExplainAnalyze: boolean;
  dualControlDdl: boolean;
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
  return {
    roleName: name,
    role,
    config,
    maxRows: role.max_rows ?? d.max_rows ?? 100,
    requireConfirmDml: role.require_confirm_dml ?? d.require_confirm_dml ?? true,
    requireConfirmDdl: role.require_confirm_ddl ?? d.require_confirm_ddl ?? true,
    allowExplainAnalyze: role.allow_explain_analyze ?? d.allow_explain_analyze ?? false,
    dualControlDdl: role.dual_control_ddl ?? false,
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
