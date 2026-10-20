import { AuditLogger } from "../audit/logger.js";
import { createSecretsProvider, type SecretsProvider, type DbCredentials } from "../secrets/index.js";
import {
  loadPolicyConfig,
  resolveEffectivePolicy,
  type EffectivePolicy,
} from "../policy/index.js";
import type { PreflightResult } from "../db/preflight.js";
import { createApprovalRuntime, type ApprovalRuntime } from "../approvals/gate.js";

export interface AppContext {
  secrets: SecretsProvider;
  audit: AuditLogger;
  policy: EffectivePolicy;
  /** Result of startup DB preflight (role hardens, timeouts, no FDW). */
  preflight?: PreflightResult;
  /** Phase 4 approval gate (public key, ledger, request queue). Built lazily from policy.approvals. */
  approvals?: ApprovalRuntime;
}

export function approvalRuntime(ctx: AppContext): ApprovalRuntime {
  if (!ctx.approvals) ctx.approvals = createApprovalRuntime(ctx.policy.approvals);
  return ctx.approvals;
}

export function createAppContext(): AppContext {
  const config = loadPolicyConfig();
  const policy = resolveEffectivePolicy(config);
  return {
    secrets: createSecretsProvider(),
    audit: new AuditLogger(),
    policy,
  };
}

export async function credsForPolicy(ctx: AppContext): Promise<DbCredentials> {
  return ctx.secrets.getDbCredentials(ctx.policy.role.db_user);
}
