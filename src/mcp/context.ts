import { AuditLogger } from "../audit/logger.js";
import { createSecretsProvider, type SecretsProvider, type DbCredentials } from "../secrets/index.js";
import {
  loadPolicyConfig,
  resolveEffectivePolicy,
  type EffectivePolicy,
} from "../policy/index.js";
import type { PreflightResult } from "../db/preflight.js";
import { createApprovalRuntime, type ApprovalRuntime } from "../approvals/gate.js";
import { NETWORK_OFF, enforceNetworkPolicy, type LookupFn, type NetworkDecision } from "../net/allowlist.js";

export interface AppContext {
  secrets: SecretsProvider;
  audit: AuditLogger;
  policy: EffectivePolicy;
  /** Result of startup DB preflight (role hardens, timeouts, no FDW). */
  preflight?: PreflightResult;
  /** Phase 4 approval gate (public key, ledger, request queue). Built lazily from policy.approvals. */
  approvals?: ApprovalRuntime;
  /** Phase 5: last network allowlist decision (whoami). */
  network?: NetworkDecision | null;
  /** Phase 5: DNS resolver override (tests). */
  lookup?: LookupFn;
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
    audit: new AuditLogger(undefined, {
      hashChain: policy.audit.hashChain,
      hmacKeyEnv: policy.audit.hmacKeyEnv,
      verifyOnStart: policy.audit.verifyOnStart,
    }),
    policy,
  };
}

/**
 * Credentials for the role's DB user, checked against the phase 5 network
 * policy. The returned host is the verified (pinned) address; throws before
 * any socket is opened when the host, an address or the sslmode is refused.
 */
export async function credsForPolicy(ctx: AppContext): Promise<DbCredentials> {
  const raw = await ctx.secrets.getDbCredentials(ctx.policy.role.db_user);
  const { creds, decision } = await enforceNetworkPolicy(raw, ctx.policy.network ?? NETWORK_OFF, ctx.lookup);
  ctx.network = decision;
  return creds;
}
