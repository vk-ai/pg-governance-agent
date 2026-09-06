import { AuditLogger } from "../audit/logger.js";
import { createSecretsProvider, type SecretsProvider, type DbCredentials } from "../secrets/index.js";
import {
  loadPolicyConfig,
  resolveEffectivePolicy,
  type EffectivePolicy,
} from "../policy/index.js";

export interface AppContext {
  secrets: SecretsProvider;
  audit: AuditLogger;
  policy: EffectivePolicy;
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
