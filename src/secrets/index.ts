import type { SecretsProvider } from "./types.js";
import { EnvSecretsProvider } from "./env.js";
import { VaultSecretsProvider } from "./vault.js";
import { log } from "../utils/logger.js";

export type { DbCredentials, SecretsProvider } from "./types.js";
export { EnvSecretsProvider } from "./env.js";
export { VaultSecretsProvider } from "./vault.js";

export function createSecretsProvider(): SecretsProvider {
  const kind = (process.env.PGGUARD_SECRETS_PROVIDER || "env").toLowerCase();
  if (kind === "vault") {
    log("info", "secrets_provider", { provider: "vault" });
    return new VaultSecretsProvider();
  }
  log("info", "secrets_provider", { provider: "env" });
  return new EnvSecretsProvider();
}
