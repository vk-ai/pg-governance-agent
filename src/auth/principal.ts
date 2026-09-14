/**
 * Principal propagation: map an end-user JWT to Postgres session GUCs for RLS.
 *
 * User-submitted SQL still cannot SET ROLE / SET SESSION AUTHORIZATION (blocked
 * by the classifier). Only PgGuard's connection wrapper applies allowlisted
 * set_config(...) calls so policies can use current_setting('app.user_id').
 */
import { createHmac, timingSafeEqual } from "node:crypto";

export interface Principal {
  sub: string;
  email?: string;
  claims: Record<string, unknown>;
}

export interface PrincipalPropagationConfig {
  enabled: boolean;
  /** Env var holding HS256 secret. Empty/missing → verify disabled unless require_jwt. */
  jwt_secret_env: string;
  /** When true, DB tools fail if no valid bearer token is provided. */
  require_jwt: boolean;
  claim_sub: string;
  claim_email: string;
  /** Map claim keys → Postgres GUC names (e.g. sub → app.user_id). */
  session_gucs: Record<string, string>;
}

export const DEFAULT_PRINCIPAL_PROPAGATION: PrincipalPropagationConfig = {
  enabled: true,
  jwt_secret_env: "PGGUARD_JWT_SECRET",
  require_jwt: false,
  claim_sub: "sub",
  claim_email: "email",
  session_gucs: {
    sub: "app.user_id",
    email: "app.user_email",
  },
};

export class PrincipalError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PrincipalError";
  }
}

function b64urlToBuffer(input: string): Buffer {
  return Buffer.from(input, "base64url");
}

function parseJsonObject(raw: string): Record<string, unknown> {
  const v = JSON.parse(raw) as unknown;
  if (!v || typeof v !== "object" || Array.isArray(v)) {
    throw new PrincipalError("JWT payload must be an object");
  }
  return v as Record<string, unknown>;
}

/** Decode JWT payload without verifying (tests / trusted gateways only). */
export function decodeJwtPayload(token: string): Record<string, unknown> {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new PrincipalError("JWT must have three base64url parts");
  }
  try {
    return parseJsonObject(b64urlToBuffer(parts[1]!).toString("utf8"));
  } catch (e) {
    if (e instanceof PrincipalError) throw e;
    throw new PrincipalError("Invalid JWT payload encoding");
  }
}

/**
 * Verify HS256 JWT and return a Principal.
 * Checks `exp` when present.
 */
export function verifyHs256Jwt(token: string, secret: string): Principal {
  if (!secret) {
    throw new PrincipalError("JWT secret is empty");
  }
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new PrincipalError("JWT must have three base64url parts");
  }
  const [headerB64, payloadB64, sigB64] = parts as [string, string, string];
  const header = parseJsonObject(b64urlToBuffer(headerB64).toString("utf8"));
  if (header.alg !== "HS256") {
    throw new PrincipalError(`Unsupported JWT alg: ${String(header.alg)}`);
  }
  const data = `${headerB64}.${payloadB64}`;
  const expected = createHmac("sha256", secret).update(data).digest();
  const actual = b64urlToBuffer(sigB64);
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
    throw new PrincipalError("JWT signature mismatch");
  }
  const payload = parseJsonObject(b64urlToBuffer(payloadB64).toString("utf8"));
  if (typeof payload.exp === "number" && payload.exp * 1000 < Date.now()) {
    throw new PrincipalError("JWT expired");
  }
  return principalFromClaims(payload);
}

export function principalFromClaims(
  claims: Record<string, unknown>,
  cfg: Pick<PrincipalPropagationConfig, "claim_sub" | "claim_email"> = DEFAULT_PRINCIPAL_PROPAGATION,
): Principal {
  const subRaw = claims[cfg.claim_sub];
  if (subRaw === undefined || subRaw === null || String(subRaw).trim() === "") {
    throw new PrincipalError(`JWT missing required claim '${cfg.claim_sub}'`);
  }
  const emailRaw = claims[cfg.claim_email];
  return {
    sub: String(subRaw),
    email: emailRaw === undefined || emailRaw === null ? undefined : String(emailRaw),
    claims,
  };
}

/** Build GUC name→value map for set_config (transaction-local). */
export function gucsForPrincipal(
  principal: Principal,
  cfg: PrincipalPropagationConfig = DEFAULT_PRINCIPAL_PROPAGATION,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [claimKey, guc] of Object.entries(cfg.session_gucs || {})) {
    if (!guc || !/^[a-zA-Z_][a-zA-Z0-9_.]*$/.test(guc)) {
      throw new PrincipalError(`Invalid session GUC name: ${guc}`);
    }
    let value: unknown;
    if (claimKey === "sub") value = principal.sub;
    else if (claimKey === "email") value = principal.email;
    else value = principal.claims[claimKey];
    if (value === undefined || value === null) continue;
    out[guc] = String(value);
  }
  return out;
}

export function resolveBearerToken(args: Record<string, unknown>): string | undefined {
  const fromArgs = args.bearer_token;
  if (typeof fromArgs === "string" && fromArgs.trim()) return fromArgs.trim();
  const env = process.env.PGGUARD_BEARER_TOKEN;
  if (env && env.trim()) return env.trim();
  return undefined;
}

export function resolvePrincipal(
  args: Record<string, unknown>,
  cfg: PrincipalPropagationConfig,
): Principal | null {
  if (!cfg.enabled) return null;
  const token = resolveBearerToken(args);
  if (!token) {
    if (cfg.require_jwt) {
      throw new PrincipalError("bearer_token (or PGGUARD_BEARER_TOKEN) is required");
    }
    return null;
  }
  const secret = process.env[cfg.jwt_secret_env] || "";
  if (secret) {
    return verifyHs256Jwt(token, secret);
  }
  // No secret configured: decode only (dev / trusted mesh). Production should set the secret.
  return principalFromClaims(decodeJwtPayload(token), cfg);
}
