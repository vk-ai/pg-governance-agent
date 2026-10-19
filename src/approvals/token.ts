/**
 * Phase 4: out-of-band approvals.
 *
 * An approval is an Ed25519-signed token minted by a human with the approvals
 * CLI (src/approvals/cli.ts). The MCP server only holds the PUBLIC key, so the
 * agent — or anything that can drive the server's tools — cannot mint one.
 *
 * A token is bound to: the exact SQL text (sha256), the tool, the PgGuard role,
 * the DB user and database, and the end-user principal (JWT sub). It expires
 * (exp, capped by policy max_ttl_seconds) and carries a random jti that the
 * ledger accepts once (single use).
 *
 * Format: "pga1.<base64url(JSON claims)>.<base64url(ed25519 signature)>",
 * where the signature covers the ASCII bytes "pga1.<base64url(JSON claims)>".
 */
import { createHash, createPrivateKey, createPublicKey, randomBytes, sign, verify, type KeyObject } from "node:crypto";

export const TOKEN_PREFIX = "pga1";

export type ApprovalTool = "run_dml" | "run_ddl";

/** What the server checks a token against (derived from the live call, never from the token). */
export interface ApprovalScope {
  tool: ApprovalTool;
  role: string;
  db_user: string;
  database: string;
  /** End-user principal (JWT sub); null when the call has no principal. */
  sub: string | null;
  sql_sha256: string;
}

export interface ApprovalClaims extends ApprovalScope {
  v: 1;
  /** Single-use id (random, 128-bit hex). */
  jti: string;
  /** Approval request id this answers (informational). */
  rid: string;
  /** Who approved (self-declared by the key holder; recorded in audit). */
  approver: string;
  /** Issued-at / expiry, Unix seconds. */
  iat: number;
  exp: number;
  /** Optional tighter row cap the approver accepted (min()'d with the policy cap). */
  max_affected_rows?: number;
}

export type ApprovalErrorCode =
  | "missing"
  | "not_configured"
  | "malformed"
  | "bad_signature"
  | "expired"
  | "not_yet_valid"
  | "ttl_too_long"
  | "sql_mismatch"
  | "scope_mismatch"
  | "self_approval"
  | "replayed"
  | "pending"
  | "denied";

export class ApprovalError extends Error {
  constructor(
    public readonly code: ApprovalErrorCode,
    message: string,
  ) {
    super(`Approval rejected (${code}): ${message}`);
    this.name = "ApprovalError";
  }
}

/** sha256 hex of the SQL exactly as submitted (no trimming or normalisation). */
export function sqlSha256(sql: string): string {
  return createHash("sha256").update(sql, "utf8").digest("hex");
}

export function newJti(): string {
  return randomBytes(16).toString("hex");
}

export function loadPrivateKey(pem: string): KeyObject {
  const k = createPrivateKey(pem);
  if (k.asymmetricKeyType !== "ed25519") throw new Error("Approval signing key must be Ed25519");
  return k;
}

export function loadPublicKey(pem: string): KeyObject {
  const k = createPublicKey(pem);
  if (k.asymmetricKeyType !== "ed25519") throw new Error("Approval public key must be Ed25519");
  return k;
}

export function signApproval(claims: ApprovalClaims, privateKey: KeyObject): string {
  const body = `${TOKEN_PREFIX}.${Buffer.from(JSON.stringify(claims), "utf8").toString("base64url")}`;
  const sig = sign(null, Buffer.from(body, "ascii"), privateKey).toString("base64url");
  return `${body}.${sig}`;
}

export interface VerifyOptions {
  publicKey: KeyObject;
  /** Unix seconds; injectable for tests. */
  now?: number;
  maxTtlSeconds: number;
  clockSkewSeconds?: number;
}

const HEX64 = /^[0-9a-f]{64}$/;
const HEX32 = /^[0-9a-f]{32}$/;

function decodeClaims(token: string): { body: string; sig: Buffer; claims: ApprovalClaims } {
  if (typeof token !== "string" || token.length > 8192) throw new ApprovalError("malformed", "token is not a string");
  const parts = token.trim().split(".");
  if (parts.length !== 3 || parts[0] !== TOKEN_PREFIX) {
    throw new ApprovalError("malformed", `expected ${TOKEN_PREFIX}.<claims>.<signature>`);
  }
  let claims: ApprovalClaims;
  try {
    claims = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8")) as ApprovalClaims;
  } catch {
    throw new ApprovalError("malformed", "claims are not valid base64url JSON");
  }
  if (!claims || typeof claims !== "object" || Array.isArray(claims)) {
    throw new ApprovalError("malformed", "claims must be an object");
  }
  return { body: `${parts[0]}.${parts[1]}`, sig: Buffer.from(parts[2]!, "base64url"), claims };
}

function checkShape(c: ApprovalClaims): void {
  const bad = (f: string) => {
    throw new ApprovalError("malformed", `claim '${f}' missing or invalid`);
  };
  if (c.v !== 1) bad("v");
  if (typeof c.jti !== "string" || !HEX32.test(c.jti)) bad("jti");
  if (typeof c.rid !== "string" || c.rid.length === 0 || c.rid.length > 128) bad("rid");
  if (c.tool !== "run_dml" && c.tool !== "run_ddl") bad("tool");
  for (const f of ["role", "db_user", "database", "approver"] as const) {
    if (typeof c[f] !== "string" || c[f].length === 0 || c[f].length > 256) bad(f);
  }
  if (c.sub !== null && (typeof c.sub !== "string" || c.sub.length > 256)) bad("sub");
  if (typeof c.sql_sha256 !== "string" || !HEX64.test(c.sql_sha256)) bad("sql_sha256");
  if (!Number.isInteger(c.iat)) bad("iat");
  if (!Number.isInteger(c.exp)) bad("exp");
  if (c.max_affected_rows !== undefined && !(Number.isInteger(c.max_affected_rows) && c.max_affected_rows >= 0)) {
    bad("max_affected_rows");
  }
}

/**
 * Verify signature, shape, lifetime and binding. Does NOT consume the token;
 * callers must pass the claims to an {@link ApprovalLedger} before executing.
 * Signature is checked first so unsigned input never reaches the other checks.
 */
export function verifyApproval(token: string, expected: ApprovalScope, opts: VerifyOptions): ApprovalClaims {
  const { body, sig, claims } = decodeClaims(token);
  let sigOk = false;
  try {
    sigOk = verify(null, Buffer.from(body, "ascii"), opts.publicKey, sig);
  } catch {
    sigOk = false;
  }
  if (!sigOk) throw new ApprovalError("bad_signature", "signature does not verify with the configured public key");
  checkShape(claims);

  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const skew = Math.max(0, opts.clockSkewSeconds ?? 30);
  if (claims.exp <= claims.iat) throw new ApprovalError("malformed", "exp must be after iat");
  if (claims.exp - claims.iat > opts.maxTtlSeconds) {
    throw new ApprovalError("ttl_too_long", `lifetime ${claims.exp - claims.iat}s exceeds max_ttl_seconds ${opts.maxTtlSeconds}`);
  }
  if (claims.iat > now + skew) throw new ApprovalError("not_yet_valid", "iat is in the future");
  // No grace on expiry: skew only tolerates an approver clock slightly ahead (iat).
  if (now >= claims.exp) throw new ApprovalError("expired", `expired at ${new Date(claims.exp * 1000).toISOString()}`);

  if (claims.sql_sha256 !== expected.sql_sha256) {
    throw new ApprovalError("sql_mismatch", "token was approved for different SQL text (any byte change, including whitespace, needs a new approval)");
  }
  for (const f of ["tool", "role", "db_user", "database", "sub"] as const) {
    if ((claims[f] ?? null) !== (expected[f] ?? null)) {
      throw new ApprovalError("scope_mismatch", `token ${f}=${JSON.stringify(claims[f])} but call has ${f}=${JSON.stringify(expected[f])}`);
    }
  }
  if (expected.sub !== null && claims.approver === expected.sub) {
    throw new ApprovalError("self_approval", "approver must not be the requesting principal");
  }
  return claims;
}
