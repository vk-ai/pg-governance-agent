/**
 * Server-side approval gate used by run_dml / run_ddl (phase 4).
 */
import fs from "node:fs";
import path from "node:path";
import type { KeyObject } from "node:crypto";
import type { ApprovalPolicy } from "../policy/loader.js";
import type { ApprovalKind } from "../policy/types.js";
import { FileLedger, PgLedger, type ApprovalLedger } from "./ledger.js";
import { RequestQueue } from "./requests.js";
import { ApprovalError, loadPublicKey, verifyApproval, type ApprovalClaims, type ApprovalScope } from "./token.js";

export interface ApprovalRuntime {
  policy: ApprovalPolicy;
  /** null when no key is configured (real runs then fail closed if approvals are required). */
  publicKey: KeyObject | null;
  ledger: ApprovalLedger;
  queue: RequestQueue;
}

/** Read the approver public key from `<env>` (PEM text) or `<env>_FILE` (path). */
export function loadServerPublicKey(policy: ApprovalPolicy, env: NodeJS.ProcessEnv = process.env): KeyObject | null {
  const inline = env[policy.publicKeyEnv];
  const file = env[`${policy.publicKeyEnv}_FILE`];
  const pem = inline && inline.trim() ? inline.replace(/\\n/g, "\n") : file ? fs.readFileSync(file, "utf8") : null;
  return pem ? loadPublicKey(pem) : null;
}

/** Env names that suggest the approver's private key was handed to the server (separation of duties). */
export function privateKeyInServerEnv(env: NodeJS.ProcessEnv = process.env): string[] {
  return Object.keys(env).filter((k) => /^PGGUARD_APPROVAL_PRIVATE_KEY/.test(k) && env[k]);
}

export function createApprovalRuntime(policy: ApprovalPolicy, env: NodeJS.ProcessEnv = process.env): ApprovalRuntime {
  return {
    policy,
    publicKey: loadServerPublicKey(policy, env),
    ledger: policy.ledger === "postgres" ? new PgLedger() : new FileLedger(path.join(policy.dir, "used")),
    queue: new RequestQueue(policy.dir),
  };
}

export function approvalRequired(policy: ApprovalPolicy, kind: ApprovalKind): boolean {
  return policy.requiredFor.includes(kind);
}

/** approval_token wins; otherwise approval_id is looked up in the queue (approved/pending/denied). */
export function tokenFromArgs(args: Record<string, unknown>, queue: RequestQueue): string {
  if (typeof args.approval_token === "string" && args.approval_token.trim()) return args.approval_token.trim();
  if (typeof args.approval_id === "string" && args.approval_id.trim()) return queue.tokenFor(args.approval_id.trim());
  throw new ApprovalError(
    "missing",
    "this statement needs an out-of-band approval: call request_approval with the exact SQL, have a human run `npm run approvals -- approve <approval_id>`, then retry with approval_id",
  );
}

/** Verify (not consume) the approval for this call. */
export function checkApproval(rt: ApprovalRuntime, args: Record<string, unknown>, scope: ApprovalScope, now?: number): ApprovalClaims {
  if (!rt.publicKey) {
    throw new ApprovalError(
      "not_configured",
      `approvals are required but no approver public key is configured (${rt.policy.publicKeyEnv} or ${rt.policy.publicKeyEnv}_FILE)`,
    );
  }
  const token = tokenFromArgs(args, rt.queue);
  return verifyApproval(token, scope, {
    publicKey: rt.publicKey,
    now,
    maxTtlSeconds: rt.policy.maxTtlSeconds,
    clockSkewSeconds: rt.policy.clockSkewSeconds,
  });
}

/** min(policy cap, approver cap). */
export function effectiveAffectedCap(policyCap: number, claims: ApprovalClaims | null): number {
  if (!claims || claims.max_affected_rows === undefined) return policyCap;
  return Math.min(policyCap, claims.max_affected_rows);
}
