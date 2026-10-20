#!/usr/bin/env node
/**
 * Approver CLI (phase 4). Runs on the human approver's machine/session, NOT in the
 * MCP server's environment: it needs the Ed25519 private key.
 *
 *   npm run approvals -- keygen <outdir>
 *   npm run approvals -- list
 *   npm run approvals -- show <approval_id>
 *   npm run approvals -- approve <approval_id> --approver alice [--ttl 600] [--max-rows N] [--key path]
 *   npm run approvals -- deny <approval_id> --approver alice [--note "why"]
 *
 * Options: --dir <queue dir> (default PGGUARD_APPROVALS_DIR or ./data/approvals).
 * Signing key: --key <pem> or PGGUARD_APPROVAL_PRIVATE_KEY_FILE.
 */
import fs from "node:fs";
import path from "node:path";
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { pathToFileURL } from "node:url";
import { RequestQueue, type ApprovalRequest } from "./requests.js";
import { ApprovalError, loadPrivateKey, newJti, signApproval, sqlSha256, type ApprovalClaims } from "./token.js";

export interface ApproveOptions {
  approver: string;
  ttlSeconds?: number;
  /** Row cap the approver accepts; defaults to the dry-run preview count for DML. */
  maxAffectedRows?: number;
  privateKey: KeyObject;
  now?: number;
}

/** Build and sign the token for a pending request. Recomputes the SQL hash from the stored SQL. */
export function approveRequest(req: ApprovalRequest, opts: ApproveOptions): { token: string; claims: ApprovalClaims } {
  const approver = opts.approver.trim();
  if (!approver) throw new Error("--approver is required");
  if (req.sub !== null && approver === req.sub) throw new ApprovalError("self_approval", "approver must not be the requesting principal");
  const ttl = opts.ttlSeconds ?? 600;
  if (!(Number.isInteger(ttl) && ttl > 0)) throw new Error("--ttl must be a positive integer (seconds)");
  const hash = sqlSha256(req.sql);
  if (req.sql_sha256 && req.sql_sha256 !== hash) {
    throw new Error(`request ${req.rid}: stored sql_sha256 does not match its SQL; refusing (queue file was edited)`);
  }
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const maxRows = opts.maxAffectedRows ?? (req.tool === "run_dml" && req.preview ? req.preview.rowCount : undefined);
  const claims: ApprovalClaims = {
    v: 1,
    jti: newJti(),
    rid: req.rid,
    tool: req.tool,
    role: req.role,
    db_user: req.db_user,
    database: req.database,
    sub: req.sub ?? null,
    sql_sha256: hash,
    approver,
    iat: now,
    exp: now + ttl,
    ...(maxRows !== undefined ? { max_affected_rows: maxRows } : {}),
  };
  return { token: signApproval(claims, opts.privateKey), claims };
}

export function keygen(outdir: string): { privatePath: string; publicPath: string } {
  fs.mkdirSync(outdir, { recursive: true, mode: 0o700 });
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePath = path.join(outdir, "approver.key");
  const publicPath = path.join(outdir, "approver.pub");
  fs.writeFileSync(privatePath, privateKey.export({ type: "pkcs8", format: "pem" }), { flag: "wx", mode: 0o600 });
  fs.writeFileSync(publicPath, publicKey.export({ type: "spki", format: "pem" }), { flag: "wx", mode: 0o644 });
  return { privatePath, publicPath };
}

function flag(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] : undefined;
}

function describe(req: ApprovalRequest): string {
  return [
    `approval_id: ${req.rid}`,
    `created:     ${req.created_at}`,
    `tool:        ${req.tool}   role: ${req.role}   db: ${req.db_user}@${req.database}`,
    `principal:   ${req.sub ?? "(none)"}`,
    req.reason ? `reason:      ${req.reason}` : null,
    req.preview ? `dry run:     ${req.preview.rowCount} row(s)${req.preview.would_exceed_cap ? " (OVER role cap " + req.preview.max_affected_rows + ")" : ""}` : null,
    `sql_sha256:  ${sqlSha256(req.sql)}`,
    "sql:",
    req.sql,
  ]
    .filter(Boolean)
    .join("\n");
}

export function main(argv: string[]): number {
  const [cmd, arg] = argv;
  const queue = new RequestQueue(flag(argv, "dir") || process.env.PGGUARD_APPROVALS_DIR || path.join(process.cwd(), "data", "approvals"));
  switch (cmd) {
    case "keygen": {
      if (!arg) throw new Error("usage: keygen <outdir>");
      const k = keygen(arg);
      console.log(`private key (keep with the approver, never in the server env): ${k.privatePath}`);
      console.log(`public key (give the server PGGUARD_APPROVAL_PUBLIC_KEY_FILE=${k.publicPath})`);
      return 0;
    }
    case "list": {
      const pending = queue.list().filter((r) => queue.status(r.rid) === "pending");
      if (!pending.length) console.log("no pending approval requests");
      for (const r of pending) console.log(`${r.rid}  ${r.created_at}  ${r.tool}  ${r.role}  ${r.sql.replace(/\s+/g, " ").slice(0, 80)}`);
      return 0;
    }
    case "show": {
      const r = arg ? queue.get(arg) : null;
      if (!r) throw new Error(`no approval request ${arg}`);
      console.log(describe(r));
      console.log(`status:      ${queue.status(r.rid)}`);
      return 0;
    }
    case "approve": {
      const r = arg ? queue.get(arg) : null;
      if (!r) throw new Error(`no approval request ${arg}`);
      if (queue.status(r.rid) !== "pending") throw new Error(`request ${r.rid} is ${queue.status(r.rid)}, not pending`);
      const keyPath = flag(argv, "key") || process.env.PGGUARD_APPROVAL_PRIVATE_KEY_FILE;
      if (!keyPath) throw new Error("need --key <pem> or PGGUARD_APPROVAL_PRIVATE_KEY_FILE");
      const ttl = flag(argv, "ttl");
      const maxRows = flag(argv, "max-rows");
      const { token, claims } = approveRequest(r, {
        approver: flag(argv, "approver") || "",
        ttlSeconds: ttl ? Number(ttl) : undefined,
        maxAffectedRows: maxRows ? Number(maxRows) : undefined,
        privateKey: loadPrivateKey(fs.readFileSync(keyPath, "utf8")),
      });
      queue.writeToken(r.rid, token);
      console.error(describe(r));
      console.error(`approved by ${claims.approver}, expires ${new Date(claims.exp * 1000).toISOString()}` + (claims.max_affected_rows !== undefined ? `, max_affected_rows ${claims.max_affected_rows}` : ""));
      console.log(token);
      return 0;
    }
    case "deny": {
      const r = arg ? queue.get(arg) : null;
      if (!r) throw new Error(`no approval request ${arg}`);
      const by = flag(argv, "approver");
      if (!by) throw new Error("--approver is required");
      queue.writeDenial(r.rid, by, flag(argv, "note"));
      console.log(`denied ${r.rid}`);
      return 0;
    }
    default:
      console.error("usage: approvals keygen|list|show|approve|deny ... (see src/approvals/cli.ts)");
      return 2;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  try {
    process.exit(main(process.argv.slice(2)));
  } catch (e) {
    console.error(e instanceof Error ? e.message : String(e));
    process.exit(1);
  }
}
