/**
 * Approval request queue on the local filesystem.
 *
 *   <dir>/pending/<rid>.json   written by the server's request_approval tool
 *   <dir>/approved/<rid>.token written by the approvals CLI (human, holds the private key)
 *   <dir>/denied/<rid>.json    written by the approvals CLI
 *   <dir>/used/<jti>           FileLedger (single use)
 *
 * The queue is a convenience transport. It is not trusted: a token found in
 * approved/ is verified exactly like one pasted into the tool call, and the CLI
 * recomputes the SQL hash from the stored SQL instead of trusting the file.
 */
import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { ApprovalError, sqlSha256, type ApprovalScope } from "./token.js";

export interface ApprovalRequest extends ApprovalScope {
  rid: string;
  sql: string;
  created_at: string;
  reason?: string;
  /** run_dml requests: row count from a rolled-back dry run, shown to the approver. */
  preview?: { rowCount: number; would_exceed_cap: boolean; max_affected_rows: number };
}

const RID_RE = /^[0-9a-f]{24}$/;

export function newRid(): string {
  return randomBytes(12).toString("hex");
}

function checkRid(rid: string): string {
  if (typeof rid !== "string" || !RID_RE.test(rid)) throw new ApprovalError("malformed", "approval_id must be 24 hex chars");
  return rid;
}

export class RequestQueue {
  constructor(readonly dir: string) {}

  private sub(name: "pending" | "approved" | "denied"): string {
    const d = path.join(this.dir, name);
    fs.mkdirSync(d, { recursive: true, mode: 0o700 });
    return d;
  }

  create(req: Omit<ApprovalRequest, "rid" | "created_at" | "sql_sha256">): ApprovalRequest {
    const full: ApprovalRequest = {
      ...req,
      rid: newRid(),
      created_at: new Date().toISOString(),
      sql_sha256: sqlSha256(req.sql),
    };
    fs.writeFileSync(path.join(this.sub("pending"), `${full.rid}.json`), JSON.stringify(full, null, 2) + "\n", {
      flag: "wx",
      mode: 0o600,
    });
    return full;
  }

  get(rid: string): ApprovalRequest | null {
    const f = path.join(this.sub("pending"), `${checkRid(rid)}.json`);
    if (!fs.existsSync(f)) return null;
    return JSON.parse(fs.readFileSync(f, "utf8")) as ApprovalRequest;
  }

  list(): ApprovalRequest[] {
    const d = this.sub("pending");
    return fs
      .readdirSync(d)
      .filter((f) => f.endsWith(".json"))
      .map((f) => JSON.parse(fs.readFileSync(path.join(d, f), "utf8")) as ApprovalRequest)
      .sort((a, b) => a.created_at.localeCompare(b.created_at));
  }

  status(rid: string): "approved" | "denied" | "pending" | "unknown" {
    checkRid(rid);
    if (fs.existsSync(path.join(this.sub("approved"), `${rid}.token`))) return "approved";
    if (fs.existsSync(path.join(this.sub("denied"), `${rid}.json`))) return "denied";
    if (fs.existsSync(path.join(this.sub("pending"), `${rid}.json`))) return "pending";
    return "unknown";
  }

  /** Token for an approved request, or ApprovalError(pending|denied|missing). */
  tokenFor(rid: string): string {
    const s = this.status(rid);
    if (s === "approved") return fs.readFileSync(path.join(this.sub("approved"), `${rid}.token`), "utf8").trim();
    if (s === "denied") throw new ApprovalError("denied", `request ${rid} was denied`);
    if (s === "pending") throw new ApprovalError("pending", `request ${rid} is still waiting for a human approver`);
    throw new ApprovalError("missing", `no approval request ${rid}`);
  }

  writeToken(rid: string, token: string): void {
    fs.writeFileSync(path.join(this.sub("approved"), `${checkRid(rid)}.token`), token + "\n", { flag: "wx", mode: 0o600 });
  }

  writeDenial(rid: string, by: string, note?: string): void {
    fs.writeFileSync(
      path.join(this.sub("denied"), `${checkRid(rid)}.json`),
      JSON.stringify({ rid, denied_by: by, note, at: new Date().toISOString() }) + "\n",
      { flag: "wx", mode: 0o600 },
    );
  }
}
