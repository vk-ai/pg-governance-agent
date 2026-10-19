/**
 * Single-use ledger for approval tokens (jti).
 *
 * - FileLedger: one file per jti created with O_CREAT|O_EXCL ("wx"), which is
 *   atomic on a local filesystem, so two processes on the same host cannot both
 *   consume a jti. Consumed before the statement runs ("burn then run"): if the
 *   statement then fails, the approval is spent and a new one is needed.
 * - PgLedger: pgguard.consume_approval() (docker/postgres/optional/approval-ledger.sql),
 *   a SECURITY DEFINER function inserting into a table agent roles cannot read or
 *   write. For run_dml it runs inside the DML transaction, so the approval is spent
 *   only if the write commits (a cap rollback leaves it unused). It also rejects
 *   tokens whose exp has passed by the database clock.
 */
import fs from "node:fs";
import path from "node:path";
import type pg from "pg";
import { ApprovalError, type ApprovalClaims } from "./token.js";

export type LedgerKind = "file" | "postgres";

export interface ApprovalLedger {
  readonly kind: LedgerKind;
  /** Throws ApprovalError("replayed") if the jti was already used. `client` is required for postgres. */
  consume(claims: ApprovalClaims, client?: pg.PoolClient): Promise<void>;
}

export class FileLedger implements ApprovalLedger {
  readonly kind = "file" as const;
  constructor(private readonly dir: string) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  async consume(claims: ApprovalClaims): Promise<void> {
    if (!/^[0-9a-f]{32}$/.test(claims.jti)) throw new ApprovalError("malformed", "bad jti");
    const f = path.join(this.dir, claims.jti);
    try {
      fs.writeFileSync(
        f,
        JSON.stringify({ jti: claims.jti, rid: claims.rid, sql_sha256: claims.sql_sha256, tool: claims.tool, approver: claims.approver, consumed_at: new Date().toISOString() }) + "\n",
        { flag: "wx", mode: 0o600 },
      );
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "EEXIST") {
        throw new ApprovalError("replayed", `approval ${claims.jti} was already used`);
      }
      throw e;
    }
  }

  isConsumed(jti: string): boolean {
    return fs.existsSync(path.join(this.dir, jti));
  }
}

export class PgLedger implements ApprovalLedger {
  readonly kind = "postgres" as const;

  async consume(claims: ApprovalClaims, client?: pg.PoolClient): Promise<void> {
    if (!client) throw new Error("PgLedger.consume needs a client");
    try {
      await client.query("SELECT pgguard.consume_approval($1, $2, $3, $4, to_timestamp($5))", [
        claims.jti,
        claims.sql_sha256,
        claims.tool,
        claims.approver,
        claims.exp,
      ]);
    } catch (e) {
      const err = e as { code?: string; message?: string };
      if (err.code === "23505") throw new ApprovalError("replayed", `approval ${claims.jti} was already used`);
      if (err.code === "22023" && /expired/.test(err.message || "")) {
        throw new ApprovalError("expired", "expired by the database clock");
      }
      throw e;
    }
  }
}
