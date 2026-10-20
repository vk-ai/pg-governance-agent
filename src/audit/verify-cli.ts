/**
 * Verify the audit hash chain.
 *
 *   npm run audit:verify -- [path/to/events.jsonl] [--key-env NAME]
 *
 * Exits 0 when the chain verifies, 1 when it is broken (prints the first bad
 * line), 2 on usage errors. Prints the head {seq, hash}: store it outside this
 * host (ticket, SIEM, object storage with retention) so truncation of the
 * tail can be detected later.
 */
import path from "node:path";
import { auditKeyFromEnv, verifyAuditFile } from "./logger.js";

function main(argv: string[]): number {
  let file: string | undefined;
  let keyEnv = "PGGUARD_AUDIT_HMAC_KEY";
  let expectHead: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--key-env") keyEnv = argv[++i] ?? "";
    else if (a === "--expect-head") expectHead = argv[++i];
    else if (a.startsWith("--")) {
      process.stderr.write(`unknown option ${a}\n`);
      return 2;
    } else file = a;
  }
  file ??= path.join(process.env.PGGUARD_AUDIT_DIR || path.join(process.cwd(), "data", "audit"), "events.jsonl");
  let head: { seq: number; hash: string } | undefined;
  if (expectHead !== undefined) {
    const m = /^(\d+):([0-9a-f]{64})$/.exec(expectHead);
    if (!m) {
      process.stderr.write("--expect-head must be <seq>:<64 hex hash>\n");
      return 2;
    }
    head = { seq: Number(m[1]), hash: m[2]! };
  }
  const key = auditKeyFromEnv(keyEnv);
  const res = verifyAuditFile(file, key, { expectHead: head });
  process.stdout.write(JSON.stringify(res, null, 2) + "\n");
  return res.ok ? 0 : 1;
}

process.exit(main(process.argv.slice(2)));
