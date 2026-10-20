/**
 * Append-only JSONL audit log. Phase 5 makes it tamper-evident: every line
 * carries `seq`, `prev` (the previous line's hash) and `hash`, where
 *
 *   hash = H(prev + "\n" + canonical_json(line without hash))
 *
 * and H is sha256, or HMAC-SHA256 when an audit key is configured. Editing,
 * reordering, inserting or deleting a line breaks the chain from that point;
 * `npm run audit:verify` finds the first bad line. Without the HMAC key an
 * attacker with write access can rebuild the whole chain, and nobody can
 * detect lines cut off the end unless the head hash was recorded elsewhere.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { log } from "../utils/logger.js";

export interface AuditEvent {
  ts: string;
  tool: string;
  role: string;
  principal?: string;
  ok: boolean;
  detail?: Record<string, unknown>;
  error?: string;
  sqlPreview?: string;
  /** sha256 of the full SQL text (the preview is cut at 500 chars). */
  sql_sha256?: string;
  /** Phase 5 chain fields (absent on pre-phase-5 lines). */
  seq?: number;
  prev?: string;
  alg?: "sha256" | "hmac-sha256";
  hash?: string;
}

export const GENESIS = "0".repeat(64);

export interface AuditLoggerOptions {
  /** Hash-chain new lines (default true). */
  hashChain?: boolean;
  /** HMAC key for the chain; default from PGGUARD_AUDIT_HMAC_KEY (hex, >= 32 bytes). */
  hmacKey?: Buffer | null;
  /** Env var to read the key from when hmacKey is not given. */
  hmacKeyEnv?: string;
  /** Throw from the constructor if the existing file does not verify. */
  verifyOnStart?: boolean;
}

/** Parse a hex HMAC key; throws if it is set but too short or not hex. */
export function auditKeyFromEnv(envName = "PGGUARD_AUDIT_HMAC_KEY"): Buffer | null {
  const raw = process.env[envName];
  if (raw === undefined || raw === "") return null;
  const hex = raw.trim();
  if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length % 2 !== 0 || hex.length < 64) {
    throw new Error(`${envName} must be hex and at least 32 bytes (64 hex chars)`);
  }
  return Buffer.from(hex, "hex");
}

/** JSON with sorted keys and no undefined values, so the hash is stable. */
export function canonicalJson(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v ?? null);
  if (Array.isArray(v)) return `[${v.map((x) => (x === undefined ? "null" : canonicalJson(x))).join(",")}]`;
  const o = v as Record<string, unknown>;
  const keys = Object.keys(o).filter((k) => o[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`).join(",")}}`;
}

export function chainHash(prev: string, body: Record<string, unknown>, key: Buffer | null): string {
  const data = `${prev}\n${canonicalJson(body)}`;
  return key
    ? crypto.createHmac("sha256", key).update(data).digest("hex")
    : crypto.createHash("sha256").update(data).digest("hex");
}

export interface AuditVerifyResult {
  ok: boolean;
  file: string;
  lines: number;
  /** Pre-phase-5 lines before the first chained line (not protected). */
  legacy: number;
  chained: number;
  alg: "sha256" | "hmac-sha256" | null;
  /** Last chained line: record it somewhere else to detect truncation later. */
  head: { seq: number; hash: string } | null;
  error?: { line: number; reason: string };
}

/**
 * Verify the chain in `file`. Line numbers are 1-based. With `key`, lines must
 * be HMAC-chained with that key; without it, HMAC lines are reported as
 * unverifiable rather than accepted.
 */
export function verifyAuditFile(
  file: string,
  key: Buffer | null = null,
  opts: { expectHead?: { seq: number; hash: string } } = {},
): AuditVerifyResult {
  const res: AuditVerifyResult = { ok: true, file, lines: 0, legacy: 0, chained: 0, alg: null, head: null };
  const want = opts.expectHead;
  let headSeen = false;
  if (!fs.existsSync(file)) {
    return want ? { ...res, ok: false, error: { line: 0, reason: "audit file missing but a head was recorded" } } : res;
  }
  const lines = fs.readFileSync(file, "utf8").split("\n");
  if (lines.length && lines[lines.length - 1] === "") lines.pop();
  let prev = GENESIS;
  let expectSeq = 0;
  const fail = (line: number, reason: string): AuditVerifyResult => ({ ...res, ok: false, error: { line, reason } });
  for (let i = 0; i < lines.length; i++) {
    const n = i + 1;
    res.lines = n;
    const raw = lines[i]!;
    let ev: AuditEvent & Record<string, unknown>;
    try {
      ev = JSON.parse(raw);
    } catch {
      return fail(n, "not valid JSON");
    }
    if (!ev || typeof ev !== "object") return fail(n, "not a JSON object");
    if (ev.hash === undefined) {
      if (res.chained > 0) return fail(n, "unchained line after the chain started");
      res.legacy++;
      continue;
    }
    if (typeof ev.hash !== "string" || !/^[0-9a-f]{64}$/.test(ev.hash)) return fail(n, "malformed hash");
    if (ev.alg !== "sha256" && ev.alg !== "hmac-sha256") return fail(n, `unknown alg ${String(ev.alg)}`);
    if (res.alg && ev.alg !== res.alg) return fail(n, `alg changed from ${res.alg} to ${ev.alg}`);
    res.alg = ev.alg;
    if (ev.alg === "hmac-sha256" && !key) return fail(n, "line is HMAC-chained; set the audit HMAC key to verify");
    if (ev.alg === "sha256" && key) return fail(n, "line is plain sha256 but an HMAC key was given (downgrade?)");
    if (ev.seq !== expectSeq) return fail(n, `seq ${String(ev.seq)} where ${expectSeq} was expected (line inserted or removed)`);
    if (ev.prev !== prev) return fail(n, "prev does not match the previous line's hash (line edited, removed or reordered)");
    const { hash, ...body } = ev;
    const expected = chainHash(prev, body, ev.alg === "hmac-sha256" ? key : null);
    if (!crypto.timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(hash, "hex"))) {
      return fail(n, "hash mismatch (line content was changed)");
    }
    if (want && ev.seq === want.seq) {
      if (hash !== want.hash) return fail(n, `seq ${want.seq} hash differs from the recorded head (chain rewritten)`);
      headSeen = true;
    }
    prev = hash;
    expectSeq++;
    res.chained++;
    res.head = { seq: ev.seq, hash };
  }
  if (want && !headSeen) {
    return { ...res, ok: false, error: { line: res.lines, reason: `recorded head seq ${want.seq} is not in the log (truncated?)` } };
  }
  return res;
}

function readLastLine(file: string): string | null {
  if (!fs.existsSync(file)) return null;
  const size = fs.statSync(file).size;
  if (size === 0) return null;
  const fd = fs.openSync(file, "r");
  try {
    let chunk = 4096;
    for (;;) {
      const len = Math.min(size, chunk);
      const buf = Buffer.alloc(len);
      fs.readSync(fd, buf, 0, len, size - len);
      const text = buf.toString("utf8").replace(/\n+$/, "");
      const nl = text.lastIndexOf("\n");
      if (nl >= 0 || len === size) return nl >= 0 ? text.slice(nl + 1) : text;
      chunk *= 4;
    }
  } finally {
    fs.closeSync(fd);
  }
}

export class AuditLogger {
  private dir: string;
  readonly filePath: string;
  readonly hashChain: boolean;
  private key: Buffer | null;
  private prev = GENESIS;
  private seq = 0;
  private knownSize = -1;

  constructor(dir?: string, opts: AuditLoggerOptions = {}) {
    this.dir = dir || process.env.PGGUARD_AUDIT_DIR || path.join(process.cwd(), "data", "audit");
    fs.mkdirSync(this.dir, { recursive: true });
    this.filePath = path.join(this.dir, "events.jsonl");
    this.hashChain = opts.hashChain ?? true;
    this.key = opts.hmacKey !== undefined ? opts.hmacKey : auditKeyFromEnv(opts.hmacKeyEnv);
    if (opts.verifyOnStart) {
      const v = verifyAuditFile(this.filePath, this.hashChain ? this.key : null);
      if (!v.ok && this.hashChain) {
        throw new Error(`Audit log ${this.filePath} failed verification at line ${v.error!.line}: ${v.error!.reason}`);
      }
    }
    if (this.hashChain) this.syncTail();
  }

  /** Continue the chain from the file's last line (also after another writer appended). */
  private syncTail(): void {
    const size = fs.existsSync(this.filePath) ? fs.statSync(this.filePath).size : 0;
    if (size === this.knownSize) return;
    this.prev = GENESIS;
    this.seq = 0;
    const last = readLastLine(this.filePath);
    if (last) {
      try {
        const ev = JSON.parse(last) as AuditEvent;
        if (typeof ev.hash === "string" && typeof ev.seq === "number") {
          this.prev = ev.hash;
          this.seq = ev.seq + 1;
        }
      } catch {
        // corrupt tail: keep GENESIS; audit:verify will report the break
      }
    }
    this.knownSize = size;
  }

  /** Chain algorithm for new lines (null when chaining is off). */
  get alg(): "sha256" | "hmac-sha256" | null {
    return this.hashChain ? (this.key ? "hmac-sha256" : "sha256") : null;
  }

  append(event: Omit<AuditEvent, "ts"> & { ts?: string }): AuditEvent {
    const sql = event.sqlPreview;
    const full: AuditEvent = {
      ts: event.ts || new Date().toISOString(),
      tool: event.tool,
      role: event.role,
      principal: event.principal,
      ok: event.ok,
      detail: event.detail,
      error: event.error,
      sqlPreview: sql ? sql.slice(0, 500) : undefined,
      sql_sha256: sql ? crypto.createHash("sha256").update(sql, "utf8").digest("hex") : undefined,
    };
    if (this.hashChain) {
      this.syncTail();
      full.seq = this.seq;
      full.prev = this.prev;
      full.alg = this.alg!;
      // Round-trip through JSON so the hash covers exactly what is written.
      const body = JSON.parse(JSON.stringify(full)) as Record<string, unknown>;
      full.hash = chainHash(this.prev, body, this.key);
    }
    const line = JSON.stringify(full) + "\n";
    fs.appendFileSync(this.filePath, line, { flag: "a" });
    if (this.hashChain) {
      this.prev = full.hash!;
      this.seq++;
      this.knownSize = fs.statSync(this.filePath).size;
    }
    log(full.ok ? "info" : "warn", "audit", {
      tool: full.tool,
      role: full.role,
      ok: full.ok,
    });
    return full;
  }

  verify(): AuditVerifyResult {
    return verifyAuditFile(this.filePath, this.key);
  }

  tail(n: number): AuditEvent[] {
    if (!fs.existsSync(this.filePath)) return [];
    const raw = fs.readFileSync(this.filePath, "utf8");
    const lines = raw.split("\n").filter((l) => l.trim().length > 0);
    const slice = lines.slice(-Math.max(1, n));
    const out: AuditEvent[] = [];
    for (const line of slice) {
      try {
        out.push(JSON.parse(line) as AuditEvent);
      } catch {
        // skip corrupt lines
      }
    }
    return out;
  }
}
