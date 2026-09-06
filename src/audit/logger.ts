import fs from "node:fs";
import path from "node:path";
import { log } from "../utils/logger.js";

export interface AuditEvent {
  ts: string;
  tool: string;
  role: string;
  ok: boolean;
  detail?: Record<string, unknown>;
  error?: string;
  sqlPreview?: string;
}

export class AuditLogger {
  private dir: string;
  private filePath: string;

  constructor(dir?: string) {
    this.dir = dir || process.env.PGGUARD_AUDIT_DIR || path.join(process.cwd(), "data", "audit");
    fs.mkdirSync(this.dir, { recursive: true });
    this.filePath = path.join(this.dir, "events.jsonl");
  }

  append(event: Omit<AuditEvent, "ts"> & { ts?: string }): AuditEvent {
    const full: AuditEvent = {
      ts: event.ts || new Date().toISOString(),
      tool: event.tool,
      role: event.role,
      ok: event.ok,
      detail: event.detail,
      error: event.error,
      sqlPreview: event.sqlPreview ? event.sqlPreview.slice(0, 500) : undefined,
    };
    fs.appendFileSync(this.filePath, JSON.stringify(full) + "\n", { flag: "a" });
    log(full.ok ? "info" : "warn", "audit", {
      tool: full.tool,
      role: full.role,
      ok: full.ok,
    });
    return full;
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
