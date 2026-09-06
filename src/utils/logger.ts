/** Structured JSON logs to stderr (never stdout — MCP uses stdio). */
export type LogLevel = "debug" | "info" | "warn" | "error";

export function log(level: LogLevel, message: string, fields: Record<string, unknown> = {}): void {
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    level,
    msg: message,
    ...fields,
  });
  process.stderr.write(line + "\n");
}
