import type pg from "pg";

export async function ping(client: pg.PoolClient): Promise<{ ok: true; version: string }> {
  const r = await client.query("SELECT version() AS version");
  return { ok: true, version: String(r.rows[0]?.version ?? "") };
}

export async function listSchemas(client: pg.PoolClient): Promise<string[]> {
  const r = await client.query(
    `SELECT schema_name
     FROM information_schema.schemata
     WHERE schema_name NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
     ORDER BY schema_name`,
  );
  return r.rows.map((row) => String(row.schema_name));
}

export async function listTables(
  client: pg.PoolClient,
  schema?: string,
): Promise<{ schema: string; name: string }[]> {
  const params: string[] = [];
  let sql = `SELECT table_schema AS schema, table_name AS name
    FROM information_schema.tables
    WHERE table_type = 'BASE TABLE'
      AND table_schema NOT IN ('pg_catalog', 'information_schema')`;
  if (schema) {
    params.push(schema);
    sql += ` AND table_schema = $${params.length}`;
  }
  sql += " ORDER BY table_schema, table_name";
  const r = await client.query(sql, params);
  return r.rows.map((row) => ({ schema: String(row.schema), name: String(row.name) }));
}

export async function describeTable(
  client: pg.PoolClient,
  schema: string,
  table: string,
): Promise<{ column: string; data_type: string; is_nullable: string; column_default: string | null }[]> {
  const r = await client.query(
    `SELECT column_name AS column, data_type, is_nullable, column_default
     FROM information_schema.columns
     WHERE table_schema = $1 AND table_name = $2
     ORDER BY ordinal_position`,
    [schema, table],
  );
  return r.rows.map((row) => ({
    column: String(row.column),
    data_type: String(row.data_type),
    is_nullable: String(row.is_nullable),
    column_default: row.column_default == null ? null : String(row.column_default),
  }));
}

/**
 * Run agent-supplied SQL with the extended query protocol so Postgres itself
 * rejects multi-statement strings such as `SELECT 1; COMMIT; DELETE ...`
 * (defense in depth on top of the classifier and the READ ONLY transaction).
 */
export async function runUserSql(client: pg.PoolClient, sql: string): Promise<pg.QueryResult> {
  // `queryMode` exists in node-pg >= 8.12 but is not in @types/pg yet.
  return client.query({ text: sql, queryMode: "extended" } as pg.QueryConfig);
}

/** Limits applied to rows returned to the agent. */
export interface ResultCaps {
  /** Max rows returned (already min(requested, policy) — see effectiveMaxRows). */
  maxRows: number;
  /** Total budget for the returned rows, measured as compact JSON bytes. */
  maxResultBytes: number;
  /** Per-cell cap; longer strings / bytea / json are cut to this many bytes. */
  maxCellBytes: number;
}

export interface CappedResult {
  rows: Record<string, unknown>[];
  rowCount: number;
  /** True when rows were dropped (row or byte cap) or any cell was cut. */
  truncated: boolean;
  truncatedBy: ("rows" | "bytes" | "cells")[];
  /** Compact JSON bytes of the returned rows. */
  resultBytes: number;
  /** Number of cells cut to maxCellBytes. */
  truncatedCells: number;
  /** Columns that had at least one cut cell. */
  truncatedColumns: string[];
}

/** Rows fetched per FETCH round trip (bounds memory per round to batch x row size). */
export const CURSOR_BATCH_ROWS = 50;
const CURSOR_NAME = "pgguard_result";

/** Cut a UTF-8 string to at most `max` bytes without splitting a code point. */
export function truncateUtf8(s: string, max: number): string {
  const buf = Buffer.from(s, "utf8");
  if (buf.length <= max) return s;
  let end = max;
  // Step back over UTF-8 continuation bytes (10xxxxxx) so we cut on a boundary.
  while (end > 0 && (buf[end]! & 0xc0) === 0x80) end--;
  return buf.subarray(0, end).toString("utf8");
}

function capCell(v: unknown, max: number): { value: unknown; cut: boolean } {
  if (v === null || v === undefined) return { value: v, cut: false };
  if (typeof v === "string") {
    if (Buffer.byteLength(v, "utf8") <= max) return { value: v, cut: false };
    return { value: truncateUtf8(v, max), cut: true };
  }
  if (Buffer.isBuffer(v)) {
    // Reported as hex so the agent sees bytes, not {"type":"Buffer","data":[...]}.
    const hex = v.toString("hex");
    if (v.length <= max) return { value: `\\x${hex}`, cut: false };
    return { value: `\\x${v.subarray(0, max).toString("hex")}`, cut: true };
  }
  if (typeof v === "object" && !(v instanceof Date)) {
    const j = JSON.stringify(v);
    if (Buffer.byteLength(j, "utf8") <= max) return { value: v, cut: false };
    // json/jsonb/arrays: return the cut JSON text (no longer valid JSON; flagged).
    return { value: truncateUtf8(j, max), cut: true };
  }
  return { value: v, cut: false };
}

/**
 * Apply cell and byte caps to rows already in memory, plus the row cap.
 * Shared by the cursor path and explain_query.
 */
export class ResultBudget {
  readonly rows: Record<string, unknown>[] = [];
  private bytes = 2; // "[]"
  private cells = 0;
  private columns = new Set<string>();
  private by = new Set<"rows" | "bytes" | "cells">();
  done = false;

  constructor(private readonly caps: ResultCaps) {}

  /** Add a row; returns false (and sets done) once a cap stops the result. */
  add(row: Record<string, unknown>): boolean {
    if (this.done) return false;
    if (this.rows.length >= Math.max(1, this.caps.maxRows)) {
      this.by.add("rows");
      this.done = true;
      return false;
    }
    const out: Record<string, unknown> = {};
    let cut = 0;
    const cutCols: string[] = [];
    for (const [k, v] of Object.entries(row)) {
      const c = capCell(v, this.caps.maxCellBytes);
      out[k] = c.value;
      if (c.cut) {
        cut++;
        cutCols.push(k);
      }
    }
    const size = Buffer.byteLength(JSON.stringify(out), "utf8") + (this.rows.length ? 1 : 0);
    if (this.bytes + size > this.caps.maxResultBytes) {
      this.by.add("bytes");
      this.done = true;
      return false;
    }
    this.rows.push(out);
    this.bytes += size;
    if (cut) {
      this.cells += cut;
      cutCols.forEach((c) => this.columns.add(c));
      this.by.add("cells");
    }
    return true;
  }

  result(): CappedResult {
    return {
      rows: this.rows,
      rowCount: this.rows.length,
      truncated: this.by.size > 0,
      truncatedBy: [...this.by],
      resultBytes: this.rows.length ? this.bytes : 2,
      truncatedCells: this.cells,
      truncatedColumns: [...this.columns],
    };
  }
}

/** Apply caps to an in-memory row list (EXPLAIN output, tests). */
export function capRows(rows: Record<string, unknown>[], caps: ResultCaps): CappedResult {
  const b = new ResultBudget(caps);
  for (const r of rows) if (!b.add(r)) break;
  return b.result();
}

/**
 * Run a SELECT through a server-side cursor and stop at the caps.
 *
 * Replaces the old "append LIMIT unless the text contains LIMIT" heuristic:
 * `DECLARE pgguard_result NO SCROLL CURSOR FOR <sql>` then
 * `FETCH FORWARD k` in batches until max_rows+1 rows were seen (the extra row
 * only proves truncation) or the byte budget is spent. For streaming plans
 * (scans, nested loops) Postgres produces only the rows fetched; plans with a
 * Sort / Hash / aggregate still do that work before the first row (bounded by
 * statement_timeout). LIMIT inside a subquery or a huge requested max_rows
 * cannot raise the cap.
 *
 * Must run inside a transaction (cursors are transaction-scoped); PgGuard's
 * read path is BEGIN READ ONLY ... ROLLBACK. DECLARE accepts only SELECT /
 * VALUES (incl. WITH ... SELECT), and the extended protocol still rejects
 * multi-statement strings.
 *
 * Limit: one cell is transferred in full before it is cut (bounded by
 * statement_timeout and Postgres's 1 GB field limit), so max_cell_bytes caps
 * what the agent sees, not what crosses the wire.
 */
export async function fetchCapped(
  client: pg.PoolClient,
  sql: string,
  caps: ResultCaps,
  batchRows = CURSOR_BATCH_ROWS,
): Promise<CappedResult> {
  const body = sql.trim().replace(/;\s*$/, "");
  await client.query({
    text: `DECLARE ${CURSOR_NAME} NO SCROLL CURSOR WITHOUT HOLD FOR ${body}`,
    queryMode: "extended",
  } as pg.QueryConfig);
  const budget = new ResultBudget(caps);
  const wanted = Math.max(1, caps.maxRows) + 1;
  let seen = 0;
  try {
    while (!budget.done && seen < wanted) {
      const k = Math.min(Math.max(1, batchRows), wanted - seen);
      const r = await client.query(`FETCH FORWARD ${k} FROM ${CURSOR_NAME}`);
      seen += r.rows.length;
      for (const row of r.rows) if (!budget.add(row)) break;
      if (r.rows.length < k) break;
    }
  } finally {
    await client.query(`CLOSE ${CURSOR_NAME}`).catch(() => undefined);
  }
  return budget.result();
}

/**
 * Row cap the agent cannot raise: min(requested, policy). Invalid or missing
 * requests fall back to the policy value; the result is at least 1.
 */
export function effectiveMaxRows(requested: unknown, policyMax: number): number {
  const cap = Math.max(1, Math.floor(Number(policyMax) || 1));
  const n = Number(requested);
  if (requested === undefined || requested === null || !Number.isFinite(n) || n < 1) return cap;
  return Math.min(Math.floor(n), cap);
}
