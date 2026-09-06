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

/** Wrap SELECT with LIMIT if not already present (simple heuristic). */
export function enforceMaxRows(sql: string, maxRows: number): string {
  const trimmed = sql.trim().replace(/;\s*$/, "");
  if (/\blimit\s+\d+/i.test(trimmed)) return trimmed;
  return `${trimmed} LIMIT ${Math.max(1, maxRows)}`;
}
