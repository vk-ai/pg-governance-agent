/**
 * Schema allowlist guard (phase 3 / plan phase 2).
 *
 * Walks the parsed SQL and rejects references to schemas the role may not use.
 * This is an *early deny with a clear message*; it is not the security
 * boundary. Postgres grants (USAGE on schema, SELECT on tables) remain the
 * guarantee — see tests/phase3-schema-caps.integration.test.ts, which shows a
 * grant-less schema is refused by the database with this guard switched off.
 *
 * Rules (when a role has `allowed_schemas`):
 *  1. SQL must parse. Anything pgsql-ast-parser cannot read is refused
 *     (fail closed) — the guard cannot vouch for what it cannot see.
 *  2. Schema-qualified relations (FROM / JOIN / subqueries / CTE bodies /
 *     INSERT / UPDATE / DELETE targets) must name an allowed schema.
 *     pg_catalog and information_schema count only if listed.
 *  3. Unqualified relations resolve through the search path PgGuard sets in
 *     each transaction (role `search_path`, which must be a subset of
 *     `allowed_schemas`). Postgres searches pg_catalog implicitly *first*, and
 *     every pg_catalog relation is named `pg_*`, so unqualified `pg_*`
 *     relations are refused unless pg_catalog is allowed.
 *  4. Any other qualified name (function, type, column ref `s.t.c`, DDL
 *     target) must be in an allowed schema or pg_catalog (built-in functions
 *     and types).
 *  5. Built-ins that execute SQL passed as a *string* (query_to_xml,
 *     table_to_xml, ts_stat, crosstab, ...) are refused: the guard cannot see
 *     inside the string.
 *
 * Known gaps (DB grants cover them): string-to-OID casts such as
 * 'hr.t'::regclass or to_regclass('hr.t') reveal whether an object exists;
 * pg_temp tables are searched before the path for unqualified names.
 */
import { astVisitor, parse, type Statement } from "pgsql-ast-parser";

export const SCHEMA_IDENT_RE = /^[a-z_][a-z0-9_$]*$/;

/** Built-ins that run SQL text given as an argument, so schema refs hide in a string. */
export const SQL_TEXT_FUNCTIONS = [
  "query_to_xml",
  "query_to_xmlschema",
  "query_to_xml_and_xmlschema",
  "cursor_to_xml",
  "cursor_to_xmlschema",
  "table_to_xml",
  "table_to_xmlschema",
  "table_to_xml_and_xmlschema",
  "schema_to_xml",
  "schema_to_xmlschema",
  "schema_to_xml_and_xmlschema",
  "database_to_xml",
  "database_to_xmlschema",
  "database_to_xml_and_xmlschema",
  "ts_stat",
  "crosstab",
  "crosstab2",
  "crosstab3",
  "crosstab4",
  "connectby",
  "xpath_table",
];

export interface RelationRef {
  schema: string | null;
  name: string;
}

export interface SchemaGuardResult {
  ok: boolean;
  reason?: string;
  relations: RelationRef[];
}

/** True when the guard is active (role has allowed_schemas) and `schema` is not in it. */
export function isSchemaAllowed(schema: string, allowed: readonly string[] | null | undefined): boolean {
  if (!allowed) return true;
  return allowed.includes(schema);
}

/** Keep only allowed schemas (no-op when the guard is off). */
export function filterSchemas<T>(items: T[], allowed: readonly string[] | null | undefined, key: (t: T) => string): T[] {
  if (!allowed) return items;
  return items.filter((t) => allowed.includes(key(t)));
}

function fmtAllowed(allowed: readonly string[]): string {
  return allowed.length ? allowed.join(", ") : "(none)";
}

/** Every `{ name, schema }` object anywhere in the AST (functions, types, DDL names, column refs). */
function qualifiedNames(node: unknown, out: { schema: string; name: string }[], seen = new Set<unknown>()): void {
  if (!node || typeof node !== "object" || seen.has(node)) return;
  seen.add(node);
  if (Array.isArray(node)) {
    for (const v of node) qualifiedNames(v, out, seen);
    return;
  }
  const o = node as Record<string, unknown>;
  if (typeof o.schema === "string" && typeof o.name === "string") {
    out.push({ schema: o.schema, name: o.name });
  }
  for (const v of Object.values(o)) qualifiedNames(v, out, seen);
}

function relationsOf(stmt: Statement): { relations: RelationRef[]; calls: string[] } {
  const relations: RelationRef[] = [];
  const calls: string[] = [];
  const v = astVisitor((map) => ({
    tableRef: (t) => {
      relations.push({ schema: t.schema ?? null, name: t.name });
      return map.super().tableRef(t);
    },
    call: (c) => {
      calls.push(c.function.name);
      return map.super().call(c);
    },
  }));
  v.statement(stmt);
  return { relations, calls };
}

/**
 * Check one SQL string against an allowlist. `allowed === null` disables the
 * guard (returns ok). Schema names compare exactly, as Postgres does after
 * folding unquoted identifiers to lower case.
 */
export function checkSchemas(sql: string, allowed: readonly string[] | null | undefined): SchemaGuardResult {
  if (!allowed) return { ok: true, relations: [] };
  let ast: Statement[];
  try {
    ast = parse(sql);
  } catch {
    return {
      ok: false,
      relations: [],
      reason: "Schema guard could not parse this SQL, so it cannot verify which schemas it touches (fail closed). Simplify the query or use list_tables/describe_table.",
    };
  }
  if (!ast.length) return { ok: false, relations: [], reason: "Schema guard: empty statement" };
  const catalogAllowed = allowed.includes("pg_catalog");
  const relations: RelationRef[] = [];
  for (const stmt of ast) {
    const { relations: rels, calls } = relationsOf(stmt);
    relations.push(...rels);
    for (const fn of calls) {
      const n = fn.toLowerCase();
      if (SQL_TEXT_FUNCTIONS.includes(n)) {
        return { ok: false, relations, reason: `Function ${n}() runs SQL from a string, which the schema guard cannot inspect; blocked` };
      }
    }
    for (const r of rels) {
      if (r.schema !== null) {
        if (!allowed.includes(r.schema)) {
          return { ok: false, relations, reason: `Schema '${r.schema}' is not allowed for this role (allowed_schemas: ${fmtAllowed(allowed)})` };
        }
      } else if (r.name.toLowerCase().startsWith("pg_") && !catalogAllowed) {
        return {
          ok: false,
          relations,
          reason: `Unqualified relation '${r.name}' resolves to pg_catalog, which is not in allowed_schemas (${fmtAllowed(allowed)}); rename the CTE or qualify the table`,
        };
      }
    }
    const qn: { schema: string; name: string }[] = [];
    qualifiedNames(stmt, qn);
    for (const q of qn) {
      if (q.schema === "pg_catalog" || allowed.includes(q.schema)) continue;
      return { ok: false, relations, reason: `Schema '${q.schema}' (in ${q.schema}.${q.name}) is not allowed for this role (allowed_schemas: ${fmtAllowed(allowed)})` };
    }
  }
  return { ok: true, relations };
}

/** Strip a leading `EXPLAIN [ ( options ) ] [ANALYZE] [VERBOSE]` so the explained statement can be checked. */
export function stripExplain(sql: string): string {
  let s = sql.trim();
  const m = /^explain\b\s*/i.exec(s);
  if (!m) return s;
  s = s.slice(m[0].length);
  if (s.startsWith("(")) {
    const close = s.indexOf(")");
    s = close < 0 ? "" : s.slice(close + 1).trimStart();
  }
  for (;;) {
    const kw = /^(analyze|analyse|verbose)\b\s*/i.exec(s);
    if (!kw) break;
    s = s.slice(kw[0].length);
  }
  return s;
}

/** `"corp", "sales"` — a search_path value safe to pass to set_config. */
export function searchPathValue(schemas: readonly string[]): string {
  for (const s of schemas) {
    if (!SCHEMA_IDENT_RE.test(s)) throw new Error(`Refusing invalid schema name in search_path: ${s}`);
  }
  return schemas.map((s) => `"${s}"`).join(", ");
}
