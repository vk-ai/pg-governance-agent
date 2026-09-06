import { parse, Statement } from "pgsql-ast-parser";
import type { ClassificationResult, StatementClass } from "./types.js";

const DANGEROUS_FN_DEFAULT = [
  "pg_read_file",
  "pg_write_file",
  "pg_ls_dir",
  "lo_import",
  "lo_export",
  "dblink",
  "dblink_exec",
];

/** Strip SQL comments for heuristic scans. */
export function stripComments(sql: string): string {
  return sql
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/--[^\n]*/g, " ");
}

function hasMultipleStatements(sql: string): boolean {
  const cleaned = stripComments(sql).trim();
  const withoutTrailing = cleaned.replace(/;\s*$/, "");
  return withoutTrailing.includes(";");
}

function heuristicBlocked(sql: string, dangerousFns: string[]): string | null {
  const s = stripComments(sql);
  const upper = s.toUpperCase();

  if (/\bCOPY\b/.test(upper)) return "COPY is blocked";
  if (/\bINTO\s+OUTFILE\b/.test(upper)) return "INTO OUTFILE is blocked";
  if (/\bSET\s+ROLE\b/.test(upper)) return "SET ROLE is blocked";
  if (/\bSET\s+SESSION\s+AUTHORIZATION\b/.test(upper)) return "SET SESSION AUTHORIZATION is blocked";
  if (/\b(CREATE|ALTER|DROP)\s+(USER|ROLE)\b/.test(upper)) return "USER/ROLE DDL is blocked";
  if (/\b(GRANT|REVOKE)\b/.test(upper)) return "GRANT/REVOKE is blocked";

  for (const fn of dangerousFns) {
    const escaped = fn.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp("\\b" + escaped + "\\s*\\(", "i");
    if (re.test(s)) return `Dangerous function blocked: ${fn}`;
  }
  return null;
}

function mapAstType(stmt: Statement): StatementClass {
  const t = String(stmt.type);
  if (t === "select" || t === "union" || t === "union all" || t === "values" || t === "with" || t === "with recursive") {
    return "select";
  }
  if (t === "insert") return "insert";
  if (t === "update") return "update";
  if (t === "delete") return "delete";
  if (t.startsWith("create ")) return "create";
  if (t.startsWith("alter ")) return "alter";
  if (t.startsWith("drop ")) return "drop";
  return "other";
}

function classifyWithHeuristics(sql: string): StatementClass {
  const upper = stripComments(sql).trim().toUpperCase();
  if (upper.startsWith("EXPLAIN")) return "explain";
  if (upper.startsWith("SELECT") || upper.startsWith("WITH")) return "select";
  if (upper.startsWith("INSERT")) return "insert";
  if (upper.startsWith("UPDATE")) return "update";
  if (upper.startsWith("DELETE")) return "delete";
  if (upper.startsWith("CREATE")) return "create";
  if (upper.startsWith("ALTER")) return "alter";
  if (upper.startsWith("DROP")) return "drop";
  return "other";
}

/**
 * Classify SQL for governance: single statement, allowlist classes, block dangerous ops.
 */
export function classifySql(
  sql: string,
  dangerousFunctions: string[] = DANGEROUS_FN_DEFAULT,
): ClassificationResult {
  const trimmed = sql?.trim() ?? "";
  if (!trimmed) {
    return { ok: false, statementClass: "blocked", reason: "Empty SQL", statements: 0 };
  }

  if (hasMultipleStatements(trimmed)) {
    return {
      ok: false,
      statementClass: "blocked",
      reason: "Multiple statements are not allowed",
      statements: 2,
    };
  }

  const blocked = heuristicBlocked(trimmed, dangerousFunctions);
  if (blocked) {
    return { ok: false, statementClass: "blocked", reason: blocked, statements: 1 };
  }

  const upper = stripComments(trimmed).trim().toUpperCase();
  if (upper.startsWith("EXPLAIN")) {
    return { ok: true, statementClass: "explain", statements: 1 };
  }

  try {
    const ast = parse(trimmed);
    if (!ast || ast.length === 0) {
      return { ok: false, statementClass: "blocked", reason: "Unable to parse SQL", statements: 0 };
    }
    if (ast.length > 1) {
      return {
        ok: false,
        statementClass: "blocked",
        reason: "Multiple statements are not allowed",
        statements: ast.length,
      };
    }
    const cls = mapAstType(ast[0]!);
    if (cls === "other") {
      const h = classifyWithHeuristics(trimmed);
      if (h === "other") {
        return {
          ok: false,
          statementClass: "blocked",
          reason: `Unsupported statement type: ${ast[0]!.type}`,
          statements: 1,
        };
      }
      return { ok: true, statementClass: h, statements: 1 };
    }
    return { ok: true, statementClass: cls, statements: 1 };
  } catch {
    const h = classifyWithHeuristics(trimmed);
    if (h === "other") {
      return {
        ok: false,
        statementClass: "blocked",
        reason: "Unrecognized or unsupported SQL",
        statements: 1,
      };
    }
    return { ok: true, statementClass: h, statements: 1 };
  }
}

export function isDml(c: StatementClass): boolean {
  return c === "insert" || c === "update" || c === "delete";
}

export function isDdl(c: StatementClass): boolean {
  return c === "create" || c === "alter" || c === "drop";
}

export function isSelect(c: StatementClass): boolean {
  return c === "select";
}
