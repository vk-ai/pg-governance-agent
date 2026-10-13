/**
 * Function-name checks for agent SQL.
 *
 * Two independent passes, both case-insensitive and quote-aware:
 *  1. AST walk (pgsql-ast-parser): every function call node anywhere in the
 *     statement (WHERE, CTEs, subqueries, select list, ...).
 *  2. A small lexer that skips comments, '...' / E'...' strings and $tag$ bodies,
 *     and reports every (optionally schema-qualified, optionally "quoted")
 *     identifier followed by "(". This also covers SQL the parser cannot read.
 *
 * Neither pass is the security boundary; Postgres grants / READ ONLY are.
 * They exist to deny known-dangerous calls early and explainably.
 */
import { astVisitor, type Statement } from "pgsql-ast-parser";

/** Exact names always blocked, regardless of policy.yaml. */
export const BUILTIN_BLOCKED_FUNCTIONS = [
  "set_config", // rewrites RLS principal / timeouts inside the txn
  "pg_terminate_backend",
  "pg_cancel_backend",
  "pg_sleep",
  "pg_sleep_for",
  "pg_sleep_until",
  "pg_read_file",
  "pg_read_binary_file",
  "pg_write_file",
  "pg_ls_dir",
  "pg_reload_conf",
  "pg_rotate_logfile",
  "lo_import",
  "lo_export",
];

/** Name prefixes always blocked (function families). */
export const BUILTIN_BLOCKED_PREFIXES = [
  "dblink", // dblink, dblink_exec, dblink_connect, dblink_open, ...
  "postgres_fdw", // postgres_fdw_disconnect, postgres_fdw_get_connections, ...
  "pg_advisory", // pg_advisory_lock, pg_advisory_xact_lock_shared, ...
  "pg_try_advisory",
];

/** Substrings: any *fdw* function (postgres_fdw_handler, file_fdw_validator, ...). */
const BLOCKED_SUBSTRINGS = ["fdw"];

export function normalizeIdent(raw: string): string {
  // A quoted identifier keeps its case in Postgres, but the dangerous built-ins
  // are all lower-case, so compare case-insensitively to fail closed.
  return raw.toLowerCase();
}

export function isBlockedFunction(name: string, extra: string[] = []): string | null {
  const n = normalizeIdent(name);
  const exact = new Set([...BUILTIN_BLOCKED_FUNCTIONS, ...extra.map(normalizeIdent)]);
  if (exact.has(n)) return n;
  for (const p of BUILTIN_BLOCKED_PREFIXES) if (n.startsWith(p)) return n;
  for (const s of BLOCKED_SUBSTRINGS) if (n.includes(s)) return n;
  return null;
}

/** All function names called anywhere in a parsed statement. */
export function astFunctionNames(stmt: Statement): string[] {
  const names: string[] = [];
  const v = astVisitor((map) => ({
    call: (c) => {
      names.push(c.function.name);
      map.super().call(c);
    },
  }));
  v.statement(stmt);
  return names;
}

export interface LexToken {
  kind: "ident" | "qident" | "punct";
  value: string;
}

/** Lex SQL into identifiers and punctuation, dropping comments, strings and dollar-quoted bodies. */
export function lexSql(sql: string): LexToken[] {
  const out: LexToken[] = [];
  let i = 0;
  const n = sql.length;
  while (i < n) {
    const ch = sql[i]!;
    const next = sql[i + 1];
    if (/\s/.test(ch)) { i++; continue; }
    if (ch === "-" && next === "-") { while (i < n && sql[i] !== "\n") i++; continue; }
    if (ch === "/" && next === "*") {
      // Postgres block comments nest.
      let depth = 1; i += 2;
      while (i < n && depth > 0) {
        if (sql[i] === "/" && sql[i + 1] === "*") { depth++; i += 2; }
        else if (sql[i] === "*" && sql[i + 1] === "/") { depth--; i += 2; }
        else i++;
      }
      continue;
    }
    if (ch === "'" || ((ch === "E" || ch === "e") && next === "'")) {
      const escapes = ch !== "'";
      i += escapes ? 2 : 1;
      while (i < n) {
        if (escapes && sql[i] === "\\") { i += 2; continue; }
        if (sql[i] === "'") { if (sql[i + 1] === "'") { i += 2; continue; } i++; break; }
        i++;
      }
      continue;
    }
    if (ch === "$") {
      const m = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(sql.slice(i));
      if (m) {
        const tag = m[0];
        const end = sql.indexOf(tag, i + tag.length);
        i = end < 0 ? n : end + tag.length;
        continue;
      }
      i++; continue; // $1 parameter
    }
    if (ch === '"') {
      let v = ""; i++;
      while (i < n) {
        if (sql[i] === '"') { if (sql[i + 1] === '"') { v += '"'; i += 2; continue; } i++; break; }
        v += sql[i]; i++;
      }
      out.push({ kind: "qident", value: v });
      continue;
    }
    if ((ch === "U" || ch === "u") && next === "&" && (sql[i + 2] === '"' || sql[i + 2] === "'")) {
      // U&"d\0062link" can spell any name; refuse to guess.
      out.push({ kind: "ident", value: "u&" });
      i += 2; continue;
    }
    if (/[A-Za-z_\u0080-\uffff]/.test(ch)) {
      let v = "";
      while (i < n && /[A-Za-z0-9_$\u0080-\uffff]/.test(sql[i]!)) { v += sql[i]; i++; }
      out.push({ kind: "ident", value: v.toLowerCase() });
      continue;
    }
    out.push({ kind: "punct", value: ch });
    i++;
  }
  return out;
}

/** Names of every identifier directly followed by "(" (last part of a qualified name). */
export function lexFunctionNames(sql: string): string[] {
  const t = lexSql(sql);
  const names: string[] = [];
  for (let k = 0; k < t.length - 1; k++) {
    const a = t[k]!;
    if ((a.kind === "ident" || a.kind === "qident") && t[k + 1]!.kind === "punct" && t[k + 1]!.value === "(") {
      names.push(a.value);
    }
  }
  return names;
}

/** Keyword sequences (unquoted) that are blocked outright. */
export function lexBlockedKeywords(sql: string): string | null {
  const t = lexSql(sql);
  for (let k = 0; k < t.length; k++) {
    const a = t[k]!;
    if (a.kind === "ident" && a.value === "u&") return "Unicode-escaped identifiers/strings (U&) are blocked";
    if (a.kind !== "ident") continue;
    const b = t[k + 1]?.kind === "ident" ? t[k + 1]!.value : "";
    if (a.value === "foreign" && (b === "table" || b === "data" || b === "schema")) return "Foreign tables / FDWs are blocked";
    if (a.value === "server" && k > 0 && t[k - 1]!.kind === "ident" && ["create", "alter"].includes(t[k - 1]!.value)) {
      return "CREATE/ALTER SERVER is blocked";
    }
    if (a.value === "extension" && k > 0 && t[k - 1]!.kind === "ident" && ["create", "alter"].includes(t[k - 1]!.value)) {
      return "CREATE/ALTER EXTENSION is blocked";
    }
    if (a.value === "user" && b === "mapping") return "USER MAPPING is blocked";
  }
  return null;
}
