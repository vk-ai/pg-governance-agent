import { z } from "zod";
import type { AppContext } from "./context.js";
import { credsForPolicy } from "./context.js";
import { withClient } from "../db/pool.js";
import {
  ping,
  listSchemas,
  listTables,
  describeTable,
  enforceMaxRows,
} from "../db/queries.js";
import {
  assertCapability,
  classifySql,
  isDdl,
  isDml,
  isSelect,
} from "../policy/index.js";

function textResult(data: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
  };
}

function errResult(message: string) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify({ ok: false, error: message }, null, 2) }],
    isError: true,
  };
}

export const toolDefs = [
  {
    name: "db_health",
    description: "Ping Postgres and return server version",
    inputSchema: { type: "object" as const, properties: {}, additionalProperties: false },
  },
  {
    name: "list_schemas",
    description: "List non-system schemas",
    inputSchema: { type: "object" as const, properties: {}, additionalProperties: false },
  },
  {
    name: "list_tables",
    description: "List tables, optionally filtered by schema",
    inputSchema: {
      type: "object" as const,
      properties: {
        schema: { type: "string", description: "Schema name (optional)" },
      },
      additionalProperties: false,
    },
  },
  {
    name: "describe_table",
    description: "Describe columns for a table",
    inputSchema: {
      type: "object" as const,
      properties: {
        schema: { type: "string" },
        table: { type: "string" },
      },
      required: ["schema", "table"],
      additionalProperties: false,
    },
  },
  {
    name: "run_select",
    description: "Run a single SELECT (max rows enforced; read-only role preferred)",
    inputSchema: {
      type: "object" as const,
      properties: {
        sql: { type: "string" },
        max_rows: { type: "number" },
      },
      required: ["sql"],
      additionalProperties: false,
    },
  },
  {
    name: "run_dml",
    description: "INSERT/UPDATE/DELETE when role allows; requires confirm:true",
    inputSchema: {
      type: "object" as const,
      properties: {
        sql: { type: "string" },
        confirm: { type: "boolean" },
      },
      required: ["sql", "confirm"],
      additionalProperties: false,
    },
  },
  {
    name: "run_ddl",
    description: "CREATE/ALTER/DROP for migrator/admin; requires confirm:true; optional dry_run",
    inputSchema: {
      type: "object" as const,
      properties: {
        sql: { type: "string" },
        confirm: { type: "boolean" },
        dry_run: { type: "boolean" },
      },
      required: ["sql"],
      additionalProperties: false,
    },
  },
  {
    name: "explain_query",
    description: "EXPLAIN a query; ANALYZE optional and gated by policy",
    inputSchema: {
      type: "object" as const,
      properties: {
        sql: { type: "string" },
        analyze: { type: "boolean" },
      },
      required: ["sql"],
      additionalProperties: false,
    },
  },
  {
    name: "get_audit_tail",
    description: "Return last N append-only audit events",
    inputSchema: {
      type: "object" as const,
      properties: {
        n: { type: "number", description: "Number of events (default 20)" },
      },
      additionalProperties: false,
    },
  },
  {
    name: "whoami",
    description: "Current agent role and effective policy",
    inputSchema: { type: "object" as const, properties: {}, additionalProperties: false },
  },
] as const;

export async function handleTool(
  ctx: AppContext,
  name: string,
  args: Record<string, unknown>,
): Promise<{ content: { type: "text"; text: string }[]; isError?: boolean }> {
  const role = ctx.policy.roleName;
  try {
    switch (name) {
      case "db_health": {
        assertCapability(ctx.policy, "health");
        const creds = await credsForPolicy(ctx);
        const result = await withClient(creds, (c) => ping(c));
        ctx.audit.append({ tool: name, role, ok: true, detail: { version: result.version } });
        return textResult(result);
      }
      case "list_schemas": {
        assertCapability(ctx.policy, "introspect");
        const creds = await credsForPolicy(ctx);
        const schemas = await withClient(creds, (c) => listSchemas(c));
        ctx.audit.append({ tool: name, role, ok: true, detail: { count: schemas.length } });
        return textResult({ schemas });
      }
      case "list_tables": {
        assertCapability(ctx.policy, "introspect");
        const schema = typeof args.schema === "string" ? args.schema : undefined;
        const creds = await credsForPolicy(ctx);
        const tables = await withClient(creds, (c) => listTables(c, schema));
        ctx.audit.append({ tool: name, role, ok: true, detail: { count: tables.length, schema } });
        return textResult({ tables });
      }
      case "describe_table": {
        assertCapability(ctx.policy, "introspect");
        const schema = z.string().parse(args.schema);
        const table = z.string().parse(args.table);
        const creds = await credsForPolicy(ctx);
        const columns = await withClient(creds, (c) => describeTable(c, schema, table));
        ctx.audit.append({ tool: name, role, ok: true, detail: { schema, table } });
        return textResult({ schema, table, columns });
      }
      case "run_select": {
        assertCapability(ctx.policy, "select");
        const sql = z.string().parse(args.sql);
        const maxRows = Number(args.max_rows ?? ctx.policy.maxRows);
        const cls = classifySql(sql, ctx.policy.config.dangerous_functions);
        if (!cls.ok || !isSelect(cls.statementClass)) {
          const msg = cls.reason || `Expected SELECT, got ${cls.statementClass}`;
          ctx.audit.append({ tool: name, role, ok: false, error: msg, sqlPreview: sql });
          return errResult(msg);
        }
        const limited = enforceMaxRows(sql, maxRows);
        const creds = await credsForPolicy(ctx);
        const rows = await withClient(creds, async (c) => {
          const r = await c.query(limited);
          return r.rows;
        });
        ctx.audit.append({
          tool: name,
          role,
          ok: true,
          sqlPreview: limited,
          detail: { rowCount: rows.length, maxRows },
        });
        return textResult({ rowCount: rows.length, rows });
      }
      case "run_dml": {
        assertCapability(ctx.policy, "dml");
        const sql = z.string().parse(args.sql);
        const confirm = Boolean(args.confirm);
        if (ctx.policy.requireConfirmDml && !confirm) {
          const msg = "DML requires confirm: true";
          ctx.audit.append({ tool: name, role, ok: false, error: msg, sqlPreview: sql });
          return errResult(msg);
        }
        const cls = classifySql(sql, ctx.policy.config.dangerous_functions);
        if (!cls.ok || !isDml(cls.statementClass)) {
          const msg = cls.reason || `Expected DML, got ${cls.statementClass}`;
          ctx.audit.append({ tool: name, role, ok: false, error: msg, sqlPreview: sql });
          return errResult(msg);
        }
        const creds = await credsForPolicy(ctx);
        const result = await withClient(creds, async (c) => {
          const r = await c.query(sql);
          return { rowCount: r.rowCount ?? 0, command: r.command };
        });
        ctx.audit.append({
          tool: name,
          role,
          ok: true,
          sqlPreview: sql,
          detail: { ...result, class: cls.statementClass },
        });
        return textResult({ ok: true, ...result, class: cls.statementClass });
      }
      case "run_ddl": {
        assertCapability(ctx.policy, "ddl");
        const sql = z.string().parse(args.sql);
        const confirm = Boolean(args.confirm);
        const dryRun = Boolean(args.dry_run);
        const cls = classifySql(sql, ctx.policy.config.dangerous_functions);
        if (!cls.ok || !isDdl(cls.statementClass)) {
          const msg = cls.reason || `Expected DDL, got ${cls.statementClass}`;
          ctx.audit.append({ tool: name, role, ok: false, error: msg, sqlPreview: sql });
          return errResult(msg);
        }
        if (dryRun) {
          ctx.audit.append({
            tool: name,
            role,
            ok: true,
            sqlPreview: sql,
            detail: { dry_run: true, class: cls.statementClass },
          });
          return textResult({
            ok: true,
            dry_run: true,
            class: cls.statementClass,
            message: "Parsed/validated as DDL; not executed",
            dual_control: ctx.policy.dualControlDdl,
          });
        }
        if (ctx.policy.requireConfirmDdl && !confirm) {
          const msg = ctx.policy.dualControlDdl
            ? "DDL requires confirm: true (dual-control)"
            : "DDL requires confirm: true";
          ctx.audit.append({ tool: name, role, ok: false, error: msg, sqlPreview: sql });
          return errResult(msg);
        }
        const creds = await credsForPolicy(ctx);
        const result = await withClient(creds, async (c) => {
          const r = await c.query(sql);
          return { rowCount: r.rowCount ?? 0, command: r.command };
        });
        ctx.audit.append({
          tool: name,
          role,
          ok: true,
          sqlPreview: sql,
          detail: { ...result, class: cls.statementClass },
        });
        return textResult({ ok: true, ...result, class: cls.statementClass });
      }
      case "explain_query": {
        assertCapability(ctx.policy, "explain");
        const sql = z.string().parse(args.sql);
        const analyze = Boolean(args.analyze);
        if (analyze && !ctx.policy.allowExplainAnalyze) {
          const msg = "EXPLAIN ANALYZE not permitted for this role";
          ctx.audit.append({ tool: name, role, ok: false, error: msg, sqlPreview: sql });
          return errResult(msg);
        }
        // Allow explaining a select or raw explain
        const cls = classifySql(sql, ctx.policy.config.dangerous_functions);
        if (!cls.ok && cls.statementClass === "blocked") {
          ctx.audit.append({ tool: name, role, ok: false, error: cls.reason, sqlPreview: sql });
          return errResult(cls.reason || "Blocked");
        }
        let explainSql = sql.trim();
        if (!/^explain/i.test(explainSql)) {
          explainSql = analyze ? `EXPLAIN (ANALYZE, BUFFERS) ${explainSql}` : `EXPLAIN ${explainSql}`;
        } else if (analyze && !/analyze/i.test(explainSql)) {
          explainSql = explainSql.replace(/^explain/i, "EXPLAIN (ANALYZE, BUFFERS)");
        }
        const creds = await credsForPolicy(ctx);
        const plan = await withClient(creds, async (c) => {
          const r = await c.query(explainSql);
          return r.rows;
        });
        ctx.audit.append({
          tool: name,
          role,
          ok: true,
          sqlPreview: explainSql,
          detail: { analyze },
        });
        return textResult({ plan });
      }
      case "get_audit_tail": {
        assertCapability(ctx.policy, "audit_read");
        const n = Number(args.n ?? 20);
        const events = ctx.audit.tail(n);
        return textResult({ events });
      }
      case "whoami": {
        assertCapability(ctx.policy, "whoami");
        const p = ctx.policy;
        return textResult({
          role: p.roleName,
          db_user: p.role.db_user,
          description: p.role.description,
          allow: p.role.allow,
          deny: p.role.deny,
          max_rows: p.maxRows,
          require_confirm_dml: p.requireConfirmDml,
          require_confirm_ddl: p.requireConfirmDdl,
          allow_explain_analyze: p.allowExplainAnalyze,
          dual_control_ddl: p.dualControlDdl,
          secrets_provider: process.env.PGGUARD_SECRETS_PROVIDER || "env",
        });
      }
      default:
        return errResult(`Unknown tool: ${name}`);
    }
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    ctx.audit.append({ tool: name, role, ok: false, error: message });
    return errResult(message);
  }
}
