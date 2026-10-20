import { z } from "zod";
import type { AppContext } from "./context.js";
import { approvalRuntime, credsForPolicy } from "./context.js";
import { approvalRequired, checkApproval, effectiveAffectedCap, privateKeyInServerEnv } from "../approvals/gate.js";
import { ApprovalError, sqlSha256, type ApprovalClaims, type ApprovalScope, type ApprovalTool } from "../approvals/token.js";
import {
  AffectedRowsCapExceeded,
  withClient,
  withDmlTransaction,
  withReadOnlyTransaction,
} from "../db/pool.js";
import { tierFromAllow, type PreflightResult } from "../db/preflight.js";
import {
  resolvePrincipal,
  gucsForPrincipal,
  type Principal,
} from "../auth/principal.js";
import {
  ping,
  listSchemas,
  listTables,
  describeTable,
  capRows,
  effectiveMaxRows,
  fetchCapped,
  runUserSql,
  type CappedResult,
} from "../db/queries.js";
import {
  assertCapability,
  checkSchemas,
  classifySql,
  filterSchemas,
  isDdl,
  isDml,
  isSchemaAllowed,
  isSelect,
  stripExplain,
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

const approvalProps = {
  approval_id: {
    type: "string" as const,
    description: "Phase 4: id returned by request_approval; the server loads the human-signed token once it is approved.",
  },
  approval_token: {
    type: "string" as const,
    description: "Phase 4: signed approval token (pga1....) minted out of band by `npm run approvals -- approve`.",
  },
};

const bearerTokenProp = {
  bearer_token: {
    type: "string" as const,
    description:
      "End-user JWT (HS256, verified with PGGUARD_JWT_SECRET; required by default). Sets RLS session GUCs. Or env PGGUARD_BEARER_TOKEN.",
  },
};

type TxnOpts = {
  sessionGucs?: Record<string, string>;
  timeouts: AppContext["policy"]["readTxn"];
  searchPath?: readonly string[] | null;
};

function sessionOpts(ctx: AppContext, args: Record<string, unknown>): {
  principal: Principal | null;
  withOpts: TxnOpts;
  readOpts: TxnOpts;
  principalSub?: string;
} {
  const timeouts = ctx.policy.readTxn;
  const searchPath = ctx.policy.searchPath ?? undefined;
  const principal = resolvePrincipal(args, ctx.policy.principalPropagation);
  if (!principal) {
    return { principal: null, withOpts: { timeouts, searchPath }, readOpts: { timeouts, searchPath } };
  }
  const sessionGucs = gucsForPrincipal(principal, ctx.policy.principalPropagation);
  return {
    principal,
    withOpts: { sessionGucs, timeouts, searchPath },
    readOpts: { sessionGucs, timeouts, searchPath },
    principalSub: principal.sub,
  };
}

/** Schema guard; returns an error message or null. */
function schemaDenied(ctx: AppContext, sql: string): string | null {
  const g = checkSchemas(sql, ctx.policy.allowedSchemas);
  return g.ok ? null : g.reason || "Schema not allowed";
}

function schemaArgDenied(ctx: AppContext, schema: string): string | null {
  return isSchemaAllowed(schema, ctx.policy.allowedSchemas)
    ? null
    : `Schema '${schema}' is not allowed for this role (allowed_schemas: ${(ctx.policy.allowedSchemas || []).join(", ") || "(none)"})`;
}

/** Scope a token must match, built from the live call (never from the token). */
function approvalScope(
  ctx: AppContext,
  tool: ApprovalTool,
  sql: string,
  database: string,
  principalSub: string | undefined,
): ApprovalScope {
  return {
    tool,
    role: ctx.policy.roleName,
    db_user: ctx.policy.role.db_user,
    database,
    sub: principalSub ?? null,
    sql_sha256: sqlSha256(sql),
  };
}

function approvalAudit(c: ApprovalClaims) {
  return { approval: { jti: c.jti, rid: c.rid, approver: c.approver, exp: c.exp, max_affected_rows: c.max_affected_rows } };
}

function capsMeta(r: CappedResult, caps: { maxRows: number; maxResultBytes: number; maxCellBytes: number }) {
  return {
    truncated: r.truncated,
    ...(r.truncated ? { truncated_by: r.truncatedBy } : {}),
    ...(r.truncatedCells ? { truncated_cells: r.truncatedCells, truncated_columns: r.truncatedColumns } : {}),
    result_bytes: r.resultBytes,
    max_rows: caps.maxRows,
    max_result_bytes: caps.maxResultBytes,
    max_cell_bytes: caps.maxCellBytes,
  };
}

export const toolDefs = [
  {
    name: "db_health",
    description: "Ping Postgres and return server version",
    inputSchema: {
      type: "object" as const,
      properties: { ...bearerTokenProp },
      additionalProperties: false,
    },
  },
  {
    name: "list_schemas",
    description: "List non-system schemas (only the role's allowed_schemas when configured)",
    inputSchema: {
      type: "object" as const,
      properties: { ...bearerTokenProp },
      additionalProperties: false,
    },
  },
  {
    name: "list_tables",
    description: "List tables, optionally filtered by schema",
    inputSchema: {
      type: "object" as const,
      properties: {
        schema: { type: "string", description: "Schema name (optional)" },
        ...bearerTokenProp,
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
        ...bearerTokenProp,
      },
      required: ["schema", "table"],
      additionalProperties: false,
    },
  },
  {
    name: "run_select",
    description:
      "Run a single SELECT in a READ ONLY transaction. Only allowed_schemas may be referenced. Rows are capped at min(max_rows, policy max_rows) and by max_result_bytes / max_cell_bytes; the response says truncated: true when a cap applied.",
    inputSchema: {
      type: "object" as const,
      properties: {
        sql: { type: "string" },
        max_rows: { type: "number" },
        ...bearerTokenProp,
      },
      required: ["sql"],
      additionalProperties: false,
    },
  },
  {
    name: "run_dml",
    description:
      "INSERT/UPDATE/DELETE when role allows. dry_run:true runs it in a rolled-back transaction and returns the affected row count (no confirm needed). Real runs require confirm:true and are rolled back if they affect more than the role's max_affected_rows.",
    inputSchema: {
      type: "object" as const,
      properties: {
        sql: { type: "string" },
        confirm: { type: "boolean" },
        dry_run: { type: "boolean", description: "Preview: execute, report rowCount (and RETURNING sample), then ROLLBACK" },
        ...approvalProps,
        ...bearerTokenProp,
      },
      required: ["sql"],
      additionalProperties: false,
    },
  },
  {
    name: "run_ddl",
    description: "CREATE/ALTER/DROP for migrator/admin; requires confirm:true (and an out-of-band approval when policy requires it); optional dry_run",
    inputSchema: {
      type: "object" as const,
      properties: {
        sql: { type: "string" },
        confirm: { type: "boolean" },
        dry_run: { type: "boolean" },
        ...approvalProps,
        ...bearerTokenProp,
      },
      required: ["sql"],
      additionalProperties: false,
    },
  },
  {
    name: "request_approval",
    description:
      "Phase 4: ask a human to approve one exact DML/DDL statement. Returns approval_id and the SQL sha256; a human approves out of band with `npm run approvals -- approve <approval_id>` (the server cannot). DML requests include a rolled-back dry-run row count for the approver.",
    inputSchema: {
      type: "object" as const,
      properties: {
        tool: { type: "string", enum: ["run_dml", "run_ddl"] },
        sql: { type: "string", description: "Exact SQL to run later; any byte change needs a new approval" },
        reason: { type: "string", description: "Why the change is needed (shown to the approver)" },
        ...bearerTokenProp,
      },
      required: ["tool", "sql"],
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
        ...bearerTokenProp,
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
    description: "Current agent role, effective policy, and optional JWT principal",
    inputSchema: {
      type: "object" as const,
      properties: { ...bearerTokenProp },
      additionalProperties: false,
    },
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
        const { readOpts, principalSub } = sessionOpts(ctx, args);
        const creds = await credsForPolicy(ctx);
        const result = await withReadOnlyTransaction(creds, (c) => ping(c), readOpts);
        ctx.audit.append({
          tool: name,
          role,
          principal: principalSub,
          ok: true,
          detail: { version: result.version },
        });
        return textResult(result);
      }
      case "list_schemas": {
        assertCapability(ctx.policy, "introspect");
        const { readOpts, principalSub } = sessionOpts(ctx, args);
        const creds = await credsForPolicy(ctx);
        const all = await withReadOnlyTransaction(creds, (c) => listSchemas(c), readOpts);
        const schemas = filterSchemas(all, ctx.policy.allowedSchemas, (s) => s);
        ctx.audit.append({
          tool: name,
          role,
          principal: principalSub,
          ok: true,
          detail: { count: schemas.length },
        });
        return textResult({ schemas });
      }
      case "list_tables": {
        assertCapability(ctx.policy, "introspect");
        const schema = typeof args.schema === "string" ? args.schema : undefined;
        const denied = schema !== undefined ? schemaArgDenied(ctx, schema) : null;
        if (denied) {
          ctx.audit.append({ tool: name, role, ok: false, error: denied, detail: { schema } });
          return errResult(denied);
        }
        const { readOpts, principalSub } = sessionOpts(ctx, args);
        const creds = await credsForPolicy(ctx);
        const tables = filterSchemas(
          await withReadOnlyTransaction(creds, (c) => listTables(c, schema), readOpts),
          ctx.policy.allowedSchemas,
          (t) => t.schema,
        );
        ctx.audit.append({
          tool: name,
          role,
          principal: principalSub,
          ok: true,
          detail: { count: tables.length, schema },
        });
        return textResult({ tables });
      }
      case "describe_table": {
        assertCapability(ctx.policy, "introspect");
        const schema = z.string().parse(args.schema);
        const table = z.string().parse(args.table);
        const deniedSchema = schemaArgDenied(ctx, schema);
        if (deniedSchema) {
          ctx.audit.append({ tool: name, role, ok: false, error: deniedSchema, detail: { schema, table } });
          return errResult(deniedSchema);
        }
        const { readOpts, principalSub } = sessionOpts(ctx, args);
        const creds = await credsForPolicy(ctx);
        const columns = await withReadOnlyTransaction(
          creds,
          (c) => describeTable(c, schema, table),
          readOpts,
        );
        ctx.audit.append({
          tool: name,
          role,
          principal: principalSub,
          ok: true,
          detail: { schema, table },
        });
        return textResult({ schema, table, columns });
      }
      case "run_select": {
        assertCapability(ctx.policy, "select");
        const sql = z.string().parse(args.sql);
        const maxRows = effectiveMaxRows(args.max_rows, ctx.policy.maxRows);
        const cls = classifySql(sql, ctx.policy.config.dangerous_functions);
        if (!cls.ok || !isSelect(cls.statementClass)) {
          const msg = cls.reason || `Expected SELECT, got ${cls.statementClass}`;
          ctx.audit.append({ tool: name, role, ok: false, error: msg, sqlPreview: sql });
          return errResult(msg);
        }
        const denied = schemaDenied(ctx, sql);
        if (denied) {
          ctx.audit.append({ tool: name, role, ok: false, error: denied, sqlPreview: sql });
          return errResult(denied);
        }
        const caps = { maxRows, maxResultBytes: ctx.policy.maxResultBytes, maxCellBytes: ctx.policy.maxCellBytes };
        const { readOpts, principalSub } = sessionOpts(ctx, args);
        const creds = await credsForPolicy(ctx);
        // Server-side cursor: FETCH up to max_rows+1 and stop at the byte budget.
        const r = await withReadOnlyTransaction(creds, (c) => fetchCapped(c, sql, caps), readOpts);
        const meta = capsMeta(r, caps);
        ctx.audit.append({
          tool: name,
          role,
          principal: principalSub,
          ok: true,
          sqlPreview: sql,
          detail: { rowCount: r.rowCount, ...meta },
        });
        return textResult({ rowCount: r.rowCount, ...meta, rows: r.rows });
      }
      case "run_dml": {
        assertCapability(ctx.policy, "dml");
        const sql = z.string().parse(args.sql);
        const confirm = Boolean(args.confirm);
        const dryRun = Boolean(args.dry_run);
        if (!dryRun && ctx.policy.requireConfirmDml && !confirm) {
          const msg = "DML requires confirm: true (or preview it first with dry_run: true)";
          ctx.audit.append({ tool: name, role, ok: false, error: msg, sqlPreview: sql });
          return errResult(msg);
        }
        const cls = classifySql(sql, ctx.policy.config.dangerous_functions);
        if (!cls.ok || !isDml(cls.statementClass)) {
          const msg = cls.reason || `Expected DML, got ${cls.statementClass}`;
          ctx.audit.append({ tool: name, role, ok: false, error: msg, sqlPreview: sql });
          return errResult(msg);
        }
        const dmlDenied = schemaDenied(ctx, sql);
        if (dmlDenied) {
          ctx.audit.append({ tool: name, role, ok: false, error: dmlDenied, sqlPreview: sql });
          return errResult(dmlDenied);
        }
        const { readOpts, principalSub } = sessionOpts(ctx, args);
        const creds = await credsForPolicy(ctx);
        // Phase 4: real runs need a human-signed, single-use, SQL-bound approval.
        let claims: ApprovalClaims | null = null;
        const rt = approvalRuntime(ctx);
        if (!dryRun && approvalRequired(rt.policy, "dml")) {
          try {
            claims = checkApproval(rt, args, approvalScope(ctx, "run_dml", sql, creds.database, principalSub));
            if (rt.ledger.kind === "file") await rt.ledger.consume(claims);
          } catch (e) {
            if (!(e instanceof ApprovalError)) throw e;
            ctx.audit.append({ tool: name, role, principal: principalSub, ok: false, error: e.message, sqlPreview: sql, detail: { approval_error: e.code } });
            return errResult(e.message);
          }
        }
        const maxAffectedRows = effectiveAffectedCap(ctx.policy.maxAffectedRows, claims);
        const pgConsume = claims && rt.ledger.kind === "postgres" ? claims : null;
        try {
          const r = await withDmlTransaction(creds, sql, {
            sessionGucs: readOpts.sessionGucs,
            timeouts: ctx.policy.readTxn,
            searchPath: readOpts.searchPath,
            maxAffectedRows,
            dryRun,
            ...(pgConsume ? { beforeStatement: (c: import("pg").PoolClient) => rt.ledger.consume(pgConsume, c) } : {}),
          });
          const out = {
            ok: true,
            rowCount: r.rowCount,
            command: r.command,
            class: cls.statementClass,
            dry_run: r.dryRun,
            committed: r.committed,
            max_affected_rows: maxAffectedRows,
            ...(r.dryRun ? { would_exceed_cap: r.capExceeded, sample: r.sample } : {}),
          };
          ctx.audit.append({
            tool: name,
            role,
            principal: principalSub,
            ok: true,
            sqlPreview: sql,
            detail: {
              rowCount: r.rowCount,
              command: r.command,
              class: cls.statementClass,
              dry_run: r.dryRun,
              committed: r.committed,
              max_affected_rows: maxAffectedRows,
              ...(claims ? approvalAudit(claims) : {}),
            },
          });
          return textResult(claims ? { ...out, approval: { rid: claims.rid, approver: claims.approver, consumed: r.committed } } : out);
        } catch (e) {
          if (e instanceof AffectedRowsCapExceeded) {
            ctx.audit.append({
              tool: name,
              role,
              principal: principalSub,
              ok: false,
              error: e.message,
              sqlPreview: sql,
              detail: { rowCount: e.rowCount, max_affected_rows: e.maxAffectedRows, committed: false },
            });
            return errResult(e.message);
          }
          if (e instanceof ApprovalError) {
            ctx.audit.append({ tool: name, role, principal: principalSub, ok: false, error: e.message, sqlPreview: sql, detail: { approval_error: e.code } });
            return errResult(e.message);
          }
          throw e;
        }
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
        const ddlDenied = schemaDenied(ctx, sql);
        if (ddlDenied) {
          ctx.audit.append({ tool: name, role, ok: false, error: ddlDenied, sqlPreview: sql });
          return errResult(ddlDenied);
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
        const { withOpts, principalSub } = sessionOpts(ctx, args);
        const creds = await credsForPolicy(ctx);
        let ddlClaims: ApprovalClaims | null = null;
        const ddlRt = approvalRuntime(ctx);
        if (approvalRequired(ddlRt.policy, "ddl")) {
          try {
            ddlClaims = checkApproval(ddlRt, args, approvalScope(ctx, "run_ddl", sql, creds.database, principalSub));
            // DDL may run in autocommit (CREATE INDEX CONCURRENTLY), so the approval is spent first.
            if (ddlRt.ledger.kind === "file") await ddlRt.ledger.consume(ddlClaims);
            else {
              const c0 = ddlClaims;
              await withClient(creds, (c) => ddlRt.ledger.consume(c0, c), { timeouts: ctx.policy.readTxn });
            }
          } catch (e) {
            if (!(e instanceof ApprovalError)) throw e;
            ctx.audit.append({ tool: name, role, principal: principalSub, ok: false, error: e.message, sqlPreview: sql, detail: { approval_error: e.code } });
            return errResult(e.message);
          }
        }
        const result = await withClient(
          creds,
          async (c) => {
            const r = await c.query(sql);
            return { rowCount: r.rowCount ?? 0, command: r.command };
          },
          withOpts,
        );
        ctx.audit.append({
          tool: name,
          role,
          principal: principalSub,
          ok: true,
          sqlPreview: sql,
          detail: { ...result, class: cls.statementClass, ...(ddlClaims ? approvalAudit(ddlClaims) : {}) },
        });
        return textResult({
          ok: true,
          ...result,
          class: cls.statementClass,
          ...(ddlClaims ? { approval: { rid: ddlClaims.rid, approver: ddlClaims.approver, consumed: true } } : {}),
        });
      }
      case "request_approval": {
        const tool = z.enum(["run_dml", "run_ddl"]).parse(args.tool);
        const sql = z.string().min(1).parse(args.sql);
        const reason = args.reason === undefined ? undefined : z.string().max(2000).parse(args.reason);
        assertCapability(ctx.policy, tool === "run_dml" ? "dml" : "ddl");
        const cls = classifySql(sql, ctx.policy.config.dangerous_functions);
        const kindOk = tool === "run_dml" ? isDml(cls.statementClass) : isDdl(cls.statementClass);
        if (!cls.ok || !kindOk) {
          const msg = cls.reason || `Expected ${tool === "run_dml" ? "DML" : "DDL"}, got ${cls.statementClass}`;
          ctx.audit.append({ tool: name, role, ok: false, error: msg, sqlPreview: sql });
          return errResult(msg);
        }
        const reqDenied = schemaDenied(ctx, sql);
        if (reqDenied) {
          ctx.audit.append({ tool: name, role, ok: false, error: reqDenied, sqlPreview: sql });
          return errResult(reqDenied);
        }
        const { readOpts, principalSub } = sessionOpts(ctx, args);
        const creds = await credsForPolicy(ctx);
        let preview: { rowCount: number; would_exceed_cap: boolean; max_affected_rows: number } | undefined;
        if (tool === "run_dml") {
          const r = await withDmlTransaction(creds, sql, {
            sessionGucs: readOpts.sessionGucs,
            timeouts: ctx.policy.readTxn,
            searchPath: readOpts.searchPath,
            maxAffectedRows: ctx.policy.maxAffectedRows,
            dryRun: true,
          });
          preview = { rowCount: r.rowCount, would_exceed_cap: r.capExceeded, max_affected_rows: ctx.policy.maxAffectedRows };
        }
        const rt = approvalRuntime(ctx);
        const scope = approvalScope(ctx, tool, sql, creds.database, principalSub);
        const req = rt.queue.create({ ...scope, sql, reason, preview });
        ctx.audit.append({
          tool: name,
          role,
          principal: principalSub,
          ok: true,
          sqlPreview: sql,
          detail: { rid: req.rid, sql_sha256: req.sql_sha256, for_tool: tool, preview },
        });
        return textResult({
          ok: true,
          approval_id: req.rid,
          status: "pending",
          sql_sha256: req.sql_sha256,
          for_tool: tool,
          ...(preview ? { preview } : {}),
          approvals_required: approvalRequired(rt.policy, tool === "run_dml" ? "dml" : "ddl"),
          next: `A human runs: npm run approvals -- approve ${req.rid} --approver <name>. Then call ${tool} with the same sql, confirm: true and approval_id: "${req.rid}".`,
        });
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
        const explainDenied = schemaDenied(ctx, stripExplain(sql));
        if (explainDenied) {
          ctx.audit.append({ tool: name, role, ok: false, error: explainDenied, sqlPreview: sql });
          return errResult(explainDenied);
        }
        let explainSql = sql.trim();
        if (!/^explain/i.test(explainSql)) {
          explainSql = analyze ? `EXPLAIN (ANALYZE, BUFFERS) ${explainSql}` : `EXPLAIN ${explainSql}`;
        } else if (analyze && !/analyze/i.test(explainSql)) {
          explainSql = explainSql.replace(/^explain/i, "EXPLAIN (ANALYZE, BUFFERS)");
        }
        // READ ONLY also means EXPLAIN ANALYZE of a DML statement is rejected by Postgres.
        const { readOpts, principalSub } = sessionOpts(ctx, args);
        const creds = await credsForPolicy(ctx);
        const planRows = await withReadOnlyTransaction(
          creds,
          async (c) => {
            const r = await runUserSql(c, explainSql);
            return r.rows;
          },
          readOpts,
        );
        // Plans can be large (EXPLAIN VERBOSE on wide views); same byte caps as run_select.
        const capped = capRows(planRows, {
          maxRows: Math.max(planRows.length, 1),
          maxResultBytes: ctx.policy.maxResultBytes,
          maxCellBytes: ctx.policy.maxResultBytes,
        });
        const plan = capped.rows;
        ctx.audit.append({
          tool: name,
          role,
          principal: principalSub,
          ok: true,
          sqlPreview: explainSql,
          detail: { analyze, truncated: capped.truncated },
        });
        return textResult(capped.truncated ? { plan, truncated: true, truncated_by: capped.truncatedBy } : { plan });
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
        const { principal } = sessionOpts(ctx, args);
        const preflight: PreflightResult | null = ctx.preflight ?? null;
        return textResult({
          role: p.roleName,
          db_user: p.role.db_user,
          description: p.role.description,
          allow: p.role.allow,
          deny: p.role.deny,
          max_rows: p.maxRows,
          max_affected_rows: p.maxAffectedRows,
          require_confirm_dml: p.requireConfirmDml,
          require_confirm_ddl: p.requireConfirmDdl,
          allow_explain_analyze: p.allowExplainAnalyze,
          dual_control_ddl: p.dualControlDdl,
          approvals: {
            required_for: p.approvals.requiredFor,
            public_key_configured: Boolean(approvalRuntime(ctx).publicKey),
            ledger: p.approvals.ledger,
            max_ttl_seconds: p.approvals.maxTtlSeconds,
            private_key_env_in_server: privateKeyInServerEnv(),
          },
          allowed_schemas: p.allowedSchemas,
          search_path: p.searchPath,
          max_result_bytes: p.maxResultBytes,
          max_cell_bytes: p.maxCellBytes,
          read_transaction: {
            read_only: true,
            statement_timeout_ms: p.readTxn.statementTimeoutMs,
            lock_timeout_ms: p.readTxn.lockTimeoutMs,
            idle_in_transaction_session_timeout_ms: p.readTxn.idleInTransactionSessionTimeoutMs,
          },
          secrets_provider: process.env.PGGUARD_SECRETS_PROVIDER || "env",
          principal: principal
            ? { sub: principal.sub, email: principal.email }
            : null,
          principal_propagation: {
            enabled: p.principalPropagation.enabled,
            require_jwt: p.principalPropagation.require_jwt,
            session_gucs: p.principalPropagation.session_gucs,
          },
          db_preflight: preflight
            ? {
                ok: preflight.ok,
                tier: preflight.tier,
                checks: preflight.checks,
                error: preflight.error,
              }
            : {
                ok: null,
                note: "preflight not run (server started without DB check, or whoami in unit tests)",
                expected_tier: tierFromAllow(p.role.allow),
              },
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
