#!/usr/bin/env node
/**
 * PgGuard Agent — MCP server over stdio.
 * Logs go to stderr; stdout is reserved for MCP JSON-RPC.
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { approvalRuntime, createAppContext, credsForPolicy } from "./mcp/context.js";
import { privateKeyInServerEnv } from "./approvals/gate.js";
import { handleTool, toolDefs } from "./mcp/tools.js";
import { closePool } from "./db/pool.js";
import { assertPreflight, tierFromAllow } from "./db/preflight.js";
import { log } from "./utils/logger.js";

async function main(): Promise<void> {
  const ctx = createAppContext();
  log("info", "pgguard_starting", {
    role: ctx.policy.roleName,
    db_user: ctx.policy.role.db_user,
  });

  // Phase 4 separation of duties: the approver's signing key must never be in the
  // server's environment (anything driving the tools could then mint approvals).
  const leaked = privateKeyInServerEnv();
  if (leaked.length) {
    throw new Error(`Refusing to start: approver private key env present in server env (${leaked.join(", ")})`);
  }
  const approvals = approvalRuntime(ctx);
  if (approvals.policy.requiredFor.length && !approvals.publicKey) {
    log("warn", "approvals_not_configured", {
      required_for: approvals.policy.requiredFor,
      note: `no ${approvals.policy.publicKeyEnv}; real ${approvals.policy.requiredFor.join("/")} runs will be refused`,
    });
  }

  // Phase 5: credsForPolicy has already checked the host against network.allowed_db_hosts,
  // pinned the resolved address and enforced sslmode=verify-full for non-loopback hosts.
  log("info", "pgguard_network", {
    enforced: ctx.policy.network.enforced,
    audit_chain: ctx.audit.alg,
  });

  // Fail closed: refuse to start if the DB role is superuser/BYPASSRLS, missing
  // statement_timeout, wrong default_transaction_read_only for the tier, or if
  // dblink/postgres_fdw are installed. Apply scripts/provision-roles.sql first.
  const creds = await credsForPolicy(ctx);
  const preflight = await assertPreflight(creds, {
    tier: tierFromAllow(ctx.policy.role.allow),
    requireSsl: (creds.sslmode || "").toLowerCase() === "verify-full",
  });
  ctx.preflight = preflight;
  log("info", "pgguard_preflight_ok", {
    db_user: preflight.db_user,
    tier: preflight.tier,
    checks: preflight.checks.map((c) => c.name),
  });

  const server = new Server(
    { name: "pgguard-agent", version: "1.0.0" },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: toolDefs.map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
    })),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const name = request.params.name;
    const args = (request.params.arguments || {}) as Record<string, unknown>;
    log("debug", "tool_call", { tool: name });
    return handleTool(ctx, name, args);
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
  log("info", "pgguard_ready", { transport: "stdio" });

  const shutdown = async () => {
    log("info", "pgguard_shutdown", {});
    await closePool();
    process.exit(0);
  };
  process.on("SIGINT", () => void shutdown());
  process.on("SIGTERM", () => void shutdown());
}

main().catch((err) => {
  log("error", "fatal", { error: err instanceof Error ? err.message : String(err) });
  process.exit(1);
});
