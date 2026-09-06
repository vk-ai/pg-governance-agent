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
import { createAppContext } from "./mcp/context.js";
import { handleTool, toolDefs } from "./mcp/tools.js";
import { closePool } from "./db/pool.js";
import { log } from "./utils/logger.js";

async function main(): Promise<void> {
  const ctx = createAppContext();
  log("info", "pgguard_starting", {
    role: ctx.policy.roleName,
    db_user: ctx.policy.role.db_user,
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
