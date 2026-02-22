#!/usr/bin/env node
/**
 * OpenClaw GitHub Pro MCP Server
 *
 * Stdio-based MCP server that exposes OpenClaw gateway, skill, Burp, and triage tools
 * to GitHub Pro Agent Mode in VS Code Insiders.
 *
 * Usage:
 *   node dist/server.js          (production — built output)
 *   npx tsx src/server.ts        (development)
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import { openclawTools, handleOpenclawTool } from "./tools/openclaw";
import { jobTools, handleJobTool } from "./tools/jobs";
import { skillTools, handleSkillTool } from "./tools/skills";
import { burpTools, handleBurpTool } from "./tools/burp";
import { triageTools, handleTriageTool } from "./tools/triage";

const ALL_TOOLS = [
  ...openclawTools,
  ...jobTools,
  ...skillTools,
  ...burpTools,
  ...triageTools,
];

// Build a dispatch map: tool name → handler
const HANDLERS: Record<
  string,
  (name: string, args: Record<string, unknown>) => Promise<import("@modelcontextprotocol/sdk/types.js").CallToolResult>
> = {};

for (const tool of openclawTools) HANDLERS[tool.name] = handleOpenclawTool;
for (const tool of jobTools) HANDLERS[tool.name] = handleJobTool;
for (const tool of skillTools) HANDLERS[tool.name] = handleSkillTool;
for (const tool of burpTools) HANDLERS[tool.name] = handleBurpTool;
for (const tool of triageTools) HANDLERS[tool.name] = handleTriageTool;

async function main(): Promise<void> {
  const server = new Server(
    {
      name: "openclaw-github-pro-mcp",
      version: "0.1.0",
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  // List all available tools
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: ALL_TOOLS,
  }));

  // Dispatch tool calls
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const handler = HANDLERS[name];
    if (!handler) {
      return {
        content: [
          { type: "text", text: `Unknown tool: ${name}. Available: ${ALL_TOOLS.map((t) => t.name).join(", ")}` },
        ],
        isError: true,
      };
    }

    try {
      return await handler(name, (args as Record<string, unknown>) || {});
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        content: [{ type: "text", text: `Tool execution error: ${message}` }],
        isError: true,
      };
    }
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);

  // Log to stderr (stdout is reserved for MCP JSON-RPC)
  process.stderr.write(
    `openclaw-github-pro-mcp started (${ALL_TOOLS.length} tools registered, stdio transport only, bridge=${process.env.OPENCLAW_BRIDGE_BASE_URL || "http://127.0.0.1:8787"})\n`
  );
}

main().catch((error) => {
  process.stderr.write(`Fatal: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});
