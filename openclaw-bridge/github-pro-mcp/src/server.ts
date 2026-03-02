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
  CallToolResult,
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import path from "node:path";

import { openclawTools, handleOpenclawTool } from "./tools/openclaw";
import { jobTools, handleJobTool } from "./tools/jobs";
import { skillTools, handleSkillTool } from "./tools/skills";
import { burpTools, handleBurpTool } from "./tools/burp";
import { triageTools, handleTriageTool } from "./tools/triage";

type JsonObject = Record<string, unknown>;

interface ExecutionRouterLike {
  execute(tool: string, args: JsonObject, context: JsonObject): Promise<{ ok: boolean; code?: string; message?: string; data?: unknown }>;
  listTools(context: JsonObject): Promise<Array<{ name: string; description?: string; inputSchema?: JsonObject }>>;
}

const ALL_TOOLS: Tool[] = [
  ...openclawTools,
  ...jobTools,
  ...skillTools,
  ...burpTools,
  ...triageTools,
];

// Build a dispatch map: tool name → handler
const HANDLERS: Record<
  string,
  (name: string, args: Record<string, unknown>) => Promise<CallToolResult>
> = {};

for (const tool of openclawTools) HANDLERS[tool.name] = handleOpenclawTool;
for (const tool of jobTools) HANDLERS[tool.name] = handleJobTool;
for (const tool of skillTools) HANDLERS[tool.name] = handleSkillTool;
for (const tool of burpTools) HANDLERS[tool.name] = handleBurpTool;
for (const tool of triageTools) HANDLERS[tool.name] = handleTriageTool;

function parseBoolean(value: string | undefined, fallback = false): boolean {
  const normalized = String(value || "").trim().toLowerCase();
  if (!normalized) {
    return fallback;
  }
  return normalized === "1" || normalized === "true" || normalized === "yes";
}

function isCallToolResult(value: unknown): value is CallToolResult {
  return Boolean(value && typeof value === "object" && Array.isArray((value as { content?: unknown }).content));
}

function mapToTools(listed: Array<{ name: string; description?: string; inputSchema?: JsonObject }>): Tool[] {
  return listed.map((entry) => ({
    name: entry.name,
    description: entry.description,
    inputSchema:
      entry.inputSchema && entry.inputSchema.type === "object"
        ? (entry.inputSchema as Tool["inputSchema"])
        : {
            type: "object",
            properties: {},
            additionalProperties: true,
          },
  }));
}

function createRouter(): { router: ExecutionRouterLike | null; workspaceRoot: string } {
  const workspaceRoot =
    String(process.env.BRIDGE_WORKSPACE_ROOT || process.env.OPENCLAW_WORKSPACE_ROOT || "").trim() ||
    path.resolve(process.cwd(), "..");
  const registryPath = path.join(workspaceRoot, "supervisor", "supervisor-registry.json");
  const auditLogPath = path.join(workspaceRoot, ".openclaw", "audit.log");
  const legacyTools = ALL_TOOLS.map((tool) => tool.name);

  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const mod = require("../../src/core/execution-router.js") as {
      createExecutionRouter?: (options: Record<string, unknown>) => ExecutionRouterLike;
    };
    if (!mod || typeof mod.createExecutionRouter !== "function") {
      return { router: null, workspaceRoot };
    }
    return {
      workspaceRoot,
      router: mod.createExecutionRouter({
        workspaceRoot,
        supervisorMode: parseBoolean(process.env.SUPERVISOR_MODE, false),
        supervisorAuthPhase: String(process.env.SUPERVISOR_AUTH_PHASE || "compat").trim().toLowerCase() === "strict" ? "strict" : "compat",
        supervisorInternalToken: String(process.env.SUPERVISOR_INTERNAL_TOKEN || "").trim(),
        registryPath,
        auditLogPath,
        auditMaxBytes: Number.parseInt(String(process.env.SUPERVISOR_AUDIT_MAX_BYTES || "10485760"), 10) || 10 * 1024 * 1024,
        workloadManifestPath: String(process.env.WORKLOAD_MANIFEST_PATH || "").trim(),
        workloadManifestExpectedHash: String(process.env.WORKLOAD_MANIFEST_EXPECTED_HASH || "").trim().toLowerCase(),
        workloadIntegrityEnabled:
          parseBoolean(process.env.WORKLOAD_INTEGRITY_ENABLED, false) ||
          String(process.env.NODE_ENV || "").trim().toLowerCase() === "production",
        legacyVisibleToolsByRole: {
          supervisor: legacyTools,
          internal: legacyTools,
          admin: legacyTools,
          anonymous: legacyTools,
        },
      }),
    };
  } catch {
    return { router: null, workspaceRoot };
  }
}

async function executeLegacyTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const handler = HANDLERS[name];
  if (!handler) {
    return {
      content: [{ type: "text", text: `Unknown tool: ${name}. Available: ${ALL_TOOLS.map((t) => t.name).join(", ")}` }],
      isError: true,
    };
  }
  return handler(name, args);
}

async function main(): Promise<void> {
  const { router, workspaceRoot } = createRouter();
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
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    if (!router) {
      return { tools: ALL_TOOLS };
    }
    const listed = await router.listTools({
      requestId: `github-pro-list-${Date.now()}`,
      workspaceRoot,
      source: "stdio_mcp",
      caller: "github_pro_mcp",
      trustedInProcessCaller: true,
      legacyListTools: async () => ALL_TOOLS,
    });
    return { tools: mapToTools(listed) };
  });

  // Dispatch tool calls
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const callArgs = (args as Record<string, unknown>) || {};

    try {
      if (!router) {
        return await executeLegacyTool(name, callArgs);
      }

      const result = await router.execute(name, callArgs, {
        requestId: `github-pro-call-${Date.now()}`,
        workspaceRoot,
        source: "stdio_mcp",
        caller: "github_pro_mcp",
        trustedInProcessCaller: true,
        legacyExecute: async (tool: string, legacyArgs: Record<string, unknown>) => executeLegacyTool(tool, legacyArgs),
      });

      if (!result.ok) {
        return {
          content: [{ type: "text", text: `Tool execution error: ${result.message || result.code || "Execution failed"}` }],
          isError: true,
        };
      }

      if (isCallToolResult(result.data)) {
        return result.data;
      }

      return {
        content: [{ type: "text", text: JSON.stringify(result.data ?? {}, null, 2) }],
      };
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
    `openclaw-github-pro-mcp started (${ALL_TOOLS.length} tools registered, stdio transport only, bridge=${process.env.OPENCLAW_BRIDGE_BASE_URL || "http://127.0.0.1:8787"}, router=${router ? "enabled" : "legacy"})\n`
  );
}

main().catch((error) => {
  process.stderr.write(`Fatal: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});
