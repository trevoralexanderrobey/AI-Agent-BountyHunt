import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import https from "node:https";
import os from "node:os";
import path from "node:path";
import { URL } from "node:url";
import { Server as McpJsonRpcServer } from "@modelcontextprotocol/sdk/server/index.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { CallToolRequestSchema, ListToolsRequestSchema, Tool } from "@modelcontextprotocol/sdk/types.js";
import { createExecutionRouter, ExecutionContext, ExecutionRouter, ExecutionToolDescriptor } from "../src/core/execution-router";
import { bioniclinkGetHistory, bioniclinkHealth, bioniclinkRepeater, bioniclinkScan, bioniclinkScopeCheck } from "./bioniclink-client";
import { OpenClawClient } from "./openclaw-client";
import { StateStore } from "./state-store";
import { normalizeTargetUrl, summarizeHistory, summarizeRepeater, summarizeScan } from "./tsp";
import { TaskSubmission } from "./types";
import { JobWorker } from "./worker";

const DEFAULT_WORKSPACE_ROOT = "/Users/trevorrobey/Dev/Bounties";
const DEFAULT_PORT = 8787;
const DEFAULT_OPENCLAW_SKILLS_DIR = path.join(os.homedir(), ".openclaw", "skills");
const DEFAULT_BIONICLINK_BASE_URL = "https://127.0.0.1:8090";
const DEFAULT_BIONICLINK_TIMEOUT_MS = 8_000;
const DEFAULT_MCP_SSE_KEEPALIVE_MS = 15_000;

interface ErrorPayload {
  error: string;
}

function sendJson(res: http.ServerResponse, statusCode: number, payload: unknown): void {
  const body = JSON.stringify(payload, null, 2);
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Access-Control-Allow-Origin": "vscode-webview://",
    "Access-Control-Allow-Headers": "content-type, authorization",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  });
  res.end(body);
}

function sendError(res: http.ServerResponse, statusCode: number, error: string): void {
  sendJson(res, statusCode, { error } satisfies ErrorPayload);
}

function parseBearerToken(authHeader: string): string {
  const match = authHeader.trim().match(/^Bearer\s+(.+)$/i);
  if (!match) {
    return "";
  }
  return String(match[1] || "").trim();
}

function timingSafeEqualUtf8(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(String(left || ""), "utf8");
  const rightBuffer = Buffer.from(String(right || ""), "utf8");
  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }
  try {
    return crypto.timingSafeEqual(leftBuffer, rightBuffer);
  } catch {
    return false;
  }
}

async function readBody(req: http.IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  if (chunks.length === 0) {
    return {};
  }

  const raw = Buffer.concat(chunks).toString("utf-8");
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    throw new Error("Invalid JSON body");
  }
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function normalizeHttpUrl(input: string): string {
  const trimmed = input.trim();
  const parsed = new URL(trimmed);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`Unsupported URL protocol: ${trimmed}`);
  }
  return parsed.toString();
}

function normalizeTaskSubmission(rawBody: unknown): TaskSubmission {
  const record = asRecord(rawBody);
  if (!record) {
    throw new Error("Request body must be a JSON object");
  }

  const instruction = String(record.instruction || "").trim();
  if (!instruction) {
    throw new Error("instruction is required");
  }

  const requester = normalizeRequester(record.requester);

  const repoUrlRaw = String(record.repo_url || "").trim();
  const repo_url = repoUrlRaw ? normalizeHttpUrl(repoUrlRaw) : undefined;

  const contextRaw = Array.isArray(record.context_urls) ? record.context_urls : [];
  const context_urls = contextRaw
    .map((item) => String(item || "").trim())
    .filter(Boolean)
    .map((value) => normalizeHttpUrl(value));

  const gatewayBaseUrlRaw = String(record.gateway_base_url || "").trim();
  const gateway_base_url = gatewayBaseUrlRaw ? normalizeHttpUrl(gatewayBaseUrlRaw) : undefined;
  const auth_token = String(record.auth_token || "").trim() || undefined;
  const hints = String(record.hints || "").trim() || undefined;
  const branch_name = String(record.branch_name || "").trim() || undefined;
  const model = String(record.model || "").trim() || undefined;

  return {
    instruction,
    repo_url,
    context_urls: context_urls.length > 0 ? context_urls : undefined,
    gateway_base_url,
    auth_token,
    hints,
    branch_name,
    requester,
    model,
  };
}

function normalizeRequester(raw: unknown): string {
  const value = typeof raw === "string" ? raw.trim() : "";
  if (!value) {
    return "codex";
  }

  const normalized = value.toLowerCase();
  if (!/^[a-z0-9][a-z0-9_-]{0,31}$/i.test(normalized)) {
    throw new Error("Invalid requester; expected /[a-z0-9][a-z0-9_-]{0,31}/");
  }
  return normalized;
}

function parseRoute(pathname: string): {
  type: "health" | "jobs" | "job" | "cancel" | "execute-tool" | "lldb-stop" | "bionic-ingest" | "mcp-sse" | "mcp-messages" | "unknown";
  jobId?: string;
} {
  if (pathname === "/health") {
    return { type: "health" };
  }

  if (pathname === "/jobs") {
    return { type: "jobs" };
  }

  const jobMatch = pathname.match(/^\/jobs\/([^/]+)$/);
  if (jobMatch) {
    return { type: "job", jobId: decodeURIComponent(jobMatch[1]) };
  }

  const cancelMatch = pathname.match(/^\/jobs\/([^/]+)\/cancel$/);
  if (cancelMatch) {
    return { type: "cancel", jobId: decodeURIComponent(cancelMatch[1]) };
  }

  if (pathname === "/execute-tool") {
    return { type: "execute-tool" };
  }

  if (pathname === "/lldb-stop") {
    return { type: "lldb-stop" };
  }

  if (pathname === "/bionic-ingest") {
    return { type: "bionic-ingest" };
  }

  if (pathname === "/mcp/sse" || pathname === "/mcp/events") {
    return { type: "mcp-sse" };
  }

  if (pathname === "/mcp/messages") {
    return { type: "mcp-messages" };
  }

  return { type: "unknown" };
}

interface BountyHunterToolsModule {
  [key: string]: unknown;
}

interface ExecuteToolBody {
  skill?: string;
  tool: string;
  args?: Record<string, unknown>;
  internal?: boolean;
  internal_token?: string;
}

function parseExecuteToolBody(rawBody: unknown): ExecuteToolBody {
  const record = asRecord(rawBody);
  if (!record) {
    throw new Error("Request body must be a JSON object");
  }

  const tool = String(record.tool || "").trim();
  if (!tool) {
    throw new Error("tool is required");
  }

  const skillRaw = String(record.skill || "").trim();
  const skill = skillRaw ? normalizeSkillName(skillRaw) : undefined;
  const args = asRecord(record.args) || {};
  const internal = record.internal === true;
  const internalTokenRaw = record.internal_token;
  const internal_token = typeof internalTokenRaw === "string" ? internalTokenRaw.trim() : undefined;
  return { skill, tool, args, internal, internal_token };
}

function isMutationGuardEnabled(): boolean {
  const value = (process.env.BOUNTY_HUNTER_ALLOW_MUTATIONS || "").trim().toLowerCase();
  return value === "1" || value === "true" || value === "yes";
}

function isH1MutationGuardEnabled(): boolean {
  const value = (process.env.H1_ALLOW_MUTATIONS || "").trim().toLowerCase();
  return value === "1" || value === "true" || value === "yes";
}

function isBurpActiveScanEnabled(): boolean {
  const value = (process.env.BURP_ALLOW_ACTIVE_SCAN || "").trim().toLowerCase();
  return value === "1" || value === "true" || value === "yes";
}

function isBurpRawDataEnabled(): boolean {
  const value = (process.env.BURP_ALLOW_RAW_DATA || "").trim().toLowerCase();
  return value === "1" || value === "true" || value === "yes";
}

function normalizeSkillName(skill: string): string {
  const trimmed = skill.trim();
  if (!trimmed) {
    throw new Error("skill is required");
  }
  if (!/^[a-z0-9][a-z0-9_-]*$/i.test(trimmed)) {
    throw new Error(`Invalid skill name: ${trimmed}`);
  }
  return trimmed;
}

function resolveToolsPath(skill: string): string {
  return path.join(DEFAULT_OPENCLAW_SKILLS_DIR, skill, "tools.js");
}

function loadToolsModule(toolsPath: string): BountyHunterToolsModule {
  // Force refresh to pick up local skill edits without bridge restart.
  delete require.cache[require.resolve(toolsPath)];
  return require(toolsPath) as BountyHunterToolsModule;
}

async function pathExists(targetPath: string): Promise<boolean> {
  try {
    await fs.access(targetPath);
    return true;
  } catch {
    return false;
  }
}

const BURP_ALLOWED_TOOLS = new Set(["burp_get_history", "burp_analyze_request", "burp_active_scan", "burp_get_raw_request"]);

interface BridgeMcpContext {
  bridgePort: number;
  bridgeAuthToken: string;
  executionRouter: ExecutionRouter;
  sessionAuthHeader?: string;
}

interface BridgeMcpSseSession {
  sessionId: string;
  server: McpJsonRpcServer;
  transport: SSEServerTransport;
  keepAliveTimer: NodeJS.Timeout;
  connectedAtMs: number;
}

const BRIDGE_MCP_TOOLS: Tool[] = [
  {
    name: "bridge_health",
    description: "Return OpenClaw bridge health JSON from /health.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "bridge_list_jobs",
    description: "List current OpenClaw bridge jobs from /jobs.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "bridge_job_status",
    description: "Get one job record by id from /jobs/:id.",
    inputSchema: {
      type: "object",
      properties: {
        job_id: {
          type: "string",
          description: "Job id",
        },
      },
      required: ["job_id"],
    },
  },
  {
    name: "bridge_submit_job",
    description: "Submit a new async bridge job to /jobs.",
    inputSchema: {
      type: "object",
      properties: {
        instruction: { type: "string" },
        repo_url: { type: "string" },
        context_urls: {
          type: "array",
          items: { type: "string" },
        },
        hints: { type: "string" },
        branch_name: { type: "string" },
        requester: { type: "string" },
        model: { type: "string" },
        gateway_base_url: { type: "string" },
        auth_token: { type: "string" },
      },
      required: ["instruction"],
    },
  },
  {
    name: "bridge_cancel_job",
    description: "Cancel a queued/running job via /jobs/:id/cancel.",
    inputSchema: {
      type: "object",
      properties: {
        job_id: {
          type: "string",
          description: "Job id",
        },
      },
      required: ["job_id"],
    },
  },
  {
    name: "bridge_execute_tool",
    description: "Execute a bridge tool through /execute-tool with optional skill routing.",
    inputSchema: {
      type: "object",
      properties: {
        skill: { type: "string" },
        tool: { type: "string" },
        args: { type: "object" },
        internal: { type: "boolean" },
        internal_token: { type: "string" },
      },
      required: ["tool"],
    },
  },
];

function createMcpToolResult(payload: unknown, isError = false) {
  const LOCAL_SENSITIVE_KEY_PATTERN = /(token|secret|password|authorization|authheader|signature|privatekey|apikey|api_key|credential|cookie|secret_store|secretstore|secret_manifest|secretManifest|secret_store_url|redis|password|key|auth)/i;

  function sanitizeForMcp(value: unknown): unknown {
    if (value === null || typeof value === "undefined") return value;
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return value;
    if (Array.isArray(value)) return value.map((v) => sanitizeForMcp(v));
    if (typeof value === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        if (LOCAL_SENSITIVE_KEY_PATTERN.test(k)) {
          out[k] = "<redacted>";
        } else {
          out[k] = sanitizeForMcp(v);
        }
      }
      return out;
    }
    return value;
  }

  const safe = sanitizeForMcp(payload);
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(safe, null, 2),
      },
    ],
    isError,
  };
}

async function callBridgeEndpointJson(
  context: BridgeMcpContext,
  method: "GET" | "POST",
  endpointPath: string,
  body?: unknown,
): Promise<unknown> {
  const url = `http://127.0.0.1:${context.bridgePort}${endpointPath}`;
  const headers: Record<string, string> = {};
  if (typeof body !== "undefined") {
    headers["Content-Type"] = "application/json";
  }
  if (context.bridgeAuthToken) {
    headers.Authorization = `Bearer ${context.bridgeAuthToken}`;
  }

  const response = await fetch(url, {
    method,
    headers,
    body: typeof body !== "undefined" ? JSON.stringify(body) : undefined,
  });

  const text = await response.text();
  let parsed: unknown = {};
  try {
    parsed = text ? (JSON.parse(text) as unknown) : {};
  } catch {
    parsed = { raw: text };
  }

  if (!response.ok) {
    const record = asRecord(parsed);
    const message = typeof record?.error === "string" ? record.error : `HTTP ${response.status}`;
    throw new Error(message);
  }

  return parsed;
}

async function executeLegacyBridgeMcpTool(
  context: BridgeMcpContext,
  toolName: string,
  args: Record<string, unknown>,
): Promise<unknown> {
  if (toolName === "bridge_health") {
    return callBridgeEndpointJson(context, "GET", "/health");
  }

  if (toolName === "bridge_list_jobs") {
    return callBridgeEndpointJson(context, "GET", "/jobs");
  }

  if (toolName === "bridge_job_status") {
    const jobId = String(args.job_id || "").trim();
    if (!jobId) {
      throw new Error("job_id is required");
    }
    return callBridgeEndpointJson(context, "GET", `/jobs/${encodeURIComponent(jobId)}`);
  }

  if (toolName === "bridge_submit_job") {
    const instruction = String(args.instruction || "").trim();
    if (!instruction) {
      throw new Error("instruction is required");
    }
    const body = {
      instruction,
      repo_url: typeof args.repo_url === "string" ? args.repo_url : undefined,
      context_urls: Array.isArray(args.context_urls) ? args.context_urls : undefined,
      hints: typeof args.hints === "string" ? args.hints : undefined,
      branch_name: typeof args.branch_name === "string" ? args.branch_name : undefined,
      requester: typeof args.requester === "string" ? args.requester : undefined,
      model: typeof args.model === "string" ? args.model : undefined,
      gateway_base_url: typeof args.gateway_base_url === "string" ? args.gateway_base_url : undefined,
      auth_token: typeof args.auth_token === "string" ? args.auth_token : undefined,
    };
    return callBridgeEndpointJson(context, "POST", "/jobs", body);
  }

  if (toolName === "bridge_cancel_job") {
    const jobId = String(args.job_id || "").trim();
    if (!jobId) {
      throw new Error("job_id is required");
    }
    return callBridgeEndpointJson(context, "POST", `/jobs/${encodeURIComponent(jobId)}/cancel`, {});
  }

  if (toolName === "bridge_execute_tool") {
    const tool = String(args.tool || "").trim();
    if (!tool) {
      throw new Error("tool is required");
    }
    const fallbackArgs = { ...args };
    delete fallbackArgs.skill;
    delete fallbackArgs.tool;
    delete fallbackArgs.args;
    delete fallbackArgs.internal;
    delete fallbackArgs.internal_token;
    const body = {
      skill: typeof args.skill === "string" ? args.skill : undefined,
      tool,
      args: asRecord(args.args) || fallbackArgs,
      internal: args.internal === true,
      internal_token: typeof args.internal_token === "string" ? args.internal_token : undefined,
    };
    return callBridgeEndpointJson(context, "POST", "/execute-tool", body);
  }

  throw new Error(`Unknown tool: ${toolName}`);
}

function createBridgeMcpServer(context: BridgeMcpContext): McpJsonRpcServer {
  const server = new McpJsonRpcServer(
    {
      name: "openclaw-bridge-sse-mcp",
      version: "0.1.0",
    },
    {
      capabilities: {
        tools: {},
        logging: {},
      },
    },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const listed = await context.executionRouter.listTools({
      requestId: `mcp-list-${Date.now()}`,
      workspaceRoot: process.env.BRIDGE_WORKSPACE_ROOT || DEFAULT_WORKSPACE_ROOT,
      source: "mcp_sse",
      caller: "bridge_mcp_sse",
      authHeader: context.sessionAuthHeader,
      legacyListTools: async () => BRIDGE_MCP_TOOLS as unknown as ExecutionToolDescriptor[],
    });
    return {
      tools: listed as Tool[],
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    const toolName = request.params.name;
    const args = asRecord(request.params.arguments) || {};

    const routerContext: ExecutionContext = {
      requestId: `mcp-call-${Date.now()}`,
      workspaceRoot: process.env.BRIDGE_WORKSPACE_ROOT || DEFAULT_WORKSPACE_ROOT,
      source: "mcp_sse",
      caller: "bridge_mcp_sse",
      authHeader: context.sessionAuthHeader,
      internalFlagRequested: args.internal === true,
      internalToken: typeof args.internal_token === "string" ? args.internal_token : undefined,
      legacyExecute: async (tool, legacyArgs) => executeLegacyBridgeMcpTool(context, tool, legacyArgs),
    };

    const result = await context.executionRouter.execute(toolName, args, routerContext);
    if (!result.ok) {
      const message = result.message || result.code || "Execution failed";
      await server.sendLoggingMessage({ level: "error", data: `${toolName} failed: ${message}` }, extra.sessionId).catch(() => undefined);
      return createMcpToolResult({ error: message, code: result.code }, true);
    }

    await server.sendLoggingMessage({ level: "info", data: `${toolName} executed` }, extra.sessionId).catch(() => undefined);
    return createMcpToolResult(result.data);
  });

  return server;
}

interface HttpErrorLike extends Error {
  statusCode?: number;
  code?: string;
}

function makeHttpError(statusCode: number, message: string, code = "LEGACY_EXECUTION_FAILED"): HttpErrorLike {
  const error = new Error(message) as HttpErrorLike;
  error.statusCode = statusCode;
  error.code = code;
  return error;
}

function resolveHttpErrorStatus(error: unknown): number {
  const statusCode = error && typeof error === "object" && "statusCode" in error ? Number((error as { statusCode?: unknown }).statusCode) : NaN;
  if (Number.isFinite(statusCode) && statusCode >= 100 && statusCode <= 599) {
    return statusCode;
  }
  const code = error && typeof error === "object" && "code" in error ? String((error as { code?: unknown }).code || "") : "";
  if (code === "UNAUTHORIZED" || code === "UNAUTHORIZED_INTERNAL_BYPASS") return 401;
  if (code === "UNAUTHORIZED_TOOL") return 403;
  if (code === "UNAUTHORIZED_ROLE") return 403;
  if (code === "PATH_OUTSIDE_WORKSPACE") return 403;
  if (code === "INVALID_REQUEST" || code === "INVALID_ARGUMENT") return 400;
  if (code === "RATE_LIMIT_EXCEEDED" || code === "MAX_CONCURRENT_EXECUTIONS_EXCEEDED" || code === "SOURCE_CONCURRENCY_LIMIT_EXCEEDED") return 429;
  if (
    code === "WORKLOAD_NOT_VERIFIED" ||
    code === "WORKLOAD_HASH_MISMATCH" ||
    code === "WORKLOAD_IMAGE_MISMATCH" ||
    code === "WORKLOAD_MANIFEST_MISMATCH" ||
    code === "WORKLOAD_MUTATION_DETECTED" ||
    code === "WORKLOAD_MANIFEST_SCHEMA_INVALID" ||
    code === "WORKLOAD_MANIFEST_MISSING" ||
    code === "WORKLOAD_MANIFEST_PATH_OVERRIDE_FORBIDDEN" ||
    code === "WORKLOAD_MANIFEST_WRITABLE_IN_PRODUCTION"
  ) {
    return 503;
  }
  const message = error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
  if (message.includes("out of scope")) return 403;
  if (message.includes("bioniclink")) return 502;
  return 500;
}

async function executeLegacyBridgeRouteTool(params: {
  parsed: ExecuteToolBody;
  bioniclinkBaseUrl: string;
  bioniclinkTimeoutMs: number;
}): Promise<unknown> {
  const { parsed, bioniclinkBaseUrl, bioniclinkTimeoutMs } = params;

  if (!parsed.skill) {
    const tool = parsed.tool;
    if (!BURP_ALLOWED_TOOLS.has(tool)) {
      throw makeHttpError(400, `Invalid tool (burp allowlist): ${tool}`, "INVALID_REQUEST");
    }

    if (tool === "burp_get_history") {
      const limitRaw = parsed.args?.limit;
      const fromIdRaw = parsed.args?.fromId ?? parsed.args?.from_id;
      const inScopeRaw = parsed.args?.inScope ?? parsed.args?.in_scope ?? parsed.args?.filter_scope;

      const limit = typeof limitRaw === "number" ? limitRaw : limitRaw ? Number(limitRaw) : 20;
      const fromId = typeof fromIdRaw === "number" ? fromIdRaw : fromIdRaw ? Number(fromIdRaw) : 0;
      const inScope =
        typeof inScopeRaw === "boolean"
          ? inScopeRaw
          : typeof inScopeRaw === "string"
            ? ["1", "true", "yes"].includes(inScopeRaw.trim().toLowerCase())
            : Boolean(inScopeRaw);

      const history = await bioniclinkGetHistory(bioniclinkBaseUrl, { limit, fromId, inScope }, bioniclinkTimeoutMs);
      if (!history.ok) {
        throw makeHttpError(502, "BionicLink /history returned ok=false", "BIONICLINK_ERROR");
      }

      return summarizeHistory(history);
    }

    if (tool === "burp_analyze_request") {
      const urlRaw = String(parsed.args?.url || "").trim();
      if (!urlRaw) {
        throw makeHttpError(400, "args.url is required", "INVALID_REQUEST");
      }
      const url = normalizeTargetUrl(urlRaw);

      const scope = await bioniclinkScopeCheck(bioniclinkBaseUrl, url, bioniclinkTimeoutMs);
      if (!scope.ok) {
        throw makeHttpError(502, "BionicLink /scope returned ok=false", "BIONICLINK_ERROR");
      }
      if (!scope.in_scope) {
        throw makeHttpError(403, "Target URL is out of scope (Burp Target Scope).", "OUT_OF_SCOPE");
      }

      const methodArg = parsed.args?.method;
      const reqMethod = typeof methodArg === "string" && methodArg.trim() ? methodArg.trim().toUpperCase() : "GET";
      const headersArg = asRecord(parsed.args?.headers) || {};
      const headers: Record<string, string> = {};
      for (const [key, value] of Object.entries(headersArg)) {
        if (!key.trim()) continue;
        headers[key] = String(value ?? "");
      }
      const bodyArg = parsed.args?.body;
      const reqBody = typeof bodyArg === "string" ? bodyArg : bodyArg != null ? String(bodyArg) : undefined;

      const rr = await bioniclinkRepeater(bioniclinkBaseUrl, { url, method: reqMethod, headers, body: reqBody }, bioniclinkTimeoutMs);
      if (!rr.ok) {
        throw makeHttpError(502, "BionicLink /repeater returned ok=false", "BIONICLINK_ERROR");
      }

      return summarizeRepeater(rr);
    }

    if (tool === "burp_active_scan") {
      if (!isBurpActiveScanEnabled()) {
        throw makeHttpError(403, "Active scan disabled. Set BURP_ALLOW_ACTIVE_SCAN=true to enable.", "ACTIVE_SCAN_DISABLED");
      }

      const urlRaw = String(parsed.args?.url || "").trim();
      if (!urlRaw) {
        throw makeHttpError(400, "args.url is required", "INVALID_REQUEST");
      }
      const url = normalizeTargetUrl(urlRaw);

      const scope = await bioniclinkScopeCheck(bioniclinkBaseUrl, url, bioniclinkTimeoutMs);
      if (!scope.ok) {
        throw makeHttpError(502, "BionicLink /scope returned ok=false", "BIONICLINK_ERROR");
      }
      if (!scope.in_scope) {
        throw makeHttpError(403, "Target URL is out of scope (Burp Target Scope).", "OUT_OF_SCOPE");
      }

      const requestIdRaw = parsed.args?.requestId ?? parsed.args?.request_id;
      const requestId = typeof requestIdRaw === "number" ? requestIdRaw : requestIdRaw ? Number(requestIdRaw) : undefined;
      const methodArg = parsed.args?.method;
      const reqMethod = typeof methodArg === "string" && methodArg.trim() ? methodArg.trim().toUpperCase() : "GET";

      const scan = await bioniclinkScan(bioniclinkBaseUrl, { url, method: reqMethod, requestId }, bioniclinkTimeoutMs);
      if (!scan.ok) {
        throw makeHttpError(502, "BionicLink /scan returned ok=false", "BIONICLINK_ERROR");
      }

      return summarizeScan(scan);
    }

    if (tool === "burp_get_raw_request") {
      if (!isBurpRawDataEnabled()) {
        throw makeHttpError(403, "Raw data disabled. Set BURP_ALLOW_RAW_DATA=true to enable.", "RAW_DATA_DISABLED");
      }

      const messageIdRaw = parsed.args?.messageId ?? parsed.args?.message_id ?? parsed.args?.id;
      const messageId = typeof messageIdRaw === "number" ? messageIdRaw : messageIdRaw ? Number(messageIdRaw) : NaN;
      if (!Number.isFinite(messageId) || messageId < 1) {
        throw makeHttpError(400, "args.messageId is required (positive integer).", "INVALID_REQUEST");
      }

      const history = await bioniclinkGetHistory(bioniclinkBaseUrl, { limit: 200, fromId: 0, inScope: false }, bioniclinkTimeoutMs);
      if (!history.ok) {
        throw makeHttpError(502, "BionicLink /history returned ok=false", "BIONICLINK_ERROR");
      }

      const item = (history.items || []).find((it) => it && typeof it.id === "number" && it.id === messageId);
      if (!item) {
        throw makeHttpError(404, `Message id not found in the last ${history.items?.length ?? 0} proxy history items: ${messageId}`, "NOT_FOUND");
      }

      const url = String(item.url || "").trim();
      if (!url) {
        throw makeHttpError(502, `BionicLink history item missing url for messageId=${messageId}`, "BIONICLINK_ERROR");
      }

      const scope = await bioniclinkScopeCheck(bioniclinkBaseUrl, url, bioniclinkTimeoutMs);
      if (!scope.ok) {
        throw makeHttpError(502, "BionicLink /scope returned ok=false", "BIONICLINK_ERROR");
      }
      if (!scope.in_scope) {
        throw makeHttpError(403, "Target URL is out of scope (Burp Target Scope).", "OUT_OF_SCOPE");
      }

      return {
        message_id: messageId,
        scope,
        item,
      };
    }

    throw makeHttpError(400, `Unhandled tool: ${tool}`, "INVALID_REQUEST");
  }

  const skillName = parsed.skill;
  const toolsPath = resolveToolsPath(skillName);
  if (!(await pathExists(toolsPath))) {
    throw makeHttpError(404, `Tools module not found for skill ${skillName}: ${toolsPath}`, "SKILL_NOT_FOUND");
  }

  const toolsModule = loadToolsModule(toolsPath);
  const toolFn = toolsModule[parsed.tool];

  if (typeof toolFn !== "function") {
    throw makeHttpError(404, `Unknown tool: ${parsed.tool}`, "UNKNOWN_TOOL");
  }

  return (toolFn as (args: Record<string, unknown>) => Promise<unknown>)(parsed.args || {});
}

interface BionicHeader {
  name: string;
  value: string;
}

interface StabilityFinding {
  kind: "integer_width" | "format_string" | "serialization_magic";
  where: string;
  detail: string;
}

const SENSITIVE_HEADER_NAMES = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "x-api-key",
  "x-auth-token",
]);
const SENSITIVE_KEY_PATTERN = /(token|secret|password|authorization|authheader|signature|privatekey|apikey|api_key|credential|cookie|secret_store|secretstore|secret_manifest|secretManifest|secret_store_url|redis|password|key|auth)/i;

const INT32_MAX = 2147483647n;
const UINT32_MAX = 4294967295n;
const INT64_MAX = 9223372036854775807n;
const UINT64_MAX = 18446744073709551615n;

function truncateText(value: unknown, maxChars: number): string {
  const text = typeof value === "string" ? value : value == null ? "" : String(value);
  if (text.length <= maxChars) {
    return text;
  }
  return `${text.slice(0, Math.max(0, maxChars))}...<truncated>`;
}

function normalizeBionicHeaders(raw: unknown): BionicHeader[] {
  const record = asRecord(raw);
  if (Array.isArray(raw)) {
    const headers: BionicHeader[] = [];
    for (const item of raw) {
      if (typeof item === "string") {
        const line = item.trim();
        if (!line) continue;
        const idx = line.indexOf(":");
        if (idx <= 0) {
          // Ignore request/status lines or malformed header lines.
          continue;
        }
        const name = line.slice(0, idx).trim();
        const value = line.slice(idx + 1).trim();
        if (!name) continue;
        headers.push({ name, value });
        continue;
      }

      const headerRec = asRecord(item);
      if (!headerRec) continue;
      const name = String(headerRec.name || "").trim();
      if (!name) continue;
      const value = String(headerRec.value ?? "").trim();
      headers.push({ name, value });
    }
    return headers;
  }

  if (record) {
    const headers: BionicHeader[] = [];
    for (const [key, value] of Object.entries(record)) {
      const name = String(key || "").trim();
      if (!name) continue;
      headers.push({ name, value: String(value ?? "").trim() });
    }
    return headers;
  }

  return [];
}

function normalizeBase64Field(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return undefined;
  }
  // Defensive cap to avoid decoding extremely large bodies if a client misbehaves.
  const maxChars = 512 * 1024;
  if (trimmed.length > maxChars) {
    return trimmed.slice(0, maxChars);
  }
  return trimmed;
}

function decodeBase64ToBuffer(value: string): Buffer | null {
  try {
    // Node will ignore non-base64 chars; keep it strict-ish by trimming only.
    return Buffer.from(value.trim(), "base64");
  } catch {
    return null;
  }
}

function bufferToTextPreview(buf: Buffer | null, maxChars: number): string {
  if (!buf || buf.length === 0) {
    return "";
  }
  // Best-effort: treat as UTF-8 for preview; binary will show replacement chars.
  const text = buf.toString("utf8");
  return truncateText(text, maxChars);
}

function redactHeaders(headers: BionicHeader[]): BionicHeader[] {
  return headers.map((header) => {
    const nameLower = header.name.trim().toLowerCase();
    if (SENSITIVE_HEADER_NAMES.has(nameLower)) {
      return { ...header, value: "<redacted>" };
    }
    return header;
  });
}

function parseBigIntStrict(value: string): bigint | null {
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (!/^-?\d+$/.test(trimmed)) return null;
  try {
    return BigInt(trimmed);
  } catch {
    return null;
  }
}

function shouldTreatHeaderAsInteger(name: string): boolean {
  const lowered = name.trim().toLowerCase();
  if (lowered === "content-length") return true;
  if (!lowered.startsWith("x-")) return false;
  return /(length|size|count|offset|index|id|seq|sequence|version|ttl|age|limit|max|min)/i.test(lowered);
}

function scanIntegerWidthFindings(headers: BionicHeader[], wherePrefix: string): StabilityFinding[] {
  const findings: StabilityFinding[] = [];
  for (const header of headers) {
    if (!shouldTreatHeaderAsInteger(header.name)) {
      continue;
    }

    const parsed = parseBigIntStrict(header.value);
    if (parsed === null) {
      continue;
    }

    const where = `${wherePrefix}:${header.name}`;
    if (parsed < 0n) {
      findings.push({ kind: "integer_width", where, detail: `negative integer value (${header.value})` });
      continue;
    }

    if (parsed > UINT64_MAX) {
      findings.push({ kind: "integer_width", where, detail: `exceeds uint64 (${header.value})` });
      continue;
    }

    if (parsed > INT64_MAX) {
      findings.push({ kind: "integer_width", where, detail: `exceeds int64 (${header.value})` });
      continue;
    }

    if (parsed > UINT32_MAX) {
      findings.push({ kind: "integer_width", where, detail: `exceeds uint32 (${header.value})` });
      continue;
    }

    if (parsed > INT32_MAX) {
      findings.push({ kind: "integer_width", where, detail: `exceeds int32 (${header.value})` });
      continue;
    }
  }

  return findings;
}

function scanFormatStringFindings(text: string, where: string): StabilityFinding[] {
  const findings: StabilityFinding[] = [];
  const pattern = /%(?:s|x|n)/gi;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(text)) !== null) {
    const snippetStart = Math.max(0, match.index - 24);
    const snippetEnd = Math.min(text.length, match.index + match[0].length + 24);
    const snippet = text.slice(snippetStart, snippetEnd).replace(/\s+/g, " ").trim();
    findings.push({
      kind: "format_string",
      where,
      detail: `contains ${match[0]} (snippet: "${snippet}")`,
    });
    if (findings.length >= 5) {
      break;
    }
  }
  return findings;
}

function scanSerializationMagicFindings(text: string, bytes: Buffer | null, where: string): StabilityFinding[] {
  const findings: StabilityFinding[] = [];
  const lowered = text.toLowerCase();

  if (lowered.includes("bplist00")) {
    findings.push({ kind: "serialization_magic", where, detail: 'found "bplist00" (binary plist magic)' });
  }

  // Common base64 prefix for Java serialization stream header (0xAC ED 00 05 -> "rO0ABQ==")
  if (text.includes("rO0AB") || lowered.includes("aced0005")) {
    findings.push({ kind: "serialization_magic", where, detail: "possible Java Serialization stream (AC ED 00 05)" });
  }

  if (bytes && bytes.length >= 8) {
    const head8 = bytes.subarray(0, 8).toString("ascii");
    if (head8 === "bplist00") {
      findings.push({ kind: "serialization_magic", where, detail: "binary plist magic bytes (bplist00)" });
    }
  }

  if (bytes && bytes.length >= 4) {
    if (bytes[0] === 0xac && bytes[1] === 0xed && bytes[2] === 0x00 && bytes[3] === 0x05) {
      findings.push({ kind: "serialization_magic", where, detail: "Java Serialization magic bytes (AC ED 00 05)" });
    }
  }

  return findings;
}

function runStabilityPrecheck(input: {
  url: string;
  requestHeaders: BionicHeader[];
  requestBody: string;
  requestBodyBytes?: Buffer | null;
  responseHeaders: BionicHeader[];
  responseBody: string;
  responseBodyBytes?: Buffer | null;
}): StabilityFinding[] {
  const findings: StabilityFinding[] = [];

  findings.push(...scanIntegerWidthFindings(input.requestHeaders, "request_header"));
  findings.push(...scanIntegerWidthFindings(input.responseHeaders, "response_header"));

  findings.push(...scanFormatStringFindings(input.url, "request_url"));
  for (const header of input.requestHeaders) {
    findings.push(...scanFormatStringFindings(header.value, `request_header:${header.name}`));
    if (findings.length >= 30) break;
  }
  if (findings.length < 30) {
    findings.push(...scanFormatStringFindings(input.requestBody, "request_body"));
  }

  findings.push(...scanSerializationMagicFindings(input.requestBody, input.requestBodyBytes ?? null, "request_body"));
  findings.push(...scanSerializationMagicFindings(input.responseBody, input.responseBodyBytes ?? null, "response_body"));

  return findings.slice(0, 50);
}

async function main(): Promise<void> {
  const bridgePort = Number.parseInt(process.env.BRIDGE_PORT || String(DEFAULT_PORT), 10);
  const workspaceRoot = process.env.BRIDGE_WORKSPACE_ROOT || DEFAULT_WORKSPACE_ROOT;
  const bioniclinkBaseUrl = ((process.env.BIONICLINK_BASE_URL || "").trim() || DEFAULT_BIONICLINK_BASE_URL).trim();
  const bioniclinkTimeoutMsRaw = Number.parseInt(process.env.BIONICLINK_TIMEOUT_MS || String(DEFAULT_BIONICLINK_TIMEOUT_MS), 10);
  const bioniclinkTimeoutMs =
    Number.isFinite(bioniclinkTimeoutMsRaw) && bioniclinkTimeoutMsRaw > 0 ? bioniclinkTimeoutMsRaw : DEFAULT_BIONICLINK_TIMEOUT_MS;
  const startupEnvSnapshot = {
    pid: process.pid,
    cwd: process.cwd(),
    BRIDGE_PORT: process.env.BRIDGE_PORT || String(DEFAULT_PORT),
    BRIDGE_HTTP: process.env.BRIDGE_HTTP || process.env.BRIDGE_ALLOW_HTTP || "",
    SILENT: process.env.SILENT || "",
    BRIDGE_AUTH_TOKEN: process.env.BRIDGE_AUTH_TOKEN ? "<set>" : "<unset>",
  };
  // eslint-disable-next-line no-console
  console.log(`Bridge startup context: ${JSON.stringify(startupEnvSnapshot)}`);

  const store = new StateStore(workspaceRoot);
  await store.init();

  const executionRouter = createExecutionRouter({
    workspaceRoot,
    supervisorMode: String(process.env.SUPERVISOR_MODE || "").trim().toLowerCase() === "true",
    supervisorAuthPhase: String(process.env.SUPERVISOR_AUTH_PHASE || "compat").trim().toLowerCase() === "strict" ? "strict" : "compat",
    supervisorInternalToken: String(process.env.SUPERVISOR_INTERNAL_TOKEN || "").trim(),
    registryPath: path.resolve(process.cwd(), "supervisor", "supervisor-registry.json"),
    auditLogPath: path.join(workspaceRoot, ".openclaw", "audit.log"),
    auditMaxBytes: 10 * 1024 * 1024,
    workloadManifestPath: String(process.env.WORKLOAD_MANIFEST_PATH || "").trim(),
    workloadManifestExpectedHash: String(process.env.WORKLOAD_MANIFEST_EXPECTED_HASH || "").trim().toLowerCase(),
    workloadIntegrityEnabled:
      String(process.env.WORKLOAD_INTEGRITY_ENABLED || "").trim().toLowerCase() === "true" ||
      String(process.env.NODE_ENV || "").trim().toLowerCase() === "production",
    legacyVisibleToolsByRole: {
      supervisor: ["bridge_health", "bridge_list_jobs", "bridge_job_status", "bridge_submit_job", "bridge_cancel_job", "bridge_execute_tool"],
      internal: BRIDGE_MCP_TOOLS.map((tool) => tool.name),
      admin: BRIDGE_MCP_TOOLS.map((tool) => tool.name),
      anonymous: BRIDGE_MCP_TOOLS.map((tool) => tool.name),
    },
  });

  const openclawClient = new OpenClawClient({
    baseUrl: process.env.OPENCLAW_GATEWAY_BASE_URL,
    defaultModel: process.env.OPENCLAW_DEFAULT_MODEL,
  });

  const worker = new JobWorker({
    store,
    openclawClient,
  });

  worker.enqueueQueuedJobs();

  const mcpSseKeepAliveMsRaw = Number.parseInt(process.env.MCP_SSE_KEEPALIVE_MS || String(DEFAULT_MCP_SSE_KEEPALIVE_MS), 10);
  const mcpSseKeepAliveMs =
    Number.isFinite(mcpSseKeepAliveMsRaw) && mcpSseKeepAliveMsRaw >= 1_000 ? mcpSseKeepAliveMsRaw : DEFAULT_MCP_SSE_KEEPALIVE_MS;
  const mcpSseSessions = new Map<string, BridgeMcpSseSession>();

  // ── Server mode: HTTPS by default, but allow HTTP for local testing
  // Set BRIDGE_HTTP=true to run in HTTP-only (insecure) mode for local testing.
  const allowHttp = String(process.env.BRIDGE_HTTP || process.env.BRIDGE_ALLOW_HTTP || "false").toLowerCase() === "true";
  let server: http.Server | https.Server;

  if (allowHttp) {
    // Run plain HTTP (insecure) for local dev/testing only.
    server = http.createServer(async (req, res) => {
      return handler(req, res);
    });
    // eslint-disable-next-line no-console
    console.warn("⚠️  Bridge running in HTTP-only mode (BRIDGE_HTTP=true). This is insecure and for local testing only.");
  } else {
    // HTTPS mode: Certs are auto-generated at ~/.openclaw/tls/ if missing.
    const tlsDir = path.join(os.homedir(), ".openclaw", "tls");
    const certPath = process.env.BRIDGE_TLS_CERT_PATH || path.join(tlsDir, "bridge-cert.pem");
    const keyPath = process.env.BRIDGE_TLS_KEY_PATH || path.join(tlsDir, "bridge-key.pem");

    if (!(await pathExists(certPath)) || !(await pathExists(keyPath))) {
      // Auto-generate self-signed cert
      try {
        await fs.mkdir(tlsDir, { recursive: true, mode: 0o700 });
        execFileSync("openssl", [
          "req", "-x509", "-newkey", "ec",
          "-pkeyopt", "ec_paramgen_curve:prime256v1",
          "-keyout", keyPath,
          "-out", certPath,
          "-days", "3650",
          "-nodes",
          "-subj", "/CN=localhost/O=OpenClaw Local",
          "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
        ], { stdio: "pipe" });
        await fs.chmod(keyPath, 0o600);
        await fs.chmod(certPath, 0o600);
        // eslint-disable-next-line no-console
        console.log(`Auto-generated TLS cert at ${tlsDir}`);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        // eslint-disable-next-line no-console
        console.error([
          "",
          "❌  HTTPS startup failed: could not generate TLS certificates.",
          "",
          `   cert path: ${certPath}`,
          `   key path:  ${keyPath}`,
          "",
          "   Fix options:",
          "   1. Install openssl (brew install openssl) and restart the bridge.",
          "   2. Generate certs manually:",
          "      openclaw-bridge/scripts/generate-tls-certs.sh",
          "   3. Set BRIDGE_TLS_CERT_PATH and BRIDGE_TLS_KEY_PATH to existing PEM files.",
          "",
          `   Error: ${msg}`,
          "",
        ].join("\n"));
        process.exit(1);
      }
    }

    let tlsOpts: { cert: string; key: string };
    try {
      tlsOpts = {
        cert: await fs.readFile(certPath, "utf-8"),
        key: await fs.readFile(keyPath, "utf-8"),
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      // eslint-disable-next-line no-console
      console.error([
        "",
        "❌  HTTPS startup failed: could not read TLS certificate files.",
        "",
        `   cert path: ${certPath}`,
        `   key path:  ${keyPath}`,
        "",
        "   Ensure both files exist, are valid PEM, and are readable by this process.",
        `   Error: ${msg}`,
        "",
      ].join("\n"));
      process.exit(1);
    }

    server = https.createServer(tlsOpts, async (req, res) => {
      return handler(req, res);
    });
  }

  // Internal request handler
  async function handler(req: http.IncomingMessage, res: http.ServerResponse) {
    const method = (req.method || "GET").toUpperCase();

    if (method === "OPTIONS") {
      sendJson(res, 204, {});
      return;
    }

    // Authenticate requests using BRIDGE_AUTH_TOKEN if configured
    const bridgeAuthToken = (process.env.BRIDGE_AUTH_TOKEN || "").trim();
    if (bridgeAuthToken) {
      const authHeader = typeof req.headers.authorization === "string" ? req.headers.authorization : "";
      const providedToken = parseBearerToken(authHeader);
      if (!providedToken || !timingSafeEqualUtf8(providedToken, bridgeAuthToken)) {
        sendError(res, 401, "Unauthorized: invalid or missing Bearer token");
        return;
      }
    }

    const requestUrl = new URL(req.url || "/", "http://127.0.0.1");
    const route = parseRoute(requestUrl.pathname);

    try {
      if (method === "GET" && route.type === "mcp-sse") {
        const mcpServer = createBridgeMcpServer({
          bridgePort,
          bridgeAuthToken,
          executionRouter,
          sessionAuthHeader: typeof req.headers.authorization === "string" ? req.headers.authorization : "",
        });
        const transport = new SSEServerTransport("/mcp/messages", res);
        const sessionId = transport.sessionId;
        const keepAliveTimer = setInterval(() => {
          try {
            res.write(`: keepalive ${Date.now()}\n\n`);
          } catch {
            // Ignore keepalive write errors; onclose handles cleanup.
          }
        }, mcpSseKeepAliveMs);

        const cleanupSession = () => {
          clearInterval(keepAliveTimer);
          mcpSseSessions.delete(sessionId);
          void mcpServer.close().catch(() => undefined);
        };

        transport.onclose = cleanupSession;
        transport.onerror = (error) => {
          const message = error instanceof Error ? error.message : String(error);
          // eslint-disable-next-line no-console
          console.error(`MCP SSE transport error (session=${sessionId}): ${message}`);
        };

        mcpSseSessions.set(sessionId, {
          sessionId,
          server: mcpServer,
          transport,
          keepAliveTimer,
          connectedAtMs: Date.now(),
        });

        try {
          await mcpServer.connect(transport);
          // eslint-disable-next-line no-console
          console.log(`MCP SSE session established: session=${sessionId} endpoint=/mcp/messages?sessionId=${sessionId}`);
        } catch (error) {
          cleanupSession();
          const message = error instanceof Error ? error.message : String(error);
          // eslint-disable-next-line no-console
          console.error(`Failed to establish MCP SSE session: ${message}`);
          if (!res.headersSent) {
            sendError(res, 500, "Failed to establish MCP SSE session");
          }
        }
        return;
      }

      if (method === "POST" && route.type === "mcp-messages") {
        const sessionId = String(requestUrl.searchParams.get("sessionId") || "").trim();
        if (!sessionId) {
          sendError(res, 400, "Missing sessionId query parameter");
          return;
        }
        const session = mcpSseSessions.get(sessionId);
        if (!session) {
          sendError(res, 404, `MCP SSE session not found: ${sessionId}`);
          return;
        }

        await session.transport.handlePostMessage(req, res);
        return;
      }

      if (method === "GET" && route.type === "health") {
        const jobs = store.listJobs();
        const queuedCount = jobs.filter((job) => job.status === "queued").length;
        const runningCount = jobs.filter((job) => job.status === "running").length;
        const bountyHunterToolsPath = resolveToolsPath("bounty-hunter");
        const hackeroneToolsPath = resolveToolsPath("hackerone-researcher");

        let bioniclinkReachable = false;
        try {
          const health = await bioniclinkHealth(bioniclinkBaseUrl, Math.min(750, bioniclinkTimeoutMs));
          bioniclinkReachable = Boolean(health && health.ok);
        } catch {
          bioniclinkReachable = false;
        }

        sendJson(res, 200, {
          status: "ok",
          service: "openclaw-bridge",
          timestamp: new Date().toISOString(),
          uptime_seconds: Math.floor(process.uptime()),
          queued_jobs: queuedCount,
          running_jobs: runningCount,
          mutation_guard_env_present: typeof process.env.BOUNTY_HUNTER_ALLOW_MUTATIONS !== "undefined",
          mutation_guard_enabled: isMutationGuardEnabled(),
          bounty_hunter_tools_path: bountyHunterToolsPath,
          h1_mutation_guard_env_present: typeof process.env.H1_ALLOW_MUTATIONS !== "undefined",
          h1_mutation_guard_enabled: isH1MutationGuardEnabled(),
          hackerone_researcher_tools_path: hackeroneToolsPath,
          bioniclink_base_url: bioniclinkBaseUrl,
          bioniclink_reachable: bioniclinkReachable,
          burp_active_scan_enabled: isBurpActiveScanEnabled(),
          burp_raw_data_env_present: typeof process.env.BURP_ALLOW_RAW_DATA !== "undefined",
          burp_raw_data_enabled: isBurpRawDataEnabled(),
        });
        return;
      }

      if (method === "GET" && route.type === "jobs") {
        sendJson(res, 200, { jobs: store.listJobs() });
        return;
      }

      if (method === "POST" && route.type === "jobs") {
        const body = await readBody(req);
        const submission = normalizeTaskSubmission(body);
        const job = await store.createJob(submission);
        worker.enqueue(job.id);
        sendJson(res, 201, { job });
        return;
      }

      if (method === "POST" && route.type === "execute-tool") {
        const body = await readBody(req);
        const parsed = parseExecuteToolBody(body);
        const executionResult = await executionRouter.execute(parsed.tool, parsed.args || {}, {
          requestId: `route-execute-${Date.now()}`,
          workspaceRoot,
          source: "http_api",
          caller: "bridge_execute_tool",
          authHeader: typeof req.headers.authorization === "string" ? req.headers.authorization : "",
          internalFlagRequested: parsed.internal === true,
          internalToken: parsed.internal_token,
          transportMetadata: {
            skill: parsed.skill,
          },
          legacyExecute: async (tool, legacyArgs) => {
            return executeLegacyBridgeRouteTool({
              parsed: {
                ...parsed,
                tool,
                args: legacyArgs,
              },
              bioniclinkBaseUrl,
              bioniclinkTimeoutMs,
            });
          },
        });

        if (!executionResult.ok) {
          sendError(res, resolveHttpErrorStatus(executionResult), executionResult.message || executionResult.code || "Execution failed");
          return;
        }

        const payload: Record<string, unknown> = {
          ok: true,
          tool: parsed.tool,
          result: executionResult.data,
          mutation_guard_enabled: isMutationGuardEnabled(),
          h1_mutation_guard_enabled: isH1MutationGuardEnabled(),
        };
        if (parsed.skill) {
          payload.skill = parsed.skill;
        }

        sendJson(res, 200, payload);
        return;
      }

      if (method === "POST" && route.type === "lldb-stop") {
        const body = await readBody(req);
        const record = asRecord(body);
        if (!record) {
          sendError(res, 400, "Request body must be a JSON object");
          return;
        }

        const event = record.event;
        if (!asRecord(event)) {
          sendError(res, 400, "event is required and must be a JSON object");
          return;
        }

        const eventCompact = JSON.stringify(event);
        const eventBytes = Buffer.byteLength(eventCompact, "utf-8");
        const maxBytes = 200 * 1024;
        if (eventBytes > maxBytes) {
          sendError(res, 413, `event too large (${eventBytes} bytes). Max allowed is ${maxBytes} bytes.`);
          return;
        }

        const instructionRaw = String(record.instruction || "").trim();
        const instruction = instructionRaw || "Triage this LLDB stop event (debugging-focused).";
        const requester = normalizeRequester(typeof record.requester === "string" ? record.requester : "lldb");
        const model = String(record.model || "").trim() || undefined;

        const job = await store.createJob({
          instruction,
          requester,
          model,
        });

        const eventPath = path.join(job.workspace_path, "LLDB_STOP_EVENT.json");
        const hints = [
          `LLDB stop event JSON saved at: ${eventPath}`,
          "",
          "Triage goals:",
          "- Provide a crash summary and likely root cause hypotheses.",
          "- Recommend next debugging steps and potential mitigations.",
          "",
          "Constraints:",
          "- Defensive debugging triage only.",
          "- Do not provide exploit, weaponization, or payload guidance.",
        ].join("\n");

        await fs.writeFile(eventPath, JSON.stringify(event, null, 2), "utf-8");
        const updated = await store.updateJob(job.id, {
          request: {
            ...job.request,
            hints,
          },
        });

        worker.enqueue(updated.id);
        sendJson(res, 201, { ok: true, job: updated });
        return;
      }

      if (method === "POST" && route.type === "bionic-ingest") {
        const body = await readBody(req);
        const record = asRecord(body);
        if (!record) {
          sendError(res, 400, "Request body must be a JSON object");
          return;
        }

        const instructionRaw = String(record.instruction || "").trim();
        const instruction =
          instructionRaw ||
          "Analyze this HTTP request/response pair for protocol stability risks. If risks are identified, output a FuzzingCandidate JSON object.";
        const requester = normalizeRequester(typeof record.requester === "string" ? record.requester : "bioniclink");
        const model = String(record.model || "").trim() || undefined;

        const payloadCandidate = asRecord(record.packet ?? record.pair ?? record.event);
        const payload = payloadCandidate && (typeof (payloadCandidate.url as unknown) === "string" || asRecord(payloadCandidate.request))
          ? payloadCandidate
          : record;

        const requestObj = asRecord(payload.request) || payload;
        const responseObj = asRecord(payload.response) || payload;

        const url = String(requestObj.url ?? payload.url ?? "").trim();
        if (!url) {
          sendError(res, 400, "Missing required url (expected payload.url or payload.request.url)");
          return;
        }

        const methodValue = String(requestObj.method ?? payload.method ?? "GET").trim().toUpperCase() || "GET";
        const requestHeaders = redactHeaders(
          normalizeBionicHeaders(requestObj.request_headers ?? requestObj.headers ?? payload.request_headers ?? payload.headers),
        );
        const responseHeaders = redactHeaders(normalizeBionicHeaders(responseObj.response_headers ?? responseObj.headers ?? payload.response_headers));

        const requestBodyBase64 = normalizeBase64Field(
          requestObj.request_body_base64 ?? requestObj.body_base64 ?? payload.request_body_base64 ?? payload.body_base64,
        );
        const responseBodyBase64 = normalizeBase64Field(
          responseObj.response_body_base64 ?? responseObj.body_base64 ?? payload.response_body_base64 ?? payload.body_base64,
        );

        const requestBodyBytes = requestBodyBase64 ? decodeBase64ToBuffer(requestBodyBase64) : null;
        const responseBodyBytes = responseBodyBase64 ? decodeBase64ToBuffer(responseBodyBase64) : null;

        const requestBodyText = truncateText(requestObj.request_body ?? requestObj.body ?? payload.request_body ?? payload.body, 64_000);
        const responseBodyText = truncateText(responseObj.response_body ?? responseObj.body ?? payload.response_body, 64_000);

        const requestBodyPreview = requestBodyText || bufferToTextPreview(requestBodyBytes, 64_000);
        const responseBodyPreview = responseBodyText || bufferToTextPreview(responseBodyBytes, 64_000);
        const statusRaw = responseObj.status ?? payload.status ?? 0;
        const status = typeof statusRaw === "number" ? statusRaw : statusRaw ? Number(statusRaw) : 0;

        const event = {
          version: 1,
          received_at: new Date().toISOString(),
          source: {
            tool: "bionic-ingest",
          },
          request: {
            url,
            method: methodValue,
            headers: requestHeaders,
            body_preview: requestBodyPreview,
            body_base64: requestBodyBase64,
          },
          response: {
            status: Number.isFinite(status) ? status : 0,
            headers: responseHeaders,
            body_preview: responseBodyPreview,
            body_base64: responseBodyBase64,
          },
          raw: {
            // Keep a small subset of optional fields if present, but avoid secrets.
            host: typeof requestObj.host === "string" ? requestObj.host : typeof payload.host === "string" ? payload.host : undefined,
            path: typeof requestObj.path === "string" ? requestObj.path : typeof payload.path === "string" ? payload.path : undefined,
            mime_type: typeof payload.mime_type === "string" ? payload.mime_type : undefined,
            in_scope: typeof payload.in_scope === "boolean" ? payload.in_scope : undefined,
            has_response: typeof payload.has_response === "boolean" ? payload.has_response : undefined,
          },
        };

        const eventCompact = JSON.stringify(event);
        const eventBytes = Buffer.byteLength(eventCompact, "utf-8");
        const maxBytes = 200 * 1024;
        if (eventBytes > maxBytes) {
          sendError(res, 413, `payload too large after normalization (${eventBytes} bytes). Max allowed is ${maxBytes} bytes.`);
          return;
        }

        const precheck = runStabilityPrecheck({
          url,
          requestHeaders,
          requestBody: requestBodyPreview,
          requestBodyBytes,
          responseHeaders,
          responseBody: responseBodyPreview,
          responseBodyBytes,
        });

        const job = await store.createJob({
          instruction,
          requester,
          model,
        });

        const eventPath = path.join(job.workspace_path, "BIONIC_INGEST_EVENT.json");
        const hintsLines: string[] = [];
        hintsLines.push(`Bionic ingest event JSON saved at: ${eventPath}`);
        hintsLines.push("");
        hintsLines.push("Stability analysis goals:");
        hintsLines.push("- Identify protocol deviations and input-handling risks that could cause application instability.");
        hintsLines.push("- Focus on integer width, format string anomalies, and risky serialization markers.");
        hintsLines.push("- If risks are identified, output a single FuzzingCandidate JSON object usable for a local stability harness.");
        hintsLines.push("");
        hintsLines.push("Constraints:");
        hintsLines.push("- Do NOT generate weaponized exploit payloads or shellcode.");
        hintsLines.push("- Do NOT provide instructions to bypass authentication.");
        hintsLines.push("- DO focus on input validation, memory safety, and RFC compliance.");

        if (precheck.length > 0) {
          hintsLines.push("");
          hintsLines.push("Bridge precheck findings (verify + expand):");
          for (const finding of precheck) {
            hintsLines.push(`- [${finding.kind}] ${finding.where}: ${finding.detail}`);
          }
        }

        const hints = hintsLines.join("\n");

        await fs.writeFile(eventPath, JSON.stringify(event, null, 2), "utf-8");
        const updated = await store.updateJob(job.id, {
          request: {
            ...job.request,
            hints,
          },
        });

        worker.enqueue(updated.id);
        sendJson(res, 201, { ok: true, job: updated, precheck_count: precheck.length });
        return;
      }

      if (method === "GET" && route.type === "job" && route.jobId) {
        const job = store.getJob(route.jobId);
        if (!job) {
          sendError(res, 404, `Job not found: ${route.jobId}`);
          return;
        }

        sendJson(res, 200, { job });
        return;
      }

      if (method === "POST" && route.type === "cancel" && route.jobId) {
        const existing = store.getJob(route.jobId);
        if (!existing) {
          sendError(res, 404, `Job not found: ${route.jobId}`);
          return;
        }

        if (existing.status === "succeeded" || existing.status === "failed" || existing.status === "cancelled") {
          sendJson(res, 200, { job: existing });
          return;
        }

        const job = await store.updateStatus(route.jobId, "cancelled", {
          summary: `Cancelled ${route.jobId}`,
          error_message: "Cancelled by user request.",
        });
        sendJson(res, 200, { job });
        return;
      }

      sendError(res, 404, `Route not found: ${method} ${requestUrl.pathname}`);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const statusCode =
        message.includes("required") ||
        message.includes("Invalid JSON body") ||
        message.includes("Unsupported URL protocol") ||
        message.includes("Request body must be a JSON object") ||
        message.includes("Unknown tool") ||
        message.includes("blocked:")
          ? 400
          : 500;
      sendError(res, statusCode, message);
    }
  }

  const listenHost = "127.0.0.1";
  // Debug: log the intended listen settings before attempting to bind
  // This helps diagnose cases where the server process starts but does not open the port.
  // eslint-disable-next-line no-console
  console.log(`Bridge bind intent -> host=${listenHost} port=${bridgePort} allowHttp=${allowHttp}`);

  try {
    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error) => {
        server.off("listening", onListening);
        reject(error);
      };
      const onListening = () => {
        server.off("error", onError);
        resolve();
      };

      server.once("error", onError);
      server.once("listening", onListening);
      server.listen(bridgePort, listenHost);
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const stack = error instanceof Error && error.stack ? `\n${error.stack}` : "";
    // eslint-disable-next-line no-console
    console.error(`Bridge failed to bind ${listenHost}:${bridgePort}: ${message}${stack}`);
    process.exit(1);
  }

  if (allowHttp) {
    // eslint-disable-next-line no-console
    console.log(`OpenClaw bridge listening on http://${listenHost}:${bridgePort}`);
  } else {
    // eslint-disable-next-line no-console
    console.log(`OpenClaw bridge listening on https://${listenHost}:${bridgePort}`);
    // eslint-disable-next-line no-console
    console.log(`TLS cert: ${process.env.BRIDGE_TLS_CERT_PATH || ''}`);
  }
  // eslint-disable-next-line no-console
  console.log(`Workspace root: ${workspaceRoot}`);
}

void main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  const stack = error instanceof Error && error.stack ? `\n${error.stack}` : "";
  // eslint-disable-next-line no-console
  console.error(`Bridge fatal startup error: ${message}${stack}`);
  process.exit(1);
});
