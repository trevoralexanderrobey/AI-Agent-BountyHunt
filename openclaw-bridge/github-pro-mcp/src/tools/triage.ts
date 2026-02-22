/**
 * Triage tools — LLDB crash triage and bionic HTTP pair stability analysis.
 * Submits events to the bridge job queue for asynchronous agent-assisted analysis.
 */

import { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";

const DEFAULT_BRIDGE_URL = "https://127.0.0.1:8787";

function getBridgeUrl(): string {
  return (process.env.OPENCLAW_BRIDGE_BASE_URL || process.env.BRIDGE_BASE_URL || "").trim() || DEFAULT_BRIDGE_URL;
}

async function bridgePost(
  path: string,
  body: unknown
): Promise<{ ok: boolean; status: number; data: unknown }> {
  const url = `${getBridgeUrl()}${path}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15_000);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    const text = await res.text();
    let data: unknown;
    try { data = JSON.parse(text); } catch { data = text; }
    return { ok: res.ok, status: res.status, data };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    if (msg.includes("ECONNREFUSED")) {
      throw new Error(`Bridge unreachable at ${getBridgeUrl()}. Is the bridge running? (npm run bridge:start)`);
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

export const triageTools: Tool[] = [
  {
    name: "lldb_triage",
    description:
      "Submit an LLDB crash/exception stop event for agent-assisted triage. " +
      "Creates a background job that analyzes registers, backtrace, and exception state. " +
      "Returns root cause hypotheses and debugging steps. No exploit guidance.",
    inputSchema: {
      type: "object" as const,
      properties: {
        event: {
          type: "object",
          description: "LLDB stop event data (registers, backtrace, exception state, etc.).",
          additionalProperties: true,
        },
        instruction: {
          type: "string",
          description: "Optional triage instruction override.",
        },
        model: {
          type: "string",
          description: "Model override for triage analysis.",
        },
      },
      required: ["event"],
    },
  },
  {
    name: "bionic_ingest",
    description:
      "Submit an HTTP request/response pair for protocol stability analysis. " +
      "Bridge runs server-side prechecks (integer width, format string, serialization magic) " +
      "then creates a background triage job. Returns FuzzingCandidate or NoFinding JSON.",
    inputSchema: {
      type: "object" as const,
      properties: {
        url: {
          type: "string",
          description: "The request URL.",
        },
        method: {
          type: "string",
          description: "HTTP method (default: GET).",
        },
        request_headers: {
          type: "object",
          description: "Request headers as key-value pairs.",
          additionalProperties: { type: "string" },
        },
        request_body: {
          type: "string",
          description: "Request body content.",
        },
        response_status: {
          type: "number",
          description: "Response status code.",
        },
        response_headers: {
          type: "object",
          description: "Response headers as key-value pairs.",
          additionalProperties: { type: "string" },
        },
        response_body: {
          type: "string",
          description: "Response body content.",
        },
        instruction: {
          type: "string",
          description: "Optional analysis instruction override.",
        },
        model: {
          type: "string",
          description: "Model override for stability analysis.",
        },
      },
      required: ["url"],
    },
  },
];

export async function handleTriageTool(
  name: string,
  args: Record<string, unknown>
): Promise<CallToolResult> {
  try {
    if (name === "lldb_triage") {
      if (!args.event || typeof args.event !== "object") {
        return { content: [{ type: "text", text: "Error: event object is required" }], isError: true };
      }

      const body: Record<string, unknown> = { event: args.event };
      if (typeof args.instruction === "string") body.instruction = args.instruction;
      if (typeof args.model === "string") body.model = args.model;
      body.requester = "github-pro";

      const result = await bridgePost("/lldb-stop", body);
      return {
        content: [{ type: "text", text: JSON.stringify(result.data, null, 2) }],
        isError: !result.ok,
      };
    }

    if (name === "bionic_ingest") {
      const url = String(args.url || "").trim();
      if (!url) {
        return { content: [{ type: "text", text: "Error: url is required" }], isError: true };
      }

      const body: Record<string, unknown> = {
        requester: "github-pro",
        packet: {
          url,
          method: typeof args.method === "string" ? args.method : "GET",
          request: {
            url,
            method: typeof args.method === "string" ? args.method : "GET",
            headers: args.request_headers || {},
            body: typeof args.request_body === "string" ? args.request_body : "",
          },
          response: {
            status: typeof args.response_status === "number" ? args.response_status : 0,
            headers: args.response_headers || {},
            body: typeof args.response_body === "string" ? args.response_body : "",
          },
        },
      };
      if (typeof args.instruction === "string") body.instruction = args.instruction;
      if (typeof args.model === "string") body.model = args.model;

      const result = await bridgePost("/bionic-ingest", body);
      return {
        content: [{ type: "text", text: JSON.stringify(result.data, null, 2) }],
        isError: !result.ok,
      };
    }

    return { content: [{ type: "text", text: `Unknown tool: ${name}` }], isError: true };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    return { content: [{ type: "text", text: `Triage tool error: ${msg}` }], isError: true };
  }
}
