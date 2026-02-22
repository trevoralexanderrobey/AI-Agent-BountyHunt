/**
 * Burp Suite / BionicLink tools — proxy history, request analysis, active scan, raw data.
 * Communicates with BionicLink extension inside Burp Suite Pro at https://127.0.0.1:8090.
 * Safety gates: BURP_ALLOW_ACTIVE_SCAN, BURP_ALLOW_RAW_DATA.
 */

import { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import { assertGate, isBurpActiveScanEnabled, isBurpRawDataEnabled } from "../safety";

const DEFAULT_BIONICLINK_URL = "https://127.0.0.1:8090";
const DEFAULT_TIMEOUT_MS = 8_000;

function getBionicLinkUrl(): string {
  return (process.env.BIONICLINK_BASE_URL || "").trim() || DEFAULT_BIONICLINK_URL;
}

function getTimeoutMs(): number {
  const raw = Number.parseInt(process.env.BIONICLINK_TIMEOUT_MS || "", 10);
  return Number.isFinite(raw) && raw > 0 ? raw : DEFAULT_TIMEOUT_MS;
}

async function bionicFetch<T>(
  pathAndQuery: string,
  method: string,
  body?: unknown
): Promise<T> {
  const url = `${getBionicLinkUrl()}${pathAndQuery}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), getTimeoutMs());
  try {
    const opts: RequestInit = { method, signal: controller.signal };
    if (body !== undefined) {
      opts.headers = { "Content-Type": "application/json" };
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(url, opts);
    const text = await res.text();
    let data: T;
    try { data = JSON.parse(text) as T; }
    catch { throw new Error(`BionicLink returned non-JSON (${res.status}): ${text.slice(0, 500)}`); }
    return data;
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      throw new Error(`BionicLink timeout after ${getTimeoutMs()}ms`);
    }
    const msg = error instanceof Error ? error.message : String(error);
    if (msg.includes("ECONNREFUSED")) {
      throw new Error("BionicLink unreachable. Is Burp Suite running with the BionicLink extension loaded?");
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function normalizeUrl(input: string): string {
  const parsed = new URL(input.trim());
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`Unsupported URL protocol: ${input}`);
  }
  return parsed.toString();
}

interface ScopeResponse { ok: boolean; url: string; in_scope: boolean }

async function checkScope(targetUrl: string): Promise<ScopeResponse> {
  const encoded = encodeURIComponent(targetUrl);
  return bionicFetch<ScopeResponse>(`/scope?url=${encoded}`, "GET");
}

async function assertInScope(targetUrl: string): Promise<void> {
  const scope = await checkScope(targetUrl);
  if (!scope.ok) throw new Error("BionicLink /scope returned ok=false");
  if (!scope.in_scope) throw new Error("Target URL is out of scope (Burp Target Scope). Add it in Burp before retrying.");
}

export const burpTools: Tool[] = [
  {
    name: "burp_get_history",
    description:
      "Get Burp Suite proxy history. Returns summarized HTTP traffic with method, host, path, status, " +
      "auth headers (redacted), cookie names, and response body previews. Deduplicated by path pattern.",
    inputSchema: {
      type: "object" as const,
      properties: {
        limit: { type: "number", description: "Max items to return (default: 20)." },
        from_id: { type: "number", description: "Start from this proxy history ID." },
        in_scope: { type: "boolean", description: "Filter to in-scope items only (default: false)." },
      },
    },
  },
  {
    name: "burp_analyze_request",
    description:
      "Send an HTTP request through Burp Suite's Repeater and get the response. " +
      "Validates the URL is in Burp's Target Scope before sending.",
    inputSchema: {
      type: "object" as const,
      properties: {
        url: { type: "string", description: "Target URL to send the request to." },
        method: { type: "string", description: "HTTP method (default: GET)." },
        headers: { type: "object", description: "Request headers as key-value pairs.", additionalProperties: { type: "string" } },
        body: { type: "string", description: "Request body." },
      },
      required: ["url"],
    },
  },
  {
    name: "burp_active_scan",
    description:
      "Start a Burp Suite active scan on a URL. GATED: requires BURP_ALLOW_ACTIVE_SCAN=true. " +
      "Validates URL is in Burp's Target Scope.",
    inputSchema: {
      type: "object" as const,
      properties: {
        url: { type: "string", description: "Target URL to scan." },
        method: { type: "string", description: "HTTP method (default: GET)." },
        request_id: { type: "number", description: "Optional proxy history request ID to base the scan on." },
      },
      required: ["url"],
    },
  },
  {
    name: "burp_get_raw_request",
    description:
      "Get the raw request/response data for a specific proxy history item. " +
      "GATED: requires BURP_ALLOW_RAW_DATA=true. Validates URL is in scope.",
    inputSchema: {
      type: "object" as const,
      properties: {
        message_id: { type: "number", description: "Proxy history message ID to retrieve." },
      },
      required: ["message_id"],
    },
  },
];

export async function handleBurpTool(
  name: string,
  args: Record<string, unknown>
): Promise<CallToolResult> {
  try {
    if (name === "burp_get_history") {
      const limit = typeof args.limit === "number" ? args.limit : 20;
      const fromId = typeof args.from_id === "number" ? args.from_id : 0;
      const inScope = typeof args.in_scope === "boolean" ? args.in_scope : false;

      const params = new URLSearchParams();
      params.set("limit", String(limit));
      params.set("fromId", String(fromId));
      params.set("inScope", String(inScope));

      const data = await bionicFetch<Record<string, unknown>>(`/history?${params}`, "GET");
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }

    if (name === "burp_analyze_request") {
      const urlRaw = String(args.url || "").trim();
      if (!urlRaw) return { content: [{ type: "text", text: "Error: url is required" }], isError: true };

      const url = normalizeUrl(urlRaw);
      await assertInScope(url);

      const method = typeof args.method === "string" ? args.method.trim().toUpperCase() : "GET";
      const headers = (args.headers && typeof args.headers === "object" && !Array.isArray(args.headers))
        ? Object.fromEntries(Object.entries(args.headers as Record<string, unknown>).map(([k, v]) => [k, String(v ?? "")]))
        : {};
      const body = typeof args.body === "string" ? args.body : undefined;

      const data = await bionicFetch<Record<string, unknown>>("/repeater", "POST", { url, method, headers, body });
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }

    if (name === "burp_active_scan") {
      assertGate("BURP_ALLOW_ACTIVE_SCAN", isBurpActiveScanEnabled());

      const urlRaw = String(args.url || "").trim();
      if (!urlRaw) return { content: [{ type: "text", text: "Error: url is required" }], isError: true };

      const url = normalizeUrl(urlRaw);
      await assertInScope(url);

      const method = typeof args.method === "string" ? args.method.trim().toUpperCase() : "GET";
      const requestId = typeof args.request_id === "number" ? args.request_id : undefined;

      const data = await bionicFetch<Record<string, unknown>>("/scan", "POST", { url, method, requestId });
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }

    if (name === "burp_get_raw_request") {
      assertGate("BURP_ALLOW_RAW_DATA", isBurpRawDataEnabled());

      const messageId = typeof args.message_id === "number" ? args.message_id : NaN;
      if (!Number.isFinite(messageId) || messageId < 1) {
        return { content: [{ type: "text", text: "Error: message_id must be a positive integer" }], isError: true };
      }

      // Fetch history slice containing the message
      const history = await bionicFetch<{ ok: boolean; items: Array<{ id: number; url: string; [k: string]: unknown }> }>(
        "/history?limit=200&fromId=0&inScope=false", "GET"
      );
      if (!history.ok) {
        return { content: [{ type: "text", text: "Error: BionicLink /history returned ok=false" }], isError: true };
      }

      const item = (history.items || []).find((it) => it.id === messageId);
      if (!item) {
        return { content: [{ type: "text", text: `Error: Message ID ${messageId} not found in recent proxy history` }], isError: true };
      }

      const url = String(item.url || "").trim();
      if (url) await assertInScope(url);

      return { content: [{ type: "text", text: JSON.stringify(item, null, 2) }] };
    }

    return { content: [{ type: "text", text: `Unknown tool: ${name}` }], isError: true };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    return { content: [{ type: "text", text: `Burp tool error: ${msg}` }], isError: true };
  }
}
