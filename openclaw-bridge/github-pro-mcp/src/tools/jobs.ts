/**
 * Job queue tools — submit, list, get, and cancel jobs on the OpenClaw bridge API.
 * Default bridge URL is HTTPS loopback (https://127.0.0.1:8787) but can be overridden
 * by setting `OPENCLAW_BRIDGE_BASE_URL` or `BRIDGE_BASE_URL` in the environment.
 */

import { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";

const DEFAULT_BRIDGE_URL = "https://127.0.0.1:8787";

function getBridgeUrl(): string {
  return (process.env.OPENCLAW_BRIDGE_BASE_URL || process.env.BRIDGE_BASE_URL || "").trim() || DEFAULT_BRIDGE_URL;
}

async function bridgeFetch(
  pathAndQuery: string,
  method: string,
  body?: unknown
): Promise<{ ok: boolean; status: number; data: unknown }> {
  const url = `${getBridgeUrl()}${pathAndQuery}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15_000);
  try {
    const options: RequestInit = { method, signal: controller.signal };
    if (body !== undefined) {
      options.headers = { "Content-Type": "application/json" };
      options.body = JSON.stringify(body);
    }
    const res = await fetch(url, options);
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

export const jobTools: Tool[] = [
  {
    name: "job_submit",
    description:
      "Submit a background job to the OpenClaw bridge job queue. " +
      "Jobs are processed asynchronously and produce mission reports.",
    inputSchema: {
      type: "object" as const,
      properties: {
        instruction: {
          type: "string",
          description: "What the job should accomplish.",
        },
        repo_url: {
          type: "string",
          description: "Optional Git repository URL to clone and work in.",
        },
        context_urls: {
          type: "array",
          items: { type: "string" },
          description: "Optional context URLs (issues, docs) for the job.",
        },
        hints: {
          type: "string",
          description: "Optional hints/context to guide the executor.",
        },
        branch_name: {
          type: "string",
          description: "Optional branch name override.",
        },
        requester: {
          type: "string",
          description: "Requester identifier (default: github-pro).",
        },
        model: {
          type: "string",
          description: "Model override for the executor.",
        },
        gateway_base_url: {
          type: "string",
          description: "Override the gateway base URL for this job. Default: Ollama at http://localhost:11434/v1. Use http://127.0.0.1:18789/v1 for the OpenClaw cloud gateway.",
        },
      },
      required: ["instruction"],
    },
  },
  {
    name: "job_list",
    description: "List all jobs in the OpenClaw bridge queue (most recent first).",
    inputSchema: {
      type: "object" as const,
      properties: {},
    },
  },
  {
    name: "job_status",
    description: "Get the status and details of a specific job by ID.",
    inputSchema: {
      type: "object" as const,
      properties: {
        job_id: {
          type: "string",
          description: "The job ID to look up.",
        },
      },
      required: ["job_id"],
    },
  },
  {
    name: "job_cancel",
    description: "Cancel a queued or running job.",
    inputSchema: {
      type: "object" as const,
      properties: {
        job_id: {
          type: "string",
          description: "The job ID to cancel.",
        },
      },
      required: ["job_id"],
    },
  },
];

export async function handleJobTool(
  name: string,
  args: Record<string, unknown>
): Promise<CallToolResult> {
  if (name === "job_submit") {
    const instruction = String(args.instruction || "").trim();
    if (!instruction) {
      return { content: [{ type: "text", text: "Error: instruction is required" }], isError: true };
    }

    const body: Record<string, unknown> = {
      instruction,
      requester: typeof args.requester === "string" ? args.requester : "github-pro",
    };
    if (typeof args.repo_url === "string") body.repo_url = args.repo_url;
    if (Array.isArray(args.context_urls)) body.context_urls = args.context_urls;
    if (typeof args.hints === "string") body.hints = args.hints;
    if (typeof args.branch_name === "string") body.branch_name = args.branch_name;
    if (typeof args.model === "string") body.model = args.model;
    if (typeof args.gateway_base_url === "string") body.gateway_base_url = args.gateway_base_url;

    const result = await bridgeFetch("/jobs", "POST", body);
    return {
      content: [{ type: "text", text: JSON.stringify(result.data, null, 2) }],
      isError: !result.ok,
    };
  }

  if (name === "job_list") {
    const result = await bridgeFetch("/jobs", "GET");
    return {
      content: [{ type: "text", text: JSON.stringify(result.data, null, 2) }],
      isError: !result.ok,
    };
  }

  if (name === "job_status") {
    const jobId = String(args.job_id || "").trim();
    if (!jobId) {
      return { content: [{ type: "text", text: "Error: job_id is required" }], isError: true };
    }
    const result = await bridgeFetch(`/jobs/${encodeURIComponent(jobId)}`, "GET");
    return {
      content: [{ type: "text", text: JSON.stringify(result.data, null, 2) }],
      isError: !result.ok,
    };
  }

  if (name === "job_cancel") {
    const jobId = String(args.job_id || "").trim();
    if (!jobId) {
      return { content: [{ type: "text", text: "Error: job_id is required" }], isError: true };
    }
    const result = await bridgeFetch(`/jobs/${encodeURIComponent(jobId)}/cancel`, "POST");
    return {
      content: [{ type: "text", text: JSON.stringify(result.data, null, 2) }],
      isError: !result.ok,
    };
  }

  return { content: [{ type: "text", text: `Unknown tool: ${name}` }], isError: true };
}
