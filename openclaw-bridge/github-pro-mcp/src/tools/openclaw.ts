/**
 * OpenClaw exec and terminal tools — direct agent invocation and shell execution.
 */

import { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { openclawExec } from "../openclaw-client";

const execFileAsync = promisify(execFile);

/**
 * Build a sanitized environment for child processes.
 * Only forward safe, known env vars — never leak secrets like API tokens.
 */
function getSafeEnv(): Record<string, string> {
  const ALLOWED_ENV_KEYS = [
    "PATH", "HOME", "USER", "SHELL", "LANG", "LC_ALL", "LC_CTYPE",
    "TERM", "TMPDIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME",
    "NODE_ENV", "npm_config_prefix", "NVM_DIR", "NVM_BIN",
    "HOMEBREW_PREFIX", "HOMEBREW_CELLAR", "HOMEBREW_REPOSITORY",
    // OpenClaw-specific (non-secret)
    "OPENCLAW_TRANSPORT", "OPENCLAW_DEFAULT_MODEL",
    "OPENCLAW_GATEWAY_BASE_URL", "OPENCLAW_BRIDGE_BASE_URL",
    "BIONICLINK_BASE_URL",
  ];

  const env: Record<string, string> = {};
  for (const key of ALLOWED_ENV_KEYS) {
    if (process.env[key]) {
      env[key] = process.env[key]!;
    }
  }
  return env;
}

export const openclawTools: Tool[] = [
  {
    name: "openclaw_exec",
    description:
      "Send a prompt to the OpenClaw agent for execution. OpenClaw will reason about and execute the task autonomously. " +
      "Use this to delegate complex engineering, security research, or bounty work to the OpenClaw executor.",
    inputSchema: {
      type: "object" as const,
      properties: {
        prompt: {
          type: "string",
          description: "The instruction/prompt for the OpenClaw agent to execute.",
        },
        system_prompt: {
          type: "string",
          description: "Optional system prompt to set the agent's persona (defaults to senior engineer).",
        },
        model: {
          type: "string",
          description: "Model override (default: openthinker:7b). E.g., openthinker:7b, openclaw-sonnet-4, openclaw-gpt-4o.",
        },
        gateway_base_url: {
          type: "string",
          description: "Override the gateway base URL. Default: Ollama at http://localhost:11434/v1. Use http://127.0.0.1:18789/v1 for the OpenClaw cloud gateway.",
        },
        session_id: {
          type: "string",
          description: "Optional session ID for conversation continuity.",
        },
        timeout_ms: {
          type: "number",
          description: "Timeout in milliseconds (default: 180000).",
        },
      },
      required: ["prompt"],
    },
  },
  {
    name: "openclaw_terminal",
    description:
      "Execute shell commands on the local system via OpenClaw's terminal capability. " +
      "Use for builds, tests, git ops, service control, and other system tasks.",
    inputSchema: {
      type: "object" as const,
      properties: {
        command: {
          type: "string",
          description: "The shell command to execute.",
        },
        cwd: {
          type: "string",
          description: "Working directory for the command.",
        },
        timeout_ms: {
          type: "number",
          description: "Timeout in milliseconds (default: 30000).",
        },
      },
      required: ["command"],
    },
  },
];

export async function handleOpenclawTool(
  name: string,
  args: Record<string, unknown>
): Promise<CallToolResult> {
  if (name === "openclaw_exec") {
    const prompt = String(args.prompt || "");
    if (!prompt.trim()) {
      return { content: [{ type: "text", text: "Error: prompt is required" }], isError: true };
    }

    const result = await openclawExec({
      prompt,
      systemPrompt: typeof args.system_prompt === "string" ? args.system_prompt : undefined,
      model: typeof args.model === "string" ? args.model : undefined,
      gatewayBaseUrl: typeof args.gateway_base_url === "string" ? args.gateway_base_url : undefined,
      sessionId: typeof args.session_id === "string" ? args.session_id : undefined,
      timeoutMs: typeof args.timeout_ms === "number" ? args.timeout_ms : undefined,
    });

    return {
      content: [
        { type: "text", text: `**Model:** ${result.model}\n\n${result.text}` },
      ],
    };
  }

  if (name === "openclaw_terminal") {
    const command = String(args.command || "");
    if (!command.trim()) {
      return { content: [{ type: "text", text: "Error: command is required" }], isError: true };
    }

    const cwd = typeof args.cwd === "string" ? args.cwd : undefined;
    const timeoutMs = typeof args.timeout_ms === "number" ? Math.min(args.timeout_ms, 120_000) : 30_000;

    let stdout = "";
    let stderr = "";
    let exitCode = 0;
    try {
      const result = await execFileAsync("/bin/zsh", ["-c", command], {
        timeout: timeoutMs,
        maxBuffer: 8 * 1024 * 1024,
        cwd,
        env: getSafeEnv(),
      });
      stdout = String(result.stdout || "");
      stderr = String(result.stderr || "");
    } catch (error) {
      const err = error as { stdout?: string; stderr?: string; code?: number; message?: string };
      stdout = String(err.stdout || "");
      stderr = String(err.stderr || err.message || "");
      exitCode = typeof err.code === "number" ? err.code : 1;
    }

    const output = [
      stdout.trim() ? `**stdout:**\n\`\`\`\n${stdout.trim()}\n\`\`\`` : "",
      stderr.trim() ? `**stderr:**\n\`\`\`\n${stderr.trim()}\n\`\`\`` : "",
      `**exit code:** ${exitCode}`,
    ]
      .filter(Boolean)
      .join("\n\n");

    return {
      content: [{ type: "text", text: output }],
      isError: exitCode !== 0,
    };
  }

  return { content: [{ type: "text", text: `Unknown tool: ${name}` }], isError: true };
}
