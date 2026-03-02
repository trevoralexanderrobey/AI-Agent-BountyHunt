import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { describe, expect, it } from "vitest";

const BRIDGE_ROOT = "/Users/trevorrobey/AI-Agent-BountyHunt/openclaw-bridge";

interface StartedBridge {
  port: number;
  proc: ReturnType<typeof spawn>;
}

async function waitForHealth(port: number, authToken?: string, timeoutMs = 15000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/health`, {
        headers: authToken
          ? {
              Authorization: `Bearer ${authToken}`,
            }
          : undefined,
      });
      if (response.ok) {
        return;
      }
    } catch {
      // retry
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(`bridge health timeout on port ${port}`);
}

async function startBridgeServer(port: number, extraEnv: Record<string, string> = {}): Promise<StartedBridge> {
  const workspaceRoot = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-bridge-mcp-sse-"));
  const supervisorToken = String(extraEnv.SUPERVISOR_AUTH_TOKEN || "").trim();
  if (supervisorToken) {
    const clineDir = path.join(workspaceRoot, ".cline");
    await fs.mkdir(clineDir, { recursive: true });
    const tokenPath = path.join(clineDir, "cline_mcp_settings.json");
    await fs.writeFile(tokenPath, JSON.stringify({ token: supervisorToken }, null, 2), { encoding: "utf8", mode: 0o600 });
    await fs.chmod(tokenPath, 0o600);
  }
  const tsxCli = path.join(BRIDGE_ROOT, "node_modules", "tsx", "dist", "cli.mjs");
  const proc = spawn(process.execPath, [tsxCli, "bridge/server.ts"], {
    cwd: BRIDGE_ROOT,
    env: {
      ...process.env,
      BRIDGE_HTTP: "true",
      BRIDGE_PORT: String(port),
      BRIDGE_WORKSPACE_ROOT: workspaceRoot,
      OPENCLAW_GATEWAY_BASE_URL: "http://127.0.0.1:11434/v1",
      MCP_SSE_KEEPALIVE_MS: "1000",
      ...extraEnv,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  await waitForHealth(port, extraEnv.BRIDGE_AUTH_TOKEN);
  return { port, proc };
}

async function stopBridgeServer(proc: ReturnType<typeof spawn>): Promise<void> {
  proc.kill("SIGTERM");
  await new Promise<void>((resolve) => {
    proc.once("exit", () => resolve());
  });
}

function extractSseEvent(buffer: { data: string }) {
  const idx = buffer.data.indexOf("\n\n");
  if (idx < 0) {
    return null;
  }
  const block = buffer.data.slice(0, idx);
  buffer.data = buffer.data.slice(idx + 2);
  const lines = block.split(/\r?\n/).map((line) => line.trim());
  let eventName = "message";
  const dataLines: string[] = [];
  for (const line of lines) {
    if (!line || line.startsWith(":")) {
      continue;
    }
    if (line.startsWith("event:")) {
      eventName = line.slice("event:".length).trim();
      continue;
    }
    if (line.startsWith("data:")) {
      dataLines.push(line.slice("data:".length).trim());
    }
  }
  return {
    event: eventName,
    data: dataLines.join("\n"),
  };
}

async function waitForSseCondition<T>(
  state: { events: Array<{ event: string; data: string }> },
  matcher: (events: Array<{ event: string; data: string }>) => T | null,
  timeoutMs = 10000,
): Promise<T> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const result = matcher(state.events);
    if (result !== null) {
      return result;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("timed out waiting for SSE condition");
}

describe("bridge MCP SSE endpoint", () => {
  it("serves MCP SSE handshake, keepalive, and tool calls", async () => {
    const port = 18887;
    const token = "mcp-supervisor-token";
    const authHeaders = {
      Authorization: `Bearer ${token}`,
    };
    const bridge = await startBridgeServer(port, { SUPERVISOR_AUTH_TOKEN: token });
    let sseResponse: Response | null = null;
    try {
      sseResponse = await fetch(`http://127.0.0.1:${port}/mcp/sse`, { headers: authHeaders });
      expect(sseResponse.ok).toBe(true);
      expect(String(sseResponse.headers.get("content-type") || "")).toContain("text/event-stream");

      const reader = sseResponse.body?.getReader();
      expect(Boolean(reader)).toBe(true);

      const decoder = new TextDecoder();
      const stream = { data: "" };
      const state = { events: [] as Array<{ event: string; data: string }> };

      const consume = (async () => {
        while (true) {
          const result = await reader!.read();
          if (result.done) {
            break;
          }
          stream.data += decoder.decode(result.value, { stream: true });
          while (true) {
            const parsed = extractSseEvent(stream);
            if (!parsed) break;
            state.events.push(parsed);
          }
        }
      })();

      const endpointEvent = await waitForSseCondition(state, (events) =>
        events.find((entry) => entry.event === "endpoint" && entry.data.includes("/mcp/messages?sessionId=")) || null,
      );

      const endpointPath = endpointEvent.data;
      const endpointUrl = new URL(`http://127.0.0.1:${port}${endpointPath}`);
      const sessionId = String(endpointUrl.searchParams.get("sessionId") || "");
      expect(sessionId.length).toBeGreaterThan(5);

      const initializeBody = {
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: {
            name: "bridge-sse-test",
            version: "0.0.1",
          },
        },
      };

      const initResponse = await fetch(endpointUrl, {
        method: "POST",
        headers: { "content-type": "application/json", ...authHeaders },
        body: JSON.stringify(initializeBody),
      });
      expect(initResponse.status).toBe(202);

      await waitForSseCondition(state, (events) => {
        for (const event of events) {
          if (event.event !== "message") continue;
          try {
            const payload = JSON.parse(event.data);
            if (payload?.id === 1 && payload?.result?.serverInfo?.name === "openclaw-bridge-sse-mcp") {
              return payload;
            }
          } catch {
            // continue
          }
        }
        return null;
      });

      const initializedBody = {
        jsonrpc: "2.0",
        method: "notifications/initialized",
        params: {},
      };
      const initializedResponse = await fetch(endpointUrl, {
        method: "POST",
        headers: { "content-type": "application/json", ...authHeaders },
        body: JSON.stringify(initializedBody),
      });
      expect(initializedResponse.status).toBe(202);

      const listToolsBody = {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/list",
        params: {},
      };
      const listResponse = await fetch(endpointUrl, {
        method: "POST",
        headers: { "content-type": "application/json", ...authHeaders },
        body: JSON.stringify(listToolsBody),
      });
      expect(listResponse.status).toBe(202);

      const toolsMessage = await waitForSseCondition(state, (events) => {
        for (const event of events) {
          if (event.event !== "message") continue;
          try {
            const payload = JSON.parse(event.data);
            if (payload?.id === 2) {
              return payload;
            }
          } catch {
            // continue
          }
        }
        return null;
      });
      const toolNames = Array.isArray(toolsMessage?.result?.tools)
        ? toolsMessage.result.tools.map((item: { name?: string }) => item?.name).filter(Boolean)
        : [];
      expect(toolNames).toContain("bridge_health");
      expect(toolNames).toContain("bridge_execute_tool");

      const healthCallBody = {
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: {
          name: "bridge_health",
          arguments: {},
        },
      };
      const healthCallResponse = await fetch(endpointUrl, {
        method: "POST",
        headers: { "content-type": "application/json", ...authHeaders },
        body: JSON.stringify(healthCallBody),
      });
      expect(healthCallResponse.status).toBe(202);

      const healthMessage = await waitForSseCondition(state, (events) => {
        for (const event of events) {
          if (event.event !== "message") continue;
          try {
            const payload = JSON.parse(event.data);
            if (payload?.id === 3) {
              return payload;
            }
          } catch {
            // continue
          }
        }
        return null;
      });
      const text = String(healthMessage?.result?.content?.[0]?.text || "");
      expect(text).toContain("\"service\": \"openclaw-bridge\"");

      await waitForSseCondition(state, (events) => {
        return events.some((entry) => entry.event === "message" || entry.event === "endpoint") ? true : null;
      });

      await reader!.cancel();
      await consume;
    } finally {
      if (sseResponse?.body) {
        try {
          await sseResponse.body.cancel();
        } catch {
          // ignore
        }
      }
      await stopBridgeServer(bridge.proc);
    }
  });

  it("enforces BRIDGE_AUTH_TOKEN on MCP SSE endpoints", async () => {
    const port = 18888;
    const token = "bridge-token-test";
    const bridge = await startBridgeServer(port, { BRIDGE_AUTH_TOKEN: token });
    try {
      const unauthorized = await fetch(`http://127.0.0.1:${port}/mcp/sse`);
      expect(unauthorized.status).toBe(401);

      const authorized = await fetch(`http://127.0.0.1:${port}/mcp/sse`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      expect(authorized.ok).toBe(true);
      await authorized.body?.cancel();
    } finally {
      await stopBridgeServer(bridge.proc);
    }
  });
});
