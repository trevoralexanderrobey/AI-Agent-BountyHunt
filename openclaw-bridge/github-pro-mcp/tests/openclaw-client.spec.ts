import { afterEach, describe, expect, it, vi } from "vitest";
import { openclawExec } from "../src/openclaw-client";

describe("github-pro-mcp openclaw-client provider multiplexing", () => {
  const originalEnv = { ...process.env };

  afterEach(() => {
    process.env = { ...originalEnv };
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("keeps openthinker:7b as model id (not provider prefix)", async () => {
    process.env.OPENCLAW_TRANSPORT = "http";
    process.env.OPENCLAW_GATEWAY_BASE_URL = "http://127.0.0.1:11434/v1";
    process.env.OPENCLAW_API_KEY = "global-token";
    process.env.OPENCLAW_OPENTHINKER_BASE_URL = "http://127.0.0.1:19999/v1";

    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      expect(url).toBe("http://127.0.0.1:11434/v1/responses");
      expect((init?.headers as Record<string, string>)?.Authorization).toBe("Bearer global-token");
      const payload = JSON.parse(String(init?.body || "{}")) as { model?: string };
      expect(payload.model).toBe("openthinker:7b");
      return {
        ok: true,
        status: 200,
        statusText: "OK",
        text: async () => JSON.stringify({ output_text: "ok" }),
      } as unknown as Response;
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await openclawExec({
      prompt: "Say ok",
      model: "openthinker:7b",
    });

    expect(result.text).toBe("ok");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("routes qwen:model to provider base URL and provider API key", async () => {
    process.env.OPENCLAW_TRANSPORT = "http";
    process.env.OPENCLAW_GATEWAY_BASE_URL = "http://127.0.0.1:11434/v1";
    process.env.OPENCLAW_QWEN_BASE_URL = "http://127.0.0.1:18080/v1";
    process.env.OPENCLAW_QWEN_API_KEY = "qwen-token";
    delete process.env.OPENCLAW_API_KEY;

    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      expect(url).toBe("http://127.0.0.1:18080/v1/responses");
      expect((init?.headers as Record<string, string>)?.Authorization).toBe("Bearer qwen-token");
      const payload = JSON.parse(String(init?.body || "{}")) as { model?: string };
      expect(payload.model).toBe("qwen3-32b");
      return {
        ok: true,
        status: 200,
        statusText: "OK",
        text: async () => JSON.stringify({ output_text: "qwen ok" }),
      } as unknown as Response;
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await openclawExec({
      prompt: "Say qwen ok",
      model: "qwen:qwen3-32b",
    });

    expect(result.text).toBe("qwen ok");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
