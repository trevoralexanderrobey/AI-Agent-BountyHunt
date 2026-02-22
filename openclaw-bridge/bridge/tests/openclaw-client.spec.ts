import { afterEach, describe, expect, it, vi } from "vitest";
import { extractAgentReplyTextFromCliJson, OpenClawClient } from "../openclaw-client";

describe("openclaw-client (cli json parsing)", () => {
  it("extracts concatenated payload text", () => {
    const fixture = {
      ok: true,
      result: {
        payloads: [{ text: "First line" }, { text: "Second line" }],
      },
      summary: "ignored",
    };

    expect(extractAgentReplyTextFromCliJson(fixture)).toBe("First line\nSecond line");
  });

  it("extracts text parts from content arrays", () => {
    const fixture = {
      ok: true,
      result: {
        payloads: [
          {
            content: [
              { type: "text", text: "Hello" },
              { type: "toolcall", name: "noop", arguments: {} },
              { type: "text", text: "World" },
            ],
          },
        ],
      },
    };

    expect(extractAgentReplyTextFromCliJson(fixture)).toBe("Hello\nWorld");
  });

  it("falls back to summary when payloads are empty", () => {
    const fixture = {
      ok: true,
      result: { payloads: [] },
      summary: "No reply from agent.",
    };

    expect(extractAgentReplyTextFromCliJson(fixture)).toBe("No reply from agent.");
  });
});

describe("openclaw-client (provider multiplexing)", () => {
  const originalEnv = { ...process.env };

  afterEach(() => {
    process.env = { ...originalEnv };
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("does not treat model tags like openthinker:7b as provider prefixes", async () => {
    process.env.OPENCLAW_TRANSPORT = "http";
    process.env.OPENCLAW_GATEWAY_BASE_URL = "http://127.0.0.1:11434/v1";
    process.env.OPENCLAW_OPENTHINKER_BASE_URL = "http://127.0.0.1:19999/v1";

    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      expect(url).toBe("http://127.0.0.1:11434/v1/responses");
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

    const client = new OpenClawClient();
    const result = await client.runTask({
      jobId: "job-1",
      submission: {
        instruction: "Say ok",
        requester: "codex",
        model: "openthinker:7b",
      },
    });

    expect(result.text).toBe("ok");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("routes explicit qwen:model to provider base URL and API key", async () => {
    process.env.OPENCLAW_TRANSPORT = "http";
    process.env.OPENCLAW_GATEWAY_BASE_URL = "http://127.0.0.1:11434/v1";
    process.env.OPENCLAW_QWEN_BASE_URL = "http://127.0.0.1:18080/v1";
    process.env.OPENCLAW_QWEN_API_KEY = "qwen-token";

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

    const client = new OpenClawClient();
    const result = await client.runTask({
      jobId: "job-2",
      submission: {
        instruction: "Say qwen ok",
        requester: "codex",
        model: "qwen:qwen3-32b",
      },
    });

    expect(result.text).toBe("qwen ok");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
