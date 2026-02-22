/**
 * OpenClaw client — adapted from bridge/openclaw-client.ts.
 * Supports CLI transport (default) and HTTP transport with /v1/responses + /v1/chat/completions fallback.
 */

import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const DEFAULT_BASE_URL = "https://127.0.0.1:18789/v1";
const DEFAULT_MODEL = "openthinker:7b";
const DEFAULT_TIMEOUT_MS = 180_000;

type Transport = "cli" | "http";

export interface ExecResult {
  model: string;
  text: string;
  raw: unknown;
}

export interface ExecOptions {
  sessionId?: string;
  prompt: string;
  systemPrompt?: string;
  model?: string;
  gatewayBaseUrl?: string;
  authToken?: string;
  timeoutMs?: number;
}

function getTransport(): Transport {
  const value = (process.env.OPENCLAW_TRANSPORT || "").trim().toLowerCase();
  return value === "http" ? "http" : "cli";
}

function getCliPath(): string {
  return (process.env.OPENCLAW_CLI_PATH || "").trim() || "openclaw";
}

function normalizeGatewayUrl(value: string): string {
  const trimmed = value.trim().replace(/\/$/, "");
  return trimmed.endsWith("/v1") ? trimmed : `${trimmed}/v1`;
}

function providerToEnvSegment(provider: string): string {
  return provider.trim().toUpperCase().replace(/[^A-Z0-9]+/g, "_");
}

function parseProviderFromModel(model: string): { provider?: string; modelId: string } {
  const raw = String(model || "").trim();
  if (!raw) return { modelId: raw };

  const slashIndex = raw.indexOf("/");
  if (slashIndex > 0) return { provider: raw.slice(0, slashIndex).toLowerCase(), modelId: raw.slice(slashIndex + 1) };

  const colonIndex = raw.indexOf(":");
  if (colonIndex > 0) {
    const provider = raw.slice(0, colonIndex).toLowerCase();
    const modelId = raw.slice(colonIndex + 1);
    const knownProviders = new Set(["qwen", "openai", "anthropic", "groq", "ollama", "openrouter", "deepseek", "mistral", "xai"]);
    if (knownProviders.has(provider)) {
      return { provider, modelId };
    }
  }
  return { modelId: raw };
}

function resolveProviderBaseUrl(provider: string | undefined, submissionBase?: string, fallbackBase?: string): string {
  if (submissionBase && String(submissionBase).trim()) return normalizeGatewayUrl(String(submissionBase));
  if (!provider) return fallbackBase || DEFAULT_BASE_URL;
  const envKey = `OPENCLAW_${providerToEnvSegment(provider)}_BASE_URL`;
  const envVal = process.env[envKey];
  if (envVal && String(envVal).trim()) return normalizeGatewayUrl(envVal);
  return fallbackBase || DEFAULT_BASE_URL;
}

function resolveProviderApiKey(provider: string | undefined, submissionToken?: string): string | undefined {
  if (submissionToken && String(submissionToken).trim()) return String(submissionToken).trim();
  if (!provider) return undefined;
  const envKey = `OPENCLAW_${providerToEnvSegment(provider)}_API_KEY`;
  const envToken = process.env[envKey] || process.env[`${envKey}_TOKEN`] || process.env[`${envKey}_AUTH`];
  if (envToken && String(envToken).trim()) return String(envToken).trim();
  return undefined;
}

function safeJsonParse(raw: string): unknown {
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function readStringField(record: Record<string, unknown>, key: string): string | undefined {
  const value = record[key];
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

async function readApiKeyFromConfig(): Promise<string | undefined> {
  const configPath = path.join(os.homedir(), ".openclaw", "openclaw.json");
  try {
    const raw = await fs.readFile(configPath, "utf-8");
    const parsed = safeJsonParse(raw);
    const record = asRecord(parsed);
    if (!record) return undefined;

    const directToken =
      readStringField(record, "apiKey") ||
      readStringField(record, "api_key") ||
      readStringField(record, "token") ||
      readStringField(record, "authToken");
    if (directToken) return directToken;

    const gateway = asRecord(record.gateway);
    const gatewayAuth = gateway ? asRecord(gateway.auth) : null;
    return gatewayAuth ? readStringField(gatewayAuth, "token") : undefined;
  } catch {
    return undefined;
  }
}

function extractCliText(payload: unknown): string {
  if (typeof payload === "string") return payload.trim();

  const root = asRecord(payload);
  if (!root) return "";

  const result = asRecord(root.result);
  const payloads = result && Array.isArray(result.payloads)
    ? result.payloads
    : Array.isArray(root.payloads)
      ? root.payloads
      : [];

  const chunks: string[] = [];
  for (const item of payloads) {
    const record = asRecord(item);
    if (!record) continue;
    const directText = readStringField(record, "text");
    if (directText) { chunks.push(directText); continue; }
    const content = record.content;
    if (!Array.isArray(content)) continue;
    for (const part of content) {
      const partRec = asRecord(part);
      if (!partRec || readStringField(partRec, "type") !== "text") continue;
      const text = readStringField(partRec, "text");
      if (text) chunks.push(text);
    }
  }

  const joined = chunks.map((t) => t.trim()).filter(Boolean).join("\n").trim();
  if (joined) return joined;

  const summary = readStringField(root, "summary");
  if (summary) return summary;

  return JSON.stringify(payload, null, 2);
}

function extractResponseText(payload: unknown): string {
  const root = asRecord(payload);
  if (!root) return "";
  if (typeof root.output_text === "string") return root.output_text;

  const output = root.output;
  if (Array.isArray(output)) {
    const chunks: string[] = [];
    for (const item of output) {
      const rec = asRecord(item);
      if (!rec || !Array.isArray(rec.content)) continue;
      for (const part of rec.content) {
        const partRec = asRecord(part);
        if (!partRec) continue;
        const text = readStringField(partRec, "text");
        if (text) chunks.push(text);
      }
    }
    if (chunks.length > 0) return chunks.join("\n").trim();
  }
  return "";
}

function extractChatText(payload: unknown): string {
  const root = asRecord(payload);
  if (!root || !Array.isArray(root.choices) || root.choices.length === 0) return "";
  const choice = asRecord(root.choices[0]);
  const message = choice ? asRecord(choice.message) : null;
  if (!message) return "";
  if (typeof message.content === "string") return message.content;
  if (Array.isArray(message.content)) {
    return message.content
      .map((p) => { const r = asRecord(p); return r ? readStringField(r, "text") : undefined; })
      .filter((t): t is string => Boolean(t))
      .join("\n")
      .trim();
  }
  return "";
}

function safeJsonParseFromText(raw: string): unknown {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  const direct = safeJsonParse(trimmed);
  if (direct !== null) return direct;
  const firstBrace = trimmed.indexOf("{");
  const lastBrace = trimmed.lastIndexOf("}");
  if (firstBrace >= 0 && lastBrace > firstBrace) {
    const sliced = trimmed.slice(firstBrace, lastBrace + 1);
    return safeJsonParse(sliced);
  }
  return null;
}

function normalizeOllamaModelId(model: string): string {
  return String(model || "").trim().replace(/^ollama\//i, "");
}

function buildModelCandidates(model: string, provider?: string): string[] {
  if (provider && provider !== "ollama") {
    const trimmed = String(model || "").trim();
    return trimmed ? [trimmed] : [];
  }
  const plain = normalizeOllamaModelId(model);
  if (!plain) return [String(model || "").trim()];
  const prefixed = `ollama/${plain}`;
  return Array.from(new Set([plain, prefixed]));
}

function isModelNotFound(status: number, bodyText: string): boolean {
  const text = String(bodyText || "").toLowerCase();
  return status === 404 || (text.includes("model") && text.includes("not found"));
}

export async function openclawExec(options: ExecOptions): Promise<ExecResult> {
  const transport = getTransport();
  const model = options.model || process.env.OPENCLAW_DEFAULT_MODEL || DEFAULT_MODEL;
  const timeoutMs = options.timeoutMs || Number(process.env.OPENCLAW_TIMEOUT_MS) || DEFAULT_TIMEOUT_MS;
  const systemPrompt = options.systemPrompt || "You are a senior software engineer. Follow the user's instruction precisely.";

  if (transport === "cli") {
    const cliPath = getCliPath();
    const sessionId = options.sessionId || `mcp-${Date.now()}`;
    const message = `SYSTEM:\n${systemPrompt}\n\nUSER:\n${options.prompt}`;
    const cliArgs = ["agent", "--session-id", sessionId, "--message", message, "--thinking", "minimal", "--json"];

    let stdout = "";
    let stderr = "";
    try {
      const result = await execFileAsync(cliPath, cliArgs, {
        timeout: timeoutMs,
        maxBuffer: 32 * 1024 * 1024,
        env: process.env,
      });
      stdout = String(result.stdout || "");
      stderr = String(result.stderr || "");
    } catch (error) {
      const err = error as { stdout?: string; stderr?: string; message?: string };
      stdout = String(err.stdout || "");
      stderr = String(err.stderr || err.message || "");
      const detail = [stderr.trim(), stdout.trim()].filter(Boolean).join("\n").slice(0, 3000);
      throw new Error(`OpenClaw CLI failed: ${detail || "unknown error"}`);
    }

    const parsed = safeJsonParseFromText(stdout) ?? safeJsonParseFromText(stderr) ?? null;
    const raw = parsed ?? { stdout: stdout.trim(), stderr: stderr.trim() };
    const text = extractCliText(parsed ?? stdout);
    return { model, text: text || JSON.stringify(raw, null, 2), raw };
  }

  // HTTP transport with provider multiplexing (detect provider:model prefixes)
  const { provider, modelId } = parseProviderFromModel(model);
  const effectiveModel = modelId || model;

  const baseUrl = resolveProviderBaseUrl(provider, options.gatewayBaseUrl, process.env.OPENCLAW_GATEWAY_BASE_URL || DEFAULT_BASE_URL);
  const apiKey = resolveProviderApiKey(provider, options.authToken) || process.env.OPENCLAW_API_KEY || process.env.OPENCLAW_TOKEN || (await readApiKeyFromConfig());
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (apiKey) headers.Authorization = `Bearer ${apiKey}`;

  const modelCandidates = buildModelCandidates(effectiveModel, provider);
  let lastError = "";

  for (let i = 0; i < modelCandidates.length; i += 1) {
    const candidateModel = modelCandidates[i];

    // Try /v1/responses first
    const responsesBody = { model: candidateModel, instructions: systemPrompt, input: options.prompt };
    const responsesRes = await fetchWithTimeout(`${baseUrl}/responses`, "POST", headers, responsesBody, timeoutMs);
    if (responsesRes.ok) {
      const text = extractResponseText(responsesRes.bodyJson);
      return { model: candidateModel, text: text || JSON.stringify(responsesRes.bodyJson, null, 2), raw: responsesRes.bodyJson };
    }

    // Fallback to /v1/chat/completions
    const chatBody = {
      model: candidateModel,
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: options.prompt },
      ],
      temperature: 0.2,
    };
    const chatRes = await fetchWithTimeout(`${baseUrl}/chat/completions`, "POST", headers, chatBody, timeoutMs);
    if (chatRes.ok) {
      const text = extractChatText(chatRes.bodyJson);
      return { model: candidateModel, text: text || JSON.stringify(chatRes.bodyJson, null, 2), raw: chatRes.bodyJson };
    }

    const responseDetail = responsesRes.bodyText || String(responsesRes.status);
    const chatDetail = chatRes.bodyText || String(chatRes.status);
    lastError = `model=${candidateModel}; /responses: ${responsesRes.status} ${responseDetail.slice(0, 500)}; /chat/completions: ${chatRes.status} ${chatDetail.slice(0, 500)}`;

    const hasFallback = i < modelCandidates.length - 1;
    const shouldFallback = hasFallback && (
      isModelNotFound(responsesRes.status, responsesRes.bodyText) ||
      isModelNotFound(chatRes.status, chatRes.bodyText)
    );

    if (shouldFallback) {
      continue;
    }

    throw new Error(`OpenClaw API failed. ${lastError}`);
  }

  throw new Error(`OpenClaw API failed. ${lastError || "unknown error"}`);
}

async function fetchWithTimeout(
  url: string,
  method: string,
  headers: Record<string, string>,
  body: unknown,
  timeoutMs: number
): Promise<{ ok: boolean; status: number; bodyText: string; bodyJson: unknown }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method,
      headers,
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    const bodyText = await response.text();
    return { ok: response.ok, status: response.status, bodyText, bodyJson: safeJsonParse(bodyText) };
  } finally {
    clearTimeout(timer);
  }
}
