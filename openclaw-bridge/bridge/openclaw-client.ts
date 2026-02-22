import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { OpenClawResult, TaskSubmission } from "./types";

const execFileAsync = promisify(execFile);

interface OpenClawClientOptions {
  baseUrl?: string;
  apiKey?: string;
  defaultModel?: string;
  timeoutMs?: number;
}

interface RunTaskInput {
  jobId: string;
  submission: TaskSubmission;
  repoPath?: string;
  workspacePath?: string;
}

interface RequestResponse {
  ok: boolean;
  status: number;
  statusText: string;
  bodyText: string;
  bodyJson: unknown;
}

const DEFAULT_BASE_URL = "https://127.0.0.1:18789/v1";
const DEFAULT_MODEL = "openthinker:7b";
const DEFAULT_TIMEOUT_MS = 180000;
const DEFAULT_TRANSPORT: OpenClawTransport = "cli";

type OpenClawTransport = "cli" | "http";

const REPO_SYSTEM_PROMPT =
  "You are a senior autonomous bounty engineer. Prioritize passing tests and producing merge-ready changes.";
const LLDB_TRIAGE_SYSTEM_PROMPT =
  "You are a senior debugging engineer. Triage LLDB crash/exception stops. Focus on root cause analysis, actionable debugging steps, and mitigations. Do not provide exploit, weaponization, or payload guidance.";
const BIONIC_QA_SYSTEM_PROMPT =
  "You are a security QA analyst focused on protocol stability. Analyze HTTP request/response pairs to find protocol stability risks and input-handling flaws that could cause crashes, assertions, hangs, or undefined behavior. Do not provide exploit, weaponization, or payload guidance. Do not provide instructions to bypass authentication. Perform these checks: (1) Integer widths: flag Content-Length and custom integer headers (especially X-* numeric headers) that are negative or exceed int32/uint32/int64/uint64 boundaries. (2) Format string anomalies: flag user-controlled fields containing %s, %x, or %n. (3) Serialization risks: flag binary blobs that look like bplist (bplist00) or Java Serialization (AC ED 00 05 / common base64 prefixes). Output rules: If any risk is identified, output exactly one JSON object of kind \"FuzzingCandidate\" describing the risky fields and safe boundary-focused mutations for a stability harness. If no risk is identified, output exactly one JSON object of kind \"NoFinding\".";
const GENERIC_NON_REPO_SYSTEM_PROMPT =
  "You are a senior software engineer. Follow the user's instruction. For security-related tasks, focus on defensive analysis and safety. Do not provide exploit, weaponization, or authentication bypass guidance.";

function normalizeTransport(raw: unknown): OpenClawTransport {
  const value = typeof raw === "string" ? raw.trim().toLowerCase() : "";
  if (!value) {
    return DEFAULT_TRANSPORT;
  }
  if (value === "cli" || value === "http") {
    return value;
  }
  return DEFAULT_TRANSPORT;
}

function getOpenClawCliPath(): string {
  const value = (process.env.OPENCLAW_CLI_PATH || "").trim();
  return value || "openclaw";
}

function getOpenClawAgentId(): string | undefined {
  const value = (process.env.OPENCLAW_AGENT_ID || "").trim();
  return value || undefined;
}

function safeJsonParse(raw: string): unknown {
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return null;
  }
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
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
    if (!record) {
      return undefined;
    }

    const directToken =
      readStringField(record, "apiKey") ||
      readStringField(record, "api_key") ||
      readStringField(record, "token") ||
      readStringField(record, "authToken");

    if (directToken) {
      return directToken;
    }

    const gateway = asRecord(record.gateway);
    const gatewayAuth = gateway ? asRecord(gateway.auth) : null;
    return gatewayAuth ? readStringField(gatewayAuth, "token") : undefined;
  } catch {
    return undefined;
  }
}

function normalizeGatewayBaseUrl(value: string): string {
  const trimmed = value.trim().replace(/\/$/, "");
  if (!trimmed) {
    return DEFAULT_BASE_URL;
  }

  return trimmed.endsWith("/v1") ? trimmed : `${trimmed}/v1`;
}

function providerToEnvSegment(provider: string): string {
  return provider.trim().toUpperCase().replace(/[^A-Z0-9]+/g, "_");
}

function parseProviderFromModel(model: string): { provider?: string; modelId: string } {
  const raw = String(model || "").trim();
  if (!raw) return { modelId: raw };
  // provider/model is always treated as explicit provider prefix.
  const slashIndex = raw.indexOf("/");
  if (slashIndex > 0) {
    const provider = raw.slice(0, slashIndex).toLowerCase();
    return { provider, modelId: raw.slice(slashIndex + 1) };
  }
  // provider:model is ambiguous with model tags like openthinker:7b.
  // Treat it as provider prefix only when explicitly configured or well-known.
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
  if (submissionBase && String(submissionBase).trim()) return normalizeGatewayBaseUrl(String(submissionBase));
  if (!provider) return fallbackBase || DEFAULT_BASE_URL;
  const envKey = `OPENCLAW_${providerToEnvSegment(provider)}_BASE_URL`;
  const envVal = process.env[envKey];
  if (envVal && String(envVal).trim()) return normalizeGatewayBaseUrl(envVal);
  return fallbackBase || DEFAULT_BASE_URL;
}

function resolveProviderApiKey(provider: string | undefined, submissionToken?: string, configured?: string): string | undefined {
  if (submissionToken && String(submissionToken).trim()) return String(submissionToken).trim();
  if (!provider) return configured;
  const envKey = `OPENCLAW_${providerToEnvSegment(provider)}_API_KEY`;
  const envToken = process.env[envKey] || process.env[`${envKey}_TOKEN`] || process.env[`${envKey}_AUTH`];
  if (envToken && String(envToken).trim()) return String(envToken).trim();
  return configured;
}

async function requestJson(
  url: string,
  method: string,
  headers: Record<string, string>,
  body: unknown,
  timeoutMs: number
): Promise<RequestResponse> {
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
    return {
      ok: response.ok,
      status: response.status,
      statusText: response.statusText,
      bodyText,
      bodyJson: safeJsonParse(bodyText),
    };
  } finally {
    clearTimeout(timer);
  }
}

function stringifyUnknown(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }

  if (value == null) {
    return "";
  }

  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function safeJsonParseFromText(raw: string): unknown {
  const trimmed = String(raw || "").trim();
  if (!trimmed) {
    return null;
  }

  const direct = safeJsonParse(trimmed);
  if (direct !== null) {
    return direct;
  }

  const firstBrace = trimmed.indexOf("{");
  const lastBrace = trimmed.lastIndexOf("}");
  if (firstBrace >= 0 && lastBrace > firstBrace) {
    const sliced = trimmed.slice(firstBrace, lastBrace + 1);
    const slicedJson = safeJsonParse(sliced);
    if (slicedJson !== null) {
      return slicedJson;
    }
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
  if (!plain) {
    return [String(model || "").trim()];
  }
  return Array.from(new Set([plain, `ollama/${plain}`]));
}

function isModelNotFound(status: number, bodyText: string): boolean {
  const text = String(bodyText || "").toLowerCase();
  return status === 404 || (text.includes("model") && text.includes("not found"));
}

export function extractAgentReplyTextFromCliJson(payload: unknown): string {
  if (typeof payload === "string") {
    return payload.trim();
  }

  const root = asRecord(payload);
  if (!root) {
    return "";
  }

  const result = asRecord(root.result);
  const payloads = result && Array.isArray(result.payloads) ? result.payloads : Array.isArray(root.payloads) ? root.payloads : [];

  const chunks: string[] = [];

  for (const item of payloads) {
    const record = asRecord(item);
    if (!record) {
      continue;
    }

    const directText = readStringField(record, "text");
    if (directText) {
      chunks.push(directText);
      continue;
    }

    const content = record.content;
    if (!Array.isArray(content)) {
      continue;
    }

    for (const part of content) {
      const partRecord = asRecord(part);
      if (!partRecord) {
        continue;
      }
      if (readStringField(partRecord, "type") !== "text") {
        continue;
      }
      const text = readStringField(partRecord, "text");
      if (text) {
        chunks.push(text);
      }
    }
  }

  const joined = chunks.map((text) => text.trim()).filter(Boolean).join("\n").trim();
  if (joined) {
    return joined;
  }

  const summary = readStringField(root, "summary");
  if (summary) {
    return summary;
  }

  return stringifyUnknown(payload).trim();
}

function extractResponseText(payload: unknown): string {
  const root = asRecord(payload);
  if (!root) {
    return "";
  }

  if (typeof root.output_text === "string") {
    return root.output_text;
  }

  const output = root.output;
  if (Array.isArray(output)) {
    const chunks: string[] = [];
    for (const outputItem of output) {
      const itemRecord = asRecord(outputItem);
      if (!itemRecord) {
        continue;
      }

      const content = itemRecord.content;
      if (!Array.isArray(content)) {
        continue;
      }

      for (const contentItem of content) {
        const contentRecord = asRecord(contentItem);
        if (!contentRecord) {
          continue;
        }

        const text = readStringField(contentRecord, "text");
        if (text) {
          chunks.push(text);
        }
      }
    }

    if (chunks.length > 0) {
      return chunks.join("\n").trim();
    }
  }

  return "";
}

function extractChatCompletionText(payload: unknown): string {
  const root = asRecord(payload);
  if (!root || !Array.isArray(root.choices) || root.choices.length === 0) {
    return "";
  }

  const choice = asRecord(root.choices[0]);
  const message = choice ? asRecord(choice.message) : null;
  if (!message) {
    return "";
  }

  if (typeof message.content === "string") {
    return message.content;
  }

  if (Array.isArray(message.content)) {
    const chunks: string[] = [];
    for (const part of message.content) {
      const partRecord = asRecord(part);
      if (!partRecord) {
        continue;
      }

      const text = readStringField(partRecord, "text");
      if (text) {
        chunks.push(text);
      }
    }

    return chunks.join("\n").trim();
  }

  return "";
}

function normalizeRequesterForPrompt(value: string): string {
  return String(value || "").trim().toLowerCase();
}

function isLldbTriageSubmission(submission: TaskSubmission): boolean {
  return normalizeRequesterForPrompt(submission.requester) === "lldb";
}

function isBionicIngestSubmission(submission: TaskSubmission): boolean {
  const requester = normalizeRequesterForPrompt(submission.requester);
  return requester === "bioniclink" || requester === "burp" || requester === "bionic-ingest" || requester === "bionic_ingest" || requester === "bionic";
}

function buildRepositoryPrompt(jobId: string, submission: TaskSubmission, context: { repoPath?: string; workspacePath?: string }): string {
  const contextList = (submission.context_urls || []).map((url) => `- ${url}`).join("\n") || "- (none)";

  return [
    `Job ID: ${jobId}`,
    `Job Workspace Path: ${context.workspacePath || "(none)"}`,
    `Instruction: ${submission.instruction}`,
    `Repository URL: ${submission.repo_url || "(none)"}`,
    `Repository Path: ${context.repoPath || "(none)"}`,
    `Branch Override: ${submission.branch_name || "(none)"}`,
    `Hints: ${submission.hints || "(none)"}`,
    "Context URLs:",
    contextList,
    "",
    "Execution requirements:",
    "1) If a repository path is provided, perform changes in that workspace.",
    "2) Explain what was changed and how to validate.",
    "3) Return concise implementation notes and any blockers.",
  ].join("\n");
}

function buildLldbTriagePrompt(jobId: string, submission: TaskSubmission, context: { workspacePath?: string }): string {
  const contextList = (submission.context_urls || []).map((url) => `- ${url}`).join("\n") || "- (none)";
  const eventPath = context.workspacePath ? path.join(context.workspacePath, "LLDB_STOP_EVENT.json") : "(unknown)";

  return [
    `Job ID: ${jobId}`,
    `Job Workspace Path: ${context.workspacePath || "(none)"}`,
    `Instruction: ${submission.instruction}`,
    `Hints: ${submission.hints || "(none)"}`,
    "Context URLs:",
    contextList,
    "",
    "LLDB stop event:",
    `- Read and analyze: ${eventPath}`,
    "",
    "Output format:",
    "1) Crash summary (1-3 paragraphs).",
    "2) Suspected bug class + confidence (e.g., null deref, OOB, UAF, race, assertion).",
    "3) Root-cause hypotheses (bullets, prioritize most likely).",
    "4) Next debugging steps (bullets: lldb commands, logging, repro narrowing).",
    "5) Potential mitigations (bullets: guards, input validation, defensive coding).",
    "",
    "Constraints:",
    "- This is defensive debugging triage only.",
    "- Do not provide exploit, weaponization, or payload guidance.",
  ].join("\n");
}

function buildBionicIngestPrompt(jobId: string, submission: TaskSubmission, context: { workspacePath?: string }): string {
  const contextList = (submission.context_urls || []).map((url) => `- ${url}`).join("\n") || "- (none)";
  const eventPath = context.workspacePath ? path.join(context.workspacePath, "BIONIC_INGEST_EVENT.json") : "(unknown)";

  return [
    `Job ID: ${jobId}`,
    `Job Workspace Path: ${context.workspacePath || "(none)"}`,
    `Instruction: ${submission.instruction}`,
    `Hints: ${submission.hints || "(none)"}`,
    "Context URLs:",
    contextList,
    "",
    "Bionic ingest event:",
    `- Read and analyze: ${eventPath}`,
    "",
    "Output requirements:",
    "- Output JSON only (no markdown).",
    "- If any risk is identified, output one JSON object: { kind: \"FuzzingCandidate\", ... }.",
    "- If no risk is identified, output one JSON object: { kind: \"NoFinding\", risks: [] }.",
    "",
    "Safety constraints:",
    "- Do NOT generate weaponized exploit payloads or shellcode.",
    "- Do NOT provide instructions on how to bypass authentication.",
    "- DO focus on input validation, memory safety, and RFC compliance.",
  ].join("\n");
}

function buildGenericPrompt(jobId: string, submission: TaskSubmission, context: { workspacePath?: string }): string {
  const contextList = (submission.context_urls || []).map((url) => `- ${url}`).join("\n") || "- (none)";

  return [
    `Job ID: ${jobId}`,
    `Job Workspace Path: ${context.workspacePath || "(none)"}`,
    `Instruction: ${submission.instruction}`,
    `Hints: ${submission.hints || "(none)"}`,
    "Context URLs:",
    contextList,
    "",
    "Execution requirements:",
    "1) Explain your reasoning and any assumptions.",
    "2) Keep the answer concise and actionable.",
    "3) Do not provide exploit, weaponization, or authentication bypass guidance.",
  ].join("\n");
}

function buildSystemPrompt(submission: TaskSubmission, repoPath?: string): string {
  if (repoPath) {
    return REPO_SYSTEM_PROMPT;
  }
  if (isBionicIngestSubmission(submission)) {
    return BIONIC_QA_SYSTEM_PROMPT;
  }
  if (isLldbTriageSubmission(submission)) {
    return LLDB_TRIAGE_SYSTEM_PROMPT;
  }
  return GENERIC_NON_REPO_SYSTEM_PROMPT;
}

function buildCliMessage(systemPrompt: string, userPrompt: string): string {
  return ["SYSTEM:", systemPrompt, "", "USER:", userPrompt].join("\n");
}

export class OpenClawClient {
  private readonly baseUrl: string;
  private readonly configuredApiKey?: string;
  private readonly defaultModel: string;
  private readonly timeoutMs: number;

  constructor(options: OpenClawClientOptions = {}) {
    this.baseUrl = normalizeGatewayBaseUrl(options.baseUrl || process.env.OPENCLAW_GATEWAY_BASE_URL || DEFAULT_BASE_URL);
    this.configuredApiKey = options.apiKey || process.env.OPENCLAW_API_KEY || process.env.OPENCLAW_TOKEN;
    this.defaultModel = options.defaultModel || process.env.OPENCLAW_DEFAULT_MODEL || DEFAULT_MODEL;
    this.timeoutMs = Number(options.timeoutMs || process.env.OPENCLAW_TIMEOUT_MS || DEFAULT_TIMEOUT_MS);
  }

  async runTask(input: RunTaskInput): Promise<OpenClawResult> {
    const transport = normalizeTransport(process.env.OPENCLAW_TRANSPORT);
    const model = input.submission.model || this.defaultModel;
    const systemPrompt = buildSystemPrompt(input.submission, input.repoPath);
    const userPrompt = input.repoPath
      ? buildRepositoryPrompt(input.jobId, input.submission, { repoPath: input.repoPath, workspacePath: input.workspacePath })
      : isBionicIngestSubmission(input.submission)
        ? buildBionicIngestPrompt(input.jobId, input.submission, { workspacePath: input.workspacePath })
        : isLldbTriageSubmission(input.submission)
          ? buildLldbTriagePrompt(input.jobId, input.submission, { workspacePath: input.workspacePath })
          : buildGenericPrompt(input.jobId, input.submission, { workspacePath: input.workspacePath });

    if (transport === "cli") {
      const cliPath = getOpenClawCliPath();
      const cliArgs: string[] = ["agent"];
      const agentId = getOpenClawAgentId();
      if (agentId) {
        cliArgs.push("--agent", agentId);
      }

      const message = buildCliMessage(systemPrompt, userPrompt);

      cliArgs.push("--session-id", input.jobId, "--message", message, "--thinking", "minimal", "--json");

      let stdout = "";
      let stderr = "";
      try {
        const result = await execFileAsync(cliPath, cliArgs, {
          timeout: this.timeoutMs,
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
      const text = extractAgentReplyTextFromCliJson(parsed ?? stdout);

      return {
        model,
        text: text || stringifyUnknown(raw),
        raw,
      };
    }

    // Determine provider and route based on model prefix or explicit submission.gateway_base_url
    const { provider, modelId } = parseProviderFromModel(model);
    const effectiveModel = modelId || model;

    const taskBaseUrl = resolveProviderBaseUrl(provider, input.submission.gateway_base_url, this.baseUrl);
    const apiKey = resolveProviderApiKey(provider, input.submission.auth_token, this.configuredApiKey) || (await readApiKeyFromConfig());

    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (apiKey) headers.Authorization = `Bearer ${apiKey}`;

    const prompt = userPrompt;
    const modelCandidates = buildModelCandidates(effectiveModel, provider);
    let lastError = "";

    for (let i = 0; i < modelCandidates.length; i += 1) {
      const candidateModel = modelCandidates[i];

      const responsesBody = {
        model: candidateModel,
        instructions: systemPrompt,
        input: prompt,
        metadata: {
          job_id: input.jobId,
          requester: input.submission.requester,
        },
      };

      const responsesUrl = `${taskBaseUrl}/responses`;
      const responsesResult = await requestJson(responsesUrl, "POST", headers, responsesBody, this.timeoutMs);

      if (responsesResult.ok) {
        const text = extractResponseText(responsesResult.bodyJson);
        return {
          model: candidateModel,
          text: text || stringifyUnknown(responsesResult.bodyJson),
          raw: responsesResult.bodyJson,
        };
      }

      const chatCompletionsBody = {
        model: candidateModel,
        messages: [
          {
            role: "system",
            content: systemPrompt,
          },
          {
            role: "user",
            content: prompt,
          },
        ],
        temperature: 0.2,
      };

      const chatCompletionsUrl = `${taskBaseUrl}/chat/completions`;
      const chatResult = await requestJson(chatCompletionsUrl, "POST", headers, chatCompletionsBody, this.timeoutMs);

      if (chatResult.ok) {
        const text = extractChatCompletionText(chatResult.bodyJson);
        return {
          model: candidateModel,
          text: text || stringifyUnknown(chatResult.bodyJson),
          raw: chatResult.bodyJson,
        };
      }

      const responseError = responsesResult.bodyText || `${responsesResult.status} ${responsesResult.statusText}`;
      const chatError = chatResult.bodyText || `${chatResult.status} ${chatResult.statusText}`;
      lastError = `model=${candidateModel}; /responses: ${responsesResult.status} ${responseError.slice(0, 500)}; /chat/completions: ${chatResult.status} ${chatError.slice(0, 500)}`;

      const hasFallback = i < modelCandidates.length - 1;
      const shouldFallback =
        hasFallback &&
        (isModelNotFound(responsesResult.status, responsesResult.bodyText) ||
          isModelNotFound(chatResult.status, chatResult.bodyText));

      if (shouldFallback) {
        continue;
      }

      throw new Error(`OpenClaw API failed. ${lastError}`);
    }

    throw new Error(`OpenClaw API failed. ${lastError || "unknown error"}`);
  }
}
