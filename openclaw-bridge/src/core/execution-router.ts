import { execFile } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { AsyncRotatingAuditLogger, AuditLoggerStats, hashArgs } from "./audit-log";
import { assertPathInsideWorkspace, canonicalizeWorkspaceRoot } from "./workspace-guard";
import {
  WorkloadIntegrityContext,
  WorkloadIntegrityVerifier,
  WorkloadRuntimeDescriptor,
  createWorkloadIntegrityVerifier,
} from "../security/workload-integrity";
import { resolveDefaultWorkloadManifestPath } from "../security/workload-manifest";
import {
  WorkloadAttestationChallenge,
  WorkloadAttestationEvidence,
  WorkloadAttestationRuntime,
  WorkloadAttestationVerificationResult,
  generateAttestationEvidence as generateAttestationEvidenceFromRuntime,
  getAttestationState as getRuntimeAttestationState,
  initializeAttestation,
} from "../security/workload-attestation";

const execFileAsync = promisify(execFile);

type JsonObject = Record<string, unknown>;
type JsonSchema = Record<string, unknown>;

export type ExecutionRole = "supervisor" | "internal" | "admin" | "anonymous";
export type ExecutionSource = "mcp_sse" | "http_api" | "stdio_mcp" | "cli" | "job_worker" | "in_process";

export interface ExecutionContext {
  requestId: string;
  workspaceRoot: string;
  source: ExecutionSource;
  caller: string;
  authHeader?: string;
  internalFlagRequested?: boolean;
  internalToken?: string;
  trustedInProcessCaller?: boolean;
  trustedInProcessRole?: "internal" | "admin";
  transportMetadata?: JsonObject;
  legacyExecute?: (tool: string, args: JsonObject, context: ExecutionContext) => Promise<unknown>;
  legacyListTools?: () => Promise<ExecutionToolDescriptor[]>;
}

export interface ExecutionResult {
  ok: boolean;
  code?: string;
  message?: string;
  data?: unknown;
}

export interface ExecutionRouterMetrics {
  counters: Record<string, number>;
  audit: AuditLoggerStats;
}

export interface ExecutionRouter {
  execute(tool: string, args: JsonObject, context: ExecutionContext): Promise<ExecutionResult>;
  listTools(context: ExecutionContext): Promise<Array<ExecutionToolDescriptor>>;
  resolveRole(context: ExecutionContext): Promise<ExecutionRole>;
  getMetrics(): ExecutionRouterMetrics;
  getWorkloadIntegrityMetadata(): {
    nodeId: string;
    workloadManifestHash: string;
    workloadManifestLoaded: boolean;
    startupVerified: boolean;
    blocked: boolean;
    blockedReason: string;
  };
  evaluateWorkloadPeerPosture(peers?: Array<Record<string, unknown>>): {
    ok: boolean;
    status: "aligned" | "mismatch" | "not_evaluated";
    criticalMismatches: Array<Record<string, unknown>>;
    warnings: Array<Record<string, unknown>>;
    timestamp: number;
  };
  getWorkloadAttestationMetadata(): {
    nodeId: string;
    trusted: boolean;
    blockedReason: string;
    referenceHash: string;
    lastEvidenceHash: string;
    lastVerifiedAt: number;
    peerTrustMap: Record<
      string,
      {
        trusted: boolean;
        failureReason: string;
        evidenceHash: string;
        verifiedAt: number;
        stickyUntrusted: boolean;
      }
    >;
  };
  evaluateWorkloadAttestationPeerPosture(peers?: Array<Record<string, unknown>>): {
    ok: boolean;
    status: "aligned" | "mismatch" | "not_evaluated";
    criticalMismatches: Array<Record<string, unknown>>;
    warnings: Array<Record<string, unknown>>;
    timestamp: number;
  };
  generateAttestationEvidence(
    challenge?: WorkloadAttestationChallenge,
    context?: { localMetadata?: Record<string, unknown>; runtimeMeasurements?: Record<string, unknown> },
  ): {
    ok: boolean;
    code: string;
    message: string;
    evidence?: WorkloadAttestationEvidence;
    details: Record<string, unknown>;
  };
  verifyPeerAttestationEvidence(input: {
    peerId: string;
    evidence: unknown;
    challenge?: WorkloadAttestationChallenge;
  }): WorkloadAttestationVerificationResult;
}

export interface ExecutionToolDescriptor {
  name: string;
  description?: string;
  inputSchema?: JsonObject;
}

type MutationClass = "read" | "write" | "exec" | "security";

interface SupervisorToolDefinition {
  name: string;
  description?: string;
  inputSchema?: JsonSchema;
  mutationClass: MutationClass;
  loggingLevel: "info" | "warn" | "error";
  roles: Array<"supervisor" | "internal" | "admin">;
  workspacePathArgs?: string[];
}

interface SupervisorToolHandler {
  (args: JsonObject, context: ExecutionContext): Promise<unknown>;
}

export interface ExecutionRouterOptions {
  workspaceRoot: string;
  supervisorMode?: boolean;
  supervisorAuthPhase?: "compat" | "strict";
  mutationGuardEnabled?: boolean;
  supervisorInternalToken?: string;
  registryPath?: string;
  supervisorHandlers?: Record<string, SupervisorToolHandler>;
  legacyVisibleToolsByRole?: Partial<Record<ExecutionRole, string[]>>;
  auditMaxBytes?: number;
  auditLogPath?: string;
  auditMaxQueueEntries?: number;
  rateLimitWindowMs?: number;
  rateLimitMaxRequestsPerWindow?: number;
  maxConcurrentExecutions?: number;
  maxConcurrentExecutionsPerSource?: number;
  maxPatchBytes?: number;
  maxWriteFileBytes?: number;
  maxReadFileBytes?: number;
  maxCommandOutputBytes?: number;
  gitTimeoutMs?: number;
  rgTimeoutMs?: number;
  nodeTimeoutMs?: number;
  taskRunnerTimeoutMs?: number;
  workloadManifestPath?: string;
  workloadManifestExpectedHash?: string;
  workloadIntegrityEnabled?: boolean;
  workloadAttestationEnabled?: boolean;
  attestationReferencePath?: string;
  attestationReferenceExpectedHash?: string;
  workloadRuntimeDescriptorResolver?: (
    tool: string,
    context: WorkloadIntegrityContext,
  ) => WorkloadRuntimeDescriptor | null;
  integrityMetadataProvider?: (context: ExecutionContext) => {
    local?: Record<string, unknown>;
    peers?: Array<Record<string, unknown>>;
  };
  onHighRiskToolEvent?: (event: {
    requestId: string;
    tool: string;
    mutationClass: MutationClass;
    role: ExecutionRole;
    source: ExecutionSource;
  }) => void;
}

interface TokenCache {
  value: string;
  loadedAt: number;
}

interface SourceExecutionState {
  windowStartedAtMs: number;
  requestsInWindow: number;
  activeExecutions: number;
}

const DEFAULT_CACHE_TTL_MS = 5_000;
const DEFAULT_AUDIT_MAX_BYTES = 10 * 1024 * 1024;
const DEFAULT_AUDIT_MAX_QUEUE_ENTRIES = 10_000;
const DEFAULT_RATE_LIMIT_WINDOW_MS = 1_000;
const DEFAULT_RATE_LIMIT_MAX_REQUESTS_PER_WINDOW = 60;
const DEFAULT_MAX_CONCURRENT_EXECUTIONS = 32;
const DEFAULT_MAX_CONCURRENT_EXECUTIONS_PER_SOURCE = 8;
const DEFAULT_MAX_PATCH_BYTES = 256 * 1024;
const DEFAULT_MAX_WRITE_FILE_BYTES = 1024 * 1024;
const DEFAULT_MAX_READ_FILE_BYTES = 1024 * 1024;
const DEFAULT_MAX_COMMAND_OUTPUT_BYTES = 4 * 1024 * 1024;
const DEFAULT_GIT_TIMEOUT_MS = 10_000;
const DEFAULT_RG_TIMEOUT_MS = 10_000;
const DEFAULT_NODE_TIMEOUT_MS = 20_000;
const DEFAULT_TASK_RUNNER_TIMEOUT_MS = 120_000;
const MAX_REQUESTED_COMMAND_ARGS = 20;
const MAX_REQUESTED_COMMAND_ARG_LENGTH = 200;

const HIGH_RISK_MUTATION_CLASSES = new Set<MutationClass>(["write", "exec", "security"]);
const ALLOWED_TASK_RUNNER_COMMANDS = new Set(["npm", "pnpm", "yarn", "bun"]);
const warnedWeakTokenPermissionPaths = new Set<string>();

const ROLE_POLICY: Record<ExecutionRole, { canExecuteTools: boolean; canSeeTools: boolean; canUseLegacy: boolean }> = {
  supervisor: { canExecuteTools: true, canSeeTools: true, canUseLegacy: true },
  internal: { canExecuteTools: true, canSeeTools: true, canUseLegacy: true },
  admin: { canExecuteTools: true, canSeeTools: true, canUseLegacy: true },
  anonymous: { canExecuteTools: false, canSeeTools: false, canUseLegacy: false },
};

const SAFE_ERROR_MESSAGES: Record<string, string> = {
  INVALID_REQUEST: "Request validation failed",
  INVALID_ARGUMENT: "Tool arguments are invalid",
  UNAUTHORIZED: "Authentication failed",
  UNAUTHORIZED_TOOL: "Tool not exposed to caller role",
  UNAUTHORIZED_INTERNAL_BYPASS: "Internal bypass denied",
  UNAUTHORIZED_ROLE: "Role is not authorized",
  PATH_OUTSIDE_WORKSPACE: "Path is outside workspace boundary",
  LEGACY_EXECUTION_FAILED: "Legacy tool execution failed",
  MUTATION_GUARD_BLOCKED: "Mutation guard rejected operation",
  RATE_LIMIT_EXCEEDED: "Execution rate limit exceeded",
  MAX_CONCURRENT_EXECUTIONS_EXCEEDED: "Execution concurrency limit exceeded",
  SOURCE_CONCURRENCY_LIMIT_EXCEEDED: "Source concurrency limit exceeded",
  TOKEN_FILE_PERMISSIONS_INVALID: "Token configuration is invalid",
  READ_FILE_TOO_LARGE: "File exceeds allowed read size",
  WRITE_FILE_TOO_LARGE: "File exceeds allowed write size",
  PATCH_TOO_LARGE: "Patch exceeds allowed size",
  PATCH_APPLY_FAILED: "Patch application failed",
  GIT_STATUS_FAILED: "Git status failed",
  GIT_ADD_FAILED: "Git add failed",
  GIT_COMMIT_FAILED: "Git commit failed",
  SEARCH_FAILED: "Search execution failed",
  COMMAND_VALIDATION_FAILED: "Command validation failed",
  COMMAND_TIMEOUT: "Command execution timed out",
  TASK_RUNNER_FAILED: "Task runner execution failed",
  SECURITY_AUDIT_FAILED: "Security audit failed",
  SUPERVISOR_TOOL_FAILED: "Tool execution failed",
  EXECUTION_CONFIG_MISMATCH: "Execution policy authority mismatch",
  SECRET_MANIFEST_MISMATCH: "Secret authority mismatch",
  WORKLOAD_NOT_VERIFIED: "Execution integrity verification failed",
  WORKLOAD_HASH_MISMATCH: "Execution integrity verification failed",
  WORKLOAD_IMAGE_MISMATCH: "Execution integrity verification failed",
  WORKLOAD_MANIFEST_MISMATCH: "Execution integrity verification failed",
  WORKLOAD_MUTATION_DETECTED: "Execution integrity verification failed",
  WORKLOAD_MANIFEST_SCHEMA_INVALID: "Execution integrity verification failed",
  WORKLOAD_MANIFEST_MISSING: "Execution integrity verification failed",
  WORKLOAD_MANIFEST_PATH_OVERRIDE_FORBIDDEN: "Execution integrity verification failed",
  WORKLOAD_MANIFEST_WRITABLE_IN_PRODUCTION: "Execution integrity verification failed",
  WORKLOAD_ATTESTATION_NOT_TRUSTED: "Execution attestation verification failed",
  WORKLOAD_ATTESTATION_REFERENCE_MISMATCH: "Execution attestation verification failed",
  WORKLOAD_ATTESTATION_REFERENCE_MISSING: "Execution attestation verification failed",
  WORKLOAD_ATTESTATION_REFERENCE_SCHEMA_INVALID: "Execution attestation verification failed",
  WORKLOAD_ATTESTATION_REFERENCE_PATH_OVERRIDE_FORBIDDEN: "Execution attestation verification failed",
  WORKLOAD_ATTESTATION_REFERENCE_WRITABLE_IN_PRODUCTION: "Execution attestation verification failed",
  WORKLOAD_ATTESTATION_REFERENCE_HASH_MISSING: "Execution attestation verification failed",
  WORKLOAD_ATTESTATION_SIGNATURE_INVALID: "Execution attestation verification failed",
  WORKLOAD_ATTESTATION_EVIDENCE_INVALID: "Execution attestation verification failed",
  WORKLOAD_ATTESTATION_STALE: "Execution attestation verification failed",
  WORKLOAD_ATTESTATION_CHALLENGE_MISMATCH: "Execution attestation verification failed",
  WORKLOAD_ATTESTATION_REPLAY_DETECTED: "Execution attestation verification failed",
  WORKLOAD_ATTESTATION_PEER_STICKY_UNTRUSTED: "Execution attestation verification failed",
};

const COUNTER_ALIASES: Record<string, string[]> = {
  auth_failures: ["authFailures"],
  unauthorized_tool_attempts: ["unauthorizedToolAttempts"],
  internal_spoof_attempts: ["internalSpoofAttempts"],
  mutation_guard_blocks: ["mutationGuardBlocks"],
  rate_limit_blocks: ["rateLimitTriggers"],
  audit_rotations: ["auditRotationCount"],
  audit_overflow_drops: ["auditDropCount"],
};

function normalizeRecord(input: unknown): JsonObject {
  return input && typeof input === "object" && !Array.isArray(input) ? (input as JsonObject) : {};
}

function parseBoolean(value: string | undefined, fallback = false): boolean {
  const raw = String(value || "").trim().toLowerCase();
  if (!raw) return fallback;
  return raw === "1" || raw === "true" || raw === "yes";
}

function parsePositiveInt(value: unknown, fallback: number): number {
  const parsed = Number.parseInt(String(value ?? "").trim(), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
}

function normalizeString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function parseBearerToken(authHeader: string | undefined): string {
  const value = String(authHeader || "").trim();
  const match = value.match(/^Bearer\s+(.+)$/i);
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

function sanitizeMessageForClient(code: string, fallback = "Execution failed"): string {
  if (SAFE_ERROR_MESSAGES[code]) {
    return SAFE_ERROR_MESSAGES[code];
  }
  return fallback;
}

function isNoEntError(error: unknown): boolean {
  return Boolean(error && typeof error === "object" && "code" in error && (error as { code?: unknown }).code === "ENOENT");
}

function normalizeToolName(raw: string): string {
  const tool = String(raw || "").trim();
  if (!tool) {
    return "";
  }
  if (!/^[a-z0-9_.-]{1,128}$/i.test(tool)) {
    return "";
  }
  return tool;
}

function truncateText(value: string, maxChars: number): string {
  if (value.length <= maxChars) {
    return value;
  }
  return `${value.slice(0, maxChars)}...<truncated>`;
}

function isControlCharacterPresent(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code === 9 || code === 10 || code === 13) {
      continue;
    }
    if (code < 32 || code === 127) {
      return true;
    }
  }
  return false;
}

function validateSafeStringField(value: string, fieldName: string, minLength: number, maxLength: number): void {
  if (value.length < minLength || value.length > maxLength) {
    throw Object.assign(new Error(`${fieldName} length is invalid`), { code: "INVALID_ARGUMENT" });
  }
  if (isControlCharacterPresent(value)) {
    throw Object.assign(new Error(`${fieldName} contains unsupported control characters`), { code: "INVALID_ARGUMENT" });
  }
}

function validateTaskRunnerArgs(args: unknown): string[] {
  if (!Array.isArray(args)) {
    return [];
  }
  if (args.length > MAX_REQUESTED_COMMAND_ARGS) {
    throw Object.assign(new Error("Too many command arguments"), { code: "COMMAND_VALIDATION_FAILED" });
  }
  const normalized = args.map((entry) => String(entry));
  for (const entry of normalized) {
    validateSafeStringField(entry, "command arg", 1, MAX_REQUESTED_COMMAND_ARG_LENGTH);
  }
  return normalized;
}

function validateTaskRunnerCommand(commandRaw: unknown): string {
  const command = typeof commandRaw === "string" && commandRaw.trim() ? commandRaw.trim() : "npm";
  if (!ALLOWED_TASK_RUNNER_COMMANDS.has(command)) {
    throw Object.assign(new Error(`Unsupported command: ${command}`), { code: "COMMAND_VALIDATION_FAILED" });
  }
  return command;
}

interface SchemaValidationIssue {
  code: string;
  message: string;
}

function validateValueAgainstSchema(schemaRaw: unknown, value: unknown, fieldPath: string): SchemaValidationIssue | null {
  const schema = normalizeRecord(schemaRaw);
  const type = typeof schema.type === "string" ? schema.type : "";

  if (!type) {
    return {
      code: "INVALID_REQUEST",
      message: `${fieldPath} schema type is not declared`,
    };
  }

  if (type === "string") {
    if (typeof value !== "string") {
      return { code: "INVALID_ARGUMENT", message: `${fieldPath} must be a string` };
    }

    const minLength = typeof schema.minLength === "number" ? Math.max(0, schema.minLength) : undefined;
    const maxLength = typeof schema.maxLength === "number" ? Math.max(0, schema.maxLength) : undefined;
    if (typeof minLength === "number" && value.length < minLength) {
      return { code: "INVALID_ARGUMENT", message: `${fieldPath} must be at least ${minLength} characters` };
    }
    if (typeof maxLength === "number" && value.length > maxLength) {
      return { code: "INVALID_ARGUMENT", message: `${fieldPath} must be at most ${maxLength} characters` };
    }

    if (typeof schema.pattern === "string") {
      try {
        const pattern = new RegExp(schema.pattern);
        if (!pattern.test(value)) {
          return { code: "INVALID_ARGUMENT", message: `${fieldPath} has invalid format` };
        }
      } catch {
        return { code: "INVALID_REQUEST", message: `${fieldPath} schema pattern is invalid` };
      }
    }

    if (Array.isArray(schema.enum) && !schema.enum.includes(value)) {
      return { code: "INVALID_ARGUMENT", message: `${fieldPath} is not an allowed value` };
    }
    return null;
  }

  if (type === "number") {
    if (typeof value !== "number" || !Number.isFinite(value)) {
      return { code: "INVALID_ARGUMENT", message: `${fieldPath} must be a finite number` };
    }
    const minimum = typeof schema.minimum === "number" ? schema.minimum : undefined;
    const maximum = typeof schema.maximum === "number" ? schema.maximum : undefined;
    if (typeof minimum === "number" && value < minimum) {
      return { code: "INVALID_ARGUMENT", message: `${fieldPath} must be >= ${minimum}` };
    }
    if (typeof maximum === "number" && value > maximum) {
      return { code: "INVALID_ARGUMENT", message: `${fieldPath} must be <= ${maximum}` };
    }
    return null;
  }

  if (type === "boolean") {
    if (typeof value !== "boolean") {
      return { code: "INVALID_ARGUMENT", message: `${fieldPath} must be a boolean` };
    }
    return null;
  }

  if (type === "array") {
    if (!Array.isArray(value)) {
      return { code: "INVALID_ARGUMENT", message: `${fieldPath} must be an array` };
    }

    const maxItems = typeof schema.maxItems === "number" ? Math.max(0, schema.maxItems) : undefined;
    if (typeof maxItems === "number" && value.length > maxItems) {
      return { code: "INVALID_ARGUMENT", message: `${fieldPath} must contain <= ${maxItems} items` };
    }

    if (schema.items) {
      for (let index = 0; index < value.length; index += 1) {
        const issue = validateValueAgainstSchema(schema.items, value[index], `${fieldPath}[${index}]`);
        if (issue) {
          return issue;
        }
      }
    }

    return null;
  }

  if (type === "object") {
    const record = normalizeRecord(value);
    const isObject = value && typeof value === "object" && !Array.isArray(value);
    if (!isObject) {
      return { code: "INVALID_ARGUMENT", message: `${fieldPath} must be an object` };
    }

    const properties = normalizeRecord(schema.properties);
    const required = Array.isArray(schema.required) ? schema.required.filter((entry) => typeof entry === "string") : [];

    for (const requiredKey of required) {
      if (!Object.prototype.hasOwnProperty.call(record, requiredKey)) {
        return { code: "INVALID_ARGUMENT", message: `${fieldPath}.${requiredKey} is required` };
      }
    }

    const additionalProperties = schema.additionalProperties;
    if (additionalProperties === false) {
      for (const key of Object.keys(record)) {
        if (!Object.prototype.hasOwnProperty.call(properties, key)) {
          return { code: "INVALID_ARGUMENT", message: `${fieldPath}.${key} is not allowed` };
        }
      }
    }

    for (const [key, propertySchema] of Object.entries(properties)) {
      if (!Object.prototype.hasOwnProperty.call(record, key)) {
        continue;
      }
      const issue = validateValueAgainstSchema(propertySchema, record[key], `${fieldPath}.${key}`);
      if (issue) {
        return issue;
      }
    }

    return null;
  }

  return {
    code: "INVALID_REQUEST",
    message: `${fieldPath} has unsupported schema type: ${type}`,
  };
}

function validateToolArgs(schema: JsonSchema | undefined, args: JsonObject): SchemaValidationIssue | null {
  if (!schema) {
    return null;
  }
  return validateValueAgainstSchema(schema, args, "args");
}

interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  timedOut: boolean;
}

async function runCommand(
  command: string,
  args: string[],
  cwd: string,
  timeoutMs: number,
  maxBuffer: number,
): Promise<CommandResult> {
  try {
    const result = await execFileAsync(command, args, {
      cwd,
      env: process.env,
      timeout: timeoutMs,
      maxBuffer,
      windowsHide: true,
    });
    return {
      stdout: String(result.stdout || ""),
      stderr: String(result.stderr || ""),
      exitCode: 0,
      timedOut: false,
    };
  } catch (error) {
    const err = error as { stdout?: string; stderr?: string; code?: number | string; message?: string; killed?: boolean; signal?: string };
    const timedOut = err.killed === true && err.signal === "SIGTERM";
    const code = typeof err.code === "number" ? err.code : 1;
    return {
      stdout: String(err.stdout || ""),
      stderr: String(err.stderr || err.message || ""),
      exitCode: code,
      timedOut,
    };
  }
}

function extractTokenFromConfig(parsed: JsonObject): string {
  const candidates = [
    parsed.bridgeAuthToken,
    parsed.authToken,
    parsed.bearerToken,
    parsed.token,
  ];
  for (const candidate of candidates) {
    if (typeof candidate === "string" && candidate.trim()) {
      return candidate.trim();
    }
  }
  return "";
}

async function resolveTokenFromWorkspace(workspaceRoot: string): Promise<string> {
  const tokenPath = path.join(workspaceRoot, ".cline", "cline_mcp_settings.json");

  try {
    const stat = await fs.stat(tokenPath);
    if ((stat.mode & 0o077) !== 0) {
      if (!warnedWeakTokenPermissionPaths.has(tokenPath)) {
        warnedWeakTokenPermissionPaths.add(tokenPath);
        process.emitWarning("Token file permissions should be 0600", {
          code: "TOKEN_FILE_PERMISSIONS_WEAK",
          detail: "Set .cline/cline_mcp_settings.json mode to 600 for production hardening.",
        });
      }
    }

    const raw = await fs.readFile(tokenPath, "utf8");
    const parsed = normalizeRecord(JSON.parse(raw));
    const token = extractTokenFromConfig(parsed);
    if (token) {
      return token;
    }
  } catch (error) {
    if (!isNoEntError(error)) {
      throw error;
    }
  }

  return String(process.env.BRIDGE_AUTH_TOKEN || process.env.SUPERVISOR_AUTH_TOKEN || "").trim();
}

function normalizeToolDefinition(entry: unknown): SupervisorToolDefinition {
  const record = normalizeRecord(entry);
  const name = normalizeToolName(String(record.name || ""));
  if (!name) {
    throw Object.assign(new Error("Supervisor registry contains invalid tool name"), { code: "INVALID_REQUEST" });
  }

  const mutationClass = String(record.mutationClass || "") as MutationClass;
  if (!(["read", "write", "exec", "security"] as MutationClass[]).includes(mutationClass)) {
    throw Object.assign(new Error(`Invalid mutationClass for ${name}`), { code: "INVALID_REQUEST" });
  }

  const loggingLevel = String(record.loggingLevel || "") as "info" | "warn" | "error";
  if (!(["info", "warn", "error"] as Array<"info" | "warn" | "error">).includes(loggingLevel)) {
    throw Object.assign(new Error(`Invalid loggingLevel for ${name}`), { code: "INVALID_REQUEST" });
  }

  const rolesRaw = Array.isArray(record.roles) ? record.roles : [];
  const roles = rolesRaw
    .map((role) => String(role || "").trim())
    .filter((role): role is "supervisor" | "internal" | "admin" => role === "supervisor" || role === "internal" || role === "admin");

  if (roles.length === 0) {
    throw Object.assign(new Error(`No valid roles defined for ${name}`), { code: "INVALID_REQUEST" });
  }

  const workspacePathArgs = Array.isArray(record.workspacePathArgs)
    ? record.workspacePathArgs.map((key) => String(key || "").trim()).filter(Boolean)
    : [];

  const inputSchema = normalizeRecord(record.inputSchema);
  if (String(inputSchema.type || "") !== "object" || inputSchema.additionalProperties !== false) {
    throw Object.assign(new Error(`inputSchema for ${name} must declare type=object and additionalProperties=false`), {
      code: "INVALID_REQUEST",
    });
  }

  return {
    name,
    description: typeof record.description === "string" ? record.description : undefined,
    inputSchema,
    mutationClass,
    loggingLevel,
    roles,
    workspacePathArgs,
  };
}

async function loadRegistryFromJson(registryPath: string): Promise<SupervisorToolDefinition[]> {
  const raw = await fs.readFile(registryPath, "utf8");
  const parsed = JSON.parse(raw) as unknown;
  if (!Array.isArray(parsed)) {
    throw Object.assign(new Error("Supervisor registry JSON must be an array"), { code: "INVALID_REQUEST" });
  }
  return parsed.map((entry) => normalizeToolDefinition(entry));
}

export function createExecutionRouter(options: ExecutionRouterOptions): ExecutionRouter {
  const workspaceRoot = path.resolve(options.workspaceRoot);
  const canonicalWorkspaceRootPromise = canonicalizeWorkspaceRoot(workspaceRoot);
  const supervisorMode = typeof options.supervisorMode === "boolean" ? options.supervisorMode : parseBoolean(process.env.SUPERVISOR_MODE, false);
  const supervisorAuthPhase =
    options.supervisorAuthPhase || (String(process.env.SUPERVISOR_AUTH_PHASE || "compat").trim().toLowerCase() === "strict" ? "strict" : "compat");
  const mutationGuardEnabled =
    typeof options.mutationGuardEnabled === "boolean"
      ? options.mutationGuardEnabled
      : parseBoolean(process.env.SUPERVISOR_MUTATION_GUARD, false);
  const supervisorInternalToken =
    typeof options.supervisorInternalToken === "string"
      ? options.supervisorInternalToken
      : String(process.env.SUPERVISOR_INTERNAL_TOKEN || "").trim();
  const registryPath = options.registryPath || path.resolve(process.cwd(), "supervisor", "supervisor-registry.json");
  const production = normalizeString(process.env.NODE_ENV).toLowerCase() === "production";
  const workloadIntegrityEnabledConfigured =
    typeof options.workloadIntegrityEnabled === "boolean"
      ? options.workloadIntegrityEnabled
      : parseBoolean(process.env.WORKLOAD_INTEGRITY_ENABLED, production);
  const workloadIntegrityEnabled = production ? true : workloadIntegrityEnabledConfigured;
  const workloadManifestPath =
    typeof options.workloadManifestPath === "string"
      ? options.workloadManifestPath
      : normalizeString(process.env.WORKLOAD_MANIFEST_PATH);
  const workloadManifestExpectedHash = normalizeString(
    options.workloadManifestExpectedHash || process.env.WORKLOAD_MANIFEST_EXPECTED_HASH,
  ).toLowerCase();
  const workloadAttestationEnabledConfigured =
    typeof options.workloadAttestationEnabled === "boolean"
      ? options.workloadAttestationEnabled
      : parseBoolean(process.env.WORKLOAD_ATTESTATION_ENABLED, production);
  const workloadAttestationEnabled = production ? true : workloadAttestationEnabledConfigured;
  const attestationReferencePath =
    typeof options.attestationReferencePath === "string"
      ? options.attestationReferencePath
      : normalizeString(process.env.WORKLOAD_ATTESTATION_REFERENCE_PATH);
  const attestationReferenceExpectedHash = normalizeString(
    options.attestationReferenceExpectedHash || process.env.WORKLOAD_ATTESTATION_REFERENCE_EXPECTED_HASH,
  ).toLowerCase();

  const maxPatchBytes = parsePositiveInt(options.maxPatchBytes, DEFAULT_MAX_PATCH_BYTES);
  const maxWriteFileBytes = parsePositiveInt(options.maxWriteFileBytes, DEFAULT_MAX_WRITE_FILE_BYTES);
  const maxReadFileBytes = parsePositiveInt(options.maxReadFileBytes, DEFAULT_MAX_READ_FILE_BYTES);
  const maxCommandOutputBytes = parsePositiveInt(options.maxCommandOutputBytes, DEFAULT_MAX_COMMAND_OUTPUT_BYTES);
  const gitTimeoutMs = parsePositiveInt(options.gitTimeoutMs, DEFAULT_GIT_TIMEOUT_MS);
  const rgTimeoutMs = parsePositiveInt(options.rgTimeoutMs, DEFAULT_RG_TIMEOUT_MS);
  const nodeTimeoutMs = parsePositiveInt(options.nodeTimeoutMs, DEFAULT_NODE_TIMEOUT_MS);
  const taskRunnerTimeoutMs = parsePositiveInt(options.taskRunnerTimeoutMs, DEFAULT_TASK_RUNNER_TIMEOUT_MS);

  const rateLimitWindowMs = parsePositiveInt(options.rateLimitWindowMs, DEFAULT_RATE_LIMIT_WINDOW_MS);
  const rateLimitMaxRequestsPerWindow = parsePositiveInt(options.rateLimitMaxRequestsPerWindow, DEFAULT_RATE_LIMIT_MAX_REQUESTS_PER_WINDOW);
  const maxConcurrentExecutions = parsePositiveInt(options.maxConcurrentExecutions, DEFAULT_MAX_CONCURRENT_EXECUTIONS);
  const maxConcurrentExecutionsPerSource = parsePositiveInt(
    options.maxConcurrentExecutionsPerSource,
    DEFAULT_MAX_CONCURRENT_EXECUTIONS_PER_SOURCE,
  );

  const counters: Record<string, number> = {};
  const incrementCounter = (name: string, amount = 1): void => {
    counters[name] = (counters[name] || 0) + amount;
    const aliases = COUNTER_ALIASES[name];
    if (!aliases) {
      return;
    }
    for (const alias of aliases) {
      counters[alias] = (counters[alias] || 0) + amount;
    }
  };

  const auditLogPath = options.auditLogPath || path.join(workspaceRoot, ".openclaw", "audit.log");
  const auditLogger = new AsyncRotatingAuditLogger(
    auditLogPath,
    parsePositiveInt(options.auditMaxBytes, DEFAULT_AUDIT_MAX_BYTES),
    parsePositiveInt(options.auditMaxQueueEntries, DEFAULT_AUDIT_MAX_QUEUE_ENTRIES),
    {
      onDrop: (count) => incrementCounter("audit_overflow_drops", count),
      onError: () => incrementCounter("audit_write_errors", 1),
      onRotate: () => incrementCounter("audit_rotations", 1),
    },
  );

  const supervisorHandlers = options.supervisorHandlers || {};
  const legacyVisibleToolsByRole = options.legacyVisibleToolsByRole || {};
  const integrityMetadataProvider =
    typeof options.integrityMetadataProvider === "function" ? options.integrityMetadataProvider : null;

  let registryPromise: Promise<SupervisorToolDefinition[]> | null = null;
  let tokenCache: TokenCache | null = null;
  const sourceExecutionState = new Map<string, SourceExecutionState>();
  let activeExecutionCount = 0;

  function resolveRuntimeImageDigest(context: { transportMetadata?: Record<string, unknown> }): string {
    const transportMetadata = normalizeRecord(context.transportMetadata);
    const direct = normalizeString(transportMetadata.containerImageDigest || transportMetadata.container_image_digest);
    if (direct) {
      return direct;
    }
    return normalizeString(transportMetadata.executionImageDigest || transportMetadata.execution_image_digest);
  }

  function hasRuntimeMutationAttempt(context: { transportMetadata?: Record<string, unknown> }): boolean {
    const transportMetadata = normalizeRecord(context.transportMetadata);
    const overrideRequested =
      transportMetadata.workload_hash_override === true ||
      transportMetadata.workloadHashOverride === true ||
      transportMetadata.workload_manifest_override === true ||
      transportMetadata.workloadManifestOverride === true;
    if (overrideRequested) {
      return true;
    }
    const runtimeOverrideFlag =
      parseBoolean(process.env.WORKLOAD_HASH_OVERRIDE, false) ||
      parseBoolean(process.env.WORKLOAD_INTEGRITY_BYPASS, false) ||
      parseBoolean(process.env.WORKLOAD_INTEGRITY_ALLOW_OVERRIDE, false);
    if (runtimeOverrideFlag) {
      return true;
    }
    if (!production) {
      return false;
    }
    const configuredPath = normalizeString(process.env.WORKLOAD_MANIFEST_PATH);
    if (configuredPath && path.resolve(configuredPath) !== resolveDefaultWorkloadManifestPath()) {
      return true;
    }
    return false;
  }

  const defaultRuntimeDescriptorResolver = (
    tool: string,
    context: WorkloadIntegrityContext,
  ): WorkloadRuntimeDescriptor | null => {
    const normalizedTool = normalizeToolName(tool);
    if (!normalizedTool) {
      return null;
    }
    const sourcePath = path.resolve(__dirname, "execution-router.js");
    return {
      adapterPath: sourcePath,
      entrypointPath: sourcePath,
      runtimeConfig: {
        tool: normalizedTool,
        supervisorMode,
        supervisorAuthPhase,
        mutationGuardEnabled,
      },
      containerImageDigest: resolveRuntimeImageDigest({
        transportMetadata: normalizeRecord(context.transportMetadata),
      }),
      runtimeMutated: hasRuntimeMutationAttempt({
        transportMetadata: normalizeRecord(context.transportMetadata),
      }),
    };
  };

  const workloadRuntimeDescriptorResolver =
    typeof options.workloadRuntimeDescriptorResolver === "function"
      ? options.workloadRuntimeDescriptorResolver
      : defaultRuntimeDescriptorResolver;

  function resolveIntegrityMetadata(context: ExecutionContext): {
    local: Record<string, unknown>;
    peers: Array<Record<string, unknown>>;
  } {
    const fromProvider = integrityMetadataProvider ? integrityMetadataProvider(context) : {};
    const local = normalizeRecord(
      normalizeRecord(fromProvider).local || normalizeRecord(context.transportMetadata).executionMetadata || {},
    );
    const peersRaw = normalizeRecord(fromProvider).peers;
    const peers = Array.isArray(peersRaw)
      ? peersRaw.filter((peer) => peer && typeof peer === "object").map((peer) => normalizeRecord(peer))
      : [];
    return { local, peers };
  }

  const workloadIntegrityVerifier: WorkloadIntegrityVerifier | null = workloadIntegrityEnabled
    ? createWorkloadIntegrityVerifier({
        production,
        nodeId: normalizeString(process.env.SUPERVISOR_NODE_ID) || "node-unknown",
        manifestPath: workloadManifestPath || undefined,
        expectedHash: workloadManifestExpectedHash || undefined,
        allowProductionPathOverride: false,
        runtimeDescriptorResolver: workloadRuntimeDescriptorResolver,
        metrics: {
          increment: (name, labels = {}) => {
            incrementCounter(name, 1);
            if (Object.keys(labels).length > 0) {
              const stableLabel = JSON.stringify(labels, Object.keys(labels).sort());
              incrementCounter(`${name}:${stableLabel}`, 1);
            }
          },
          gauge: (name, value) => {
            counters[name] = Number(value) || 0;
          },
        },
        auditLog: (event) => {
          auditLogger.append({
            requestId: "workload-integrity",
            tool: normalizeString((event.details || {}).workloadID) || "workload-integrity",
            caller: "workload_integrity",
            timestamp: new Date().toISOString(),
            argsHash: hashArgs(event.details || {}),
            resultStatus: event.status === "error" ? "error" : "ok",
            role: "internal",
            source: "in_process",
            code: event.code,
            details: event.details,
          });
        },
      })
    : null;

  const workloadAttestationRuntime: WorkloadAttestationRuntime | null = workloadAttestationEnabled
    ? initializeAttestation({
        production,
        nodeId: normalizeString(process.env.SUPERVISOR_NODE_ID) || "node-unknown",
        referencePath: attestationReferencePath || undefined,
        expectedReferenceHash: attestationReferenceExpectedHash || undefined,
        allowProductionPathOverride: false,
        metrics: {
          increment: (name, labels = {}) => {
            incrementCounter(name, 1);
            if (Object.keys(labels).length > 0) {
              const stableLabel = JSON.stringify(labels, Object.keys(labels).sort());
              incrementCounter(`${name}:${stableLabel}`, 1);
            }
          },
          gauge: (name, value) => {
            counters[name] = Number(value) || 0;
          },
        },
        auditLog: (event) => {
          auditLogger.append({
            requestId: "workload-attestation",
            tool: normalizeString((event.details || {}).nodeId) || "workload-attestation",
            caller: "workload_attestation",
            timestamp: new Date().toISOString(),
            argsHash: hashArgs(event.details || {}),
            resultStatus: event.status === "error" ? "error" : "ok",
            role: "internal",
            source: "in_process",
            code: event.code,
            details: event.details,
          });
        },
      })
    : null;

  if (workloadIntegrityVerifier) {
    const startup = workloadIntegrityVerifier.initialize();
    if (!startup.ok) {
      incrementCounter("workload.attestation.failure", 1);
      if (startup.code === "WORKLOAD_IMAGE_MISMATCH") {
        incrementCounter("workload.image.mismatch", 1);
      } else if (startup.code === "WORKLOAD_MANIFEST_MISMATCH") {
        incrementCounter("workload.manifest.hash.mismatch", 1);
      } else {
        incrementCounter("workload.hash.mismatch", 1);
      }
    } else {
      incrementCounter("workload.hash.verified", 1);
    }
  }

  if (workloadAttestationRuntime) {
    const startup = workloadAttestationRuntime.initializeAttestation();
    if (!startup.ok) {
      incrementCounter("workload.attestation.failure", 1);
    } else {
      incrementCounter("workload.attestation.success", 1);
    }
  }

  async function getCanonicalWorkspaceRoot(): Promise<string> {
    return canonicalWorkspaceRootPromise;
  }

  async function getRegistry(): Promise<SupervisorToolDefinition[]> {
    if (!registryPromise) {
      registryPromise = loadRegistryFromJson(registryPath).catch((error) => {
        registryPromise = null;
        throw error;
      });
    }
    return registryPromise;
  }

  async function getExpectedToken(): Promise<string> {
    const now = Date.now();
    if (tokenCache && now - tokenCache.loadedAt < DEFAULT_CACHE_TTL_MS) {
      return tokenCache.value;
    }

    const value = await resolveTokenFromWorkspace(workspaceRoot);
    tokenCache = { value, loadedAt: now };
    return value;
  }

  function hasTrustedInternalContext(context: ExecutionContext): boolean {
    if (context.trustedInProcessCaller === true) {
      return true;
    }
    if (!supervisorInternalToken) {
      return false;
    }
    const provided = String(context.internalToken || "").trim();
    if (!provided) {
      return false;
    }
    return timingSafeEqualUtf8(provided, supervisorInternalToken);
  }

  function resolveTrustedInProcessRole(context: ExecutionContext): ExecutionRole {
    if (context.trustedInProcessRole === "admin") {
      return "admin";
    }
    return "internal";
  }

  async function resolveRole(context: ExecutionContext): Promise<ExecutionRole> {
    if (hasTrustedInternalContext(context)) {
      return context.trustedInProcessCaller ? resolveTrustedInProcessRole(context) : "internal";
    }

    const providedToken = parseBearerToken(context.authHeader);
    if (!providedToken) {
      return "anonymous";
    }

    const expectedToken = await getExpectedToken();
    if (expectedToken && timingSafeEqualUtf8(expectedToken, providedToken)) {
      return "supervisor";
    }

    const adminToken = String(process.env.SUPERVISOR_ADMIN_TOKEN || "").trim();
    if (adminToken && timingSafeEqualUtf8(adminToken, providedToken)) {
      return "admin";
    }

    return "anonymous";
  }

  function acquireRatePermit(context: ExecutionContext): ExecutionResult | null {
    const sourceKey = context.source;
    const now = Date.now();

    let state = sourceExecutionState.get(sourceKey);
    if (!state) {
      state = {
        windowStartedAtMs: now,
        requestsInWindow: 0,
        activeExecutions: 0,
      };
      sourceExecutionState.set(sourceKey, state);
    }

    if (now - state.windowStartedAtMs >= rateLimitWindowMs) {
      state.windowStartedAtMs = now;
      state.requestsInWindow = 0;
    }

    if (state.requestsInWindow >= rateLimitMaxRequestsPerWindow) {
      incrementCounter("rate_limit_blocks", 1);
      return {
        ok: false,
        code: "RATE_LIMIT_EXCEEDED",
        message: sanitizeMessageForClient("RATE_LIMIT_EXCEEDED"),
      };
    }

    if (activeExecutionCount >= maxConcurrentExecutions) {
      incrementCounter("concurrency_limit_blocks", 1);
      return {
        ok: false,
        code: "MAX_CONCURRENT_EXECUTIONS_EXCEEDED",
        message: sanitizeMessageForClient("MAX_CONCURRENT_EXECUTIONS_EXCEEDED"),
      };
    }

    if (state.activeExecutions >= maxConcurrentExecutionsPerSource) {
      incrementCounter("source_concurrency_limit_blocks", 1);
      return {
        ok: false,
        code: "SOURCE_CONCURRENCY_LIMIT_EXCEEDED",
        message: sanitizeMessageForClient("SOURCE_CONCURRENCY_LIMIT_EXCEEDED"),
      };
    }

    state.requestsInWindow += 1;
    state.activeExecutions += 1;
    activeExecutionCount += 1;
    return null;
  }

  function releaseRatePermit(context: ExecutionContext): void {
    const state = sourceExecutionState.get(context.source);
    if (state) {
      state.activeExecutions = Math.max(0, state.activeExecutions - 1);
    }
    activeExecutionCount = Math.max(0, activeExecutionCount - 1);
  }

  async function runDefaultSupervisorHandler(tool: string, args: JsonObject): Promise<unknown> {
    const canonicalRoot = await getCanonicalWorkspaceRoot();

    if (tool === "supervisor.read_file") {
      const filePath = String(args.path || "").trim();
      validateSafeStringField(filePath, "path", 1, 4096);
      const stat = await fs.stat(filePath);
      if (!stat.isFile()) {
        throw Object.assign(new Error("Target must be a file"), { code: "INVALID_ARGUMENT" });
      }
      if (stat.size > maxReadFileBytes) {
        throw Object.assign(new Error("File exceeds read limit"), { code: "READ_FILE_TOO_LARGE" });
      }
      const content = await fs.readFile(filePath, "utf8");
      return { ok: true, path: path.relative(canonicalRoot, filePath) || ".", content };
    }

    if (tool === "supervisor.write_file") {
      const filePath = String(args.path || "").trim();
      const content = String(args.content || "");
      validateSafeStringField(filePath, "path", 1, 4096);
      const byteLength = Buffer.byteLength(content, "utf8");
      if (byteLength > maxWriteFileBytes) {
        throw Object.assign(new Error("File exceeds write limit"), { code: "WRITE_FILE_TOO_LARGE" });
      }

      const createParents = Boolean(args.createParents);
      if (createParents) {
        await fs.mkdir(path.dirname(filePath), { recursive: true });
      }
      await fs.writeFile(filePath, content, "utf8");
      return { ok: true, path: path.relative(canonicalRoot, filePath) || ".", bytes: byteLength };
    }

    if (tool === "supervisor.apply_patch") {
      const patch = String(args.patch || "");
      if (!patch.trim()) {
        throw Object.assign(new Error("patch is required"), { code: "INVALID_ARGUMENT" });
      }
      if (Buffer.byteLength(patch, "utf8") > maxPatchBytes) {
        throw Object.assign(new Error("Patch exceeds allowed size"), { code: "PATCH_TOO_LARGE" });
      }

      const patchPath = path.join(canonicalRoot, ".openclaw", "tmp", `patch-${Date.now()}.diff`);
      await fs.mkdir(path.dirname(patchPath), { recursive: true });
      await fs.writeFile(patchPath, patch, "utf8");

      const result = await runCommand("git", ["apply", "--whitespace=nowarn", patchPath], canonicalRoot, gitTimeoutMs, maxCommandOutputBytes);
      await fs.rm(patchPath, { force: true });

      if (result.timedOut) {
        throw Object.assign(new Error("git apply timed out"), { code: "COMMAND_TIMEOUT" });
      }
      if (result.exitCode !== 0) {
        throw Object.assign(new Error("git apply failed"), { code: "PATCH_APPLY_FAILED" });
      }
      return { ok: true };
    }

    if (tool === "supervisor.git_status") {
      const result = await runCommand("git", ["status", "--porcelain"], canonicalRoot, gitTimeoutMs, maxCommandOutputBytes);
      if (result.timedOut) {
        throw Object.assign(new Error("git status timed out"), { code: "COMMAND_TIMEOUT" });
      }
      if (result.exitCode !== 0) {
        throw Object.assign(new Error("git status failed"), { code: "GIT_STATUS_FAILED" });
      }
      return {
        ok: true,
        stdout: truncateText(result.stdout, 16_000),
        changed_files: result.stdout
          .split(/\r?\n/)
          .map((line) => line.trim())
          .filter(Boolean)
          .map((line) => line.replace(/^[A-Z?]{1,2}\s+/, "").trim()),
      };
    }

    if (tool === "supervisor.git_commit") {
      const message = String(args.message || "").trim();
      validateSafeStringField(message, "message", 1, 200);

      if (Boolean(args.addAll)) {
        const addResult = await runCommand("git", ["add", "-A"], canonicalRoot, gitTimeoutMs, maxCommandOutputBytes);
        if (addResult.timedOut) {
          throw Object.assign(new Error("git add timed out"), { code: "COMMAND_TIMEOUT" });
        }
        if (addResult.exitCode !== 0) {
          throw Object.assign(new Error("git add failed"), { code: "GIT_ADD_FAILED" });
        }
      }

      const result = await runCommand("git", ["commit", "-m", message], canonicalRoot, gitTimeoutMs, maxCommandOutputBytes);
      if (result.timedOut) {
        throw Object.assign(new Error("git commit timed out"), { code: "COMMAND_TIMEOUT" });
      }
      if (result.exitCode !== 0) {
        throw Object.assign(new Error("git commit failed"), { code: "GIT_COMMIT_FAILED" });
      }
      return { ok: true, stdout: truncateText(result.stdout, 16_000) };
    }

    if (tool === "supervisor.search") {
      const pattern = String(args.pattern || "").trim();
      validateSafeStringField(pattern, "pattern", 1, 256);
      const maxResultsRaw = Number(args.maxResults);
      const maxResults = Number.isFinite(maxResultsRaw) ? Math.max(1, Math.min(500, Math.floor(maxResultsRaw))) : 200;
      const searchPath = typeof args.path === "string" && args.path.trim() ? String(args.path).trim() : canonicalRoot;

      const rgArgs = ["--line-number", "--no-heading", "--max-count", String(maxResults), "--", pattern, searchPath];
      const result = await runCommand("rg", rgArgs, canonicalRoot, rgTimeoutMs, maxCommandOutputBytes);

      if (result.timedOut) {
        throw Object.assign(new Error("rg timed out"), { code: "COMMAND_TIMEOUT" });
      }
      if (result.exitCode !== 0 && result.exitCode !== 1) {
        throw Object.assign(new Error("rg failed"), { code: "SEARCH_FAILED" });
      }

      return {
        ok: true,
        stdout: truncateText(result.stdout, 64_000),
        stderr: truncateText(result.stderr, 4_000),
        exitCode: result.exitCode,
      };
    }

    if (tool === "supervisor.run_tests") {
      const command = validateTaskRunnerCommand(args.command);
      const commandArgs = validateTaskRunnerArgs(args.args);
      const effectiveArgs = commandArgs.length > 0 ? commandArgs : ["test"];

      const result = await runCommand(command, effectiveArgs, canonicalRoot, taskRunnerTimeoutMs, maxCommandOutputBytes);
      if (result.timedOut) {
        throw Object.assign(new Error("Task runner timed out"), { code: "COMMAND_TIMEOUT" });
      }
      return {
        ok: result.exitCode === 0,
        stdout: truncateText(result.stdout, 64_000),
        stderr: truncateText(result.stderr, 16_000),
        exitCode: result.exitCode,
        command,
        args: effectiveArgs,
      };
    }

    if (tool === "supervisor.run_lint") {
      const command = validateTaskRunnerCommand(args.command);
      const commandArgs = validateTaskRunnerArgs(args.args);
      const effectiveArgs = commandArgs.length > 0 ? commandArgs : ["run", "lint"];

      const result = await runCommand(command, effectiveArgs, canonicalRoot, taskRunnerTimeoutMs, maxCommandOutputBytes);
      if (result.timedOut) {
        throw Object.assign(new Error("Task runner timed out"), { code: "COMMAND_TIMEOUT" });
      }
      return {
        ok: result.exitCode === 0,
        stdout: truncateText(result.stdout, 64_000),
        stderr: truncateText(result.stderr, 16_000),
        exitCode: result.exitCode,
        command,
        args: effectiveArgs,
      };
    }

    if (tool === "supervisor.security_audit") {
      const result = await runCommand(
        "node",
        ["deployment/deploy-check.js", "--no-diagnostics"],
        canonicalRoot,
        nodeTimeoutMs,
        maxCommandOutputBytes,
      );
      if (result.timedOut) {
        throw Object.assign(new Error("security audit timed out"), { code: "COMMAND_TIMEOUT" });
      }
      if (result.exitCode !== 0) {
        throw Object.assign(new Error("security audit failed"), { code: "SECURITY_AUDIT_FAILED" });
      }
      let parsed: unknown = { raw: truncateText(result.stdout, 16_000) };
      try {
        parsed = JSON.parse(result.stdout || "{}");
      } catch {
        parsed = { raw: truncateText(result.stdout, 16_000) };
      }
      return { ok: true, result: parsed };
    }

    throw Object.assign(new Error("No handler registered"), { code: "UNAUTHORIZED_TOOL" });
  }

  async function listTools(context: ExecutionContext): Promise<ExecutionToolDescriptor[]> {
    try {
      const role = await resolveRole(context);
      const rolePolicy = ROLE_POLICY[role];
      if (!rolePolicy || !rolePolicy.canSeeTools) {
        return [];
      }

      const registry = await getRegistry();
      const visibleRegistryTools = registry
        .filter((entry) => entry.roles.includes(role as "supervisor" | "internal" | "admin"))
        .map((entry) => ({
          name: entry.name,
          description: entry.description,
          inputSchema: entry.inputSchema,
        }));

      let visibleLegacyTools: ExecutionToolDescriptor[] = [];
      if (context.legacyListTools && rolePolicy.canUseLegacy) {
        const strictSupervisor = supervisorMode && supervisorAuthPhase === "strict" && role === "supervisor";
        if (!strictSupervisor) {
          const legacyTools = await context.legacyListTools().catch(() => []);
          const allowedLegacySet = new Set(Array.isArray(legacyVisibleToolsByRole[role]) ? legacyVisibleToolsByRole[role] : []);
          visibleLegacyTools = legacyTools.filter((tool) => allowedLegacySet.has(tool.name));
        }
      }

      const seen = new Set<string>();
      return [...visibleRegistryTools, ...visibleLegacyTools].filter((tool) => {
        if (!tool.name || seen.has(tool.name)) {
          return false;
        }
        seen.add(tool.name);
        return true;
      });
    } catch {
      incrementCounter("auth_failures", 1);
      return [];
    }
  }

  async function execute(tool: string, argsInput: JsonObject, context: ExecutionContext): Promise<ExecutionResult> {
    const toolName = normalizeToolName(tool);
    if (!toolName) {
      return {
        ok: false,
        code: "INVALID_REQUEST",
        message: sanitizeMessageForClient("INVALID_REQUEST"),
      };
    }

    const permitError = acquireRatePermit(context);
    if (permitError) {
      return permitError;
    }

    try {
      const args = normalizeRecord(argsInput);

      const trustedInternal = hasTrustedInternalContext(context);
      if (context.internalFlagRequested && !trustedInternal) {
        incrementCounter("internal_spoof_attempts", 1);
        return {
          ok: false,
          code: "UNAUTHORIZED_INTERNAL_BYPASS",
          message: sanitizeMessageForClient("UNAUTHORIZED_INTERNAL_BYPASS"),
        };
      }

      const role = await resolveRole(context);
      const rolePolicy = ROLE_POLICY[role];
      if (!rolePolicy) {
        incrementCounter("unauthorized_role_attempts", 1);
        return {
          ok: false,
          code: "UNAUTHORIZED_ROLE",
          message: sanitizeMessageForClient("UNAUTHORIZED_ROLE"),
        };
      }

      if (supervisorMode && supervisorAuthPhase === "strict" && role === "anonymous") {
        incrementCounter("auth_failures", 1);
        return {
          ok: false,
          code: "UNAUTHORIZED",
          message: sanitizeMessageForClient("UNAUTHORIZED"),
        };
      }

      if (!rolePolicy.canExecuteTools) {
        incrementCounter("unauthorized_role_attempts", 1);
        return {
          ok: false,
          code: "UNAUTHORIZED",
          message: sanitizeMessageForClient("UNAUTHORIZED"),
        };
      }

      const integrityMetadata = resolveIntegrityMetadata(context);
      const localMetadata = integrityMetadata.local || {};
      if (workloadIntegrityVerifier) {
        if (production) {
          const localPolicyHash = normalizeString(
            localMetadata.executionPolicyHash || localMetadata.execution_policy_hash || "",
          ).toLowerCase();
          const localSecretHash = normalizeString(
            localMetadata.secretManifestHash || localMetadata.secret_manifest_hash || "",
          ).toLowerCase();
          const peerList = Array.isArray(integrityMetadata.peers) ? integrityMetadata.peers : [];

          for (const peer of peerList) {
            const peerStatus = normalizeString(peer.status).toUpperCase();
            if (peerStatus && peerStatus !== "UP") {
              continue;
            }
            const peerPolicyHash = normalizeString(peer.executionPolicyHash || peer.execution_policy_hash || "").toLowerCase();
            const peerSecretHash = normalizeString(peer.secretManifestHash || peer.secret_manifest_hash || "").toLowerCase();

            if (localPolicyHash && peerPolicyHash && localPolicyHash !== peerPolicyHash) {
              incrementCounter("workload.integrity.block", 1);
              return {
                ok: false,
                code: "EXECUTION_CONFIG_MISMATCH",
                message: sanitizeMessageForClient("EXECUTION_CONFIG_MISMATCH"),
              };
            }
            if (localSecretHash && peerSecretHash && localSecretHash !== peerSecretHash) {
              incrementCounter("workload.integrity.block", 1);
              return {
                ok: false,
                code: "SECRET_MANIFEST_MISMATCH",
                message: sanitizeMessageForClient("SECRET_MANIFEST_MISMATCH"),
              };
            }
          }
        }

        const peerSummary = workloadIntegrityVerifier.evaluatePeerWorkloadPosture(integrityMetadata.peers || []);
        if (production && !peerSummary.ok) {
          return {
            ok: false,
            code: "WORKLOAD_MANIFEST_MISMATCH",
            message: sanitizeMessageForClient("WORKLOAD_MANIFEST_MISMATCH"),
          };
        }

        const integrityTransportMetadata = {
          ...normalizeRecord(context.transportMetadata),
          execution_policy_hash: normalizeString(
            localMetadata.executionPolicyHash || localMetadata.execution_policy_hash || "",
          ).toLowerCase(),
          secret_manifest_hash: normalizeString(
            localMetadata.secretManifestHash || localMetadata.secret_manifest_hash || "",
          ).toLowerCase(),
          workload_manifest_hash: normalizeString(
            localMetadata.workloadManifestHash || localMetadata.workload_manifest_hash || "",
          ).toLowerCase(),
        };

        const verification = workloadIntegrityVerifier.verifyExecution({
          tool: toolName,
          context: {
            requestId: context.requestId,
            workspaceRoot: context.workspaceRoot,
            source: context.source,
            caller: context.caller,
            transportMetadata: integrityTransportMetadata,
          },
        });

        if (!verification.ok) {
          if (!production) {
            auditLogger.append({
              requestId: context.requestId,
              tool: toolName,
              caller: context.caller,
              timestamp: new Date().toISOString(),
              argsHash: hashArgs(args),
              resultStatus: "error",
              role,
              source: context.source,
              code: verification.code || "WORKLOAD_NOT_VERIFIED",
              details: verification.details,
            });
            incrementCounter("workload.integrity.warning", 1);
          } else {
            return {
              ok: false,
              code: verification.code || "WORKLOAD_NOT_VERIFIED",
              message: sanitizeMessageForClient(verification.code || "WORKLOAD_NOT_VERIFIED", verification.message),
            };
          }
        }
      }

      if (workloadAttestationRuntime) {
        const localAttestation = workloadAttestationRuntime.syncLocalAttestationPosture(localMetadata);
        if (!localAttestation.ok) {
          incrementCounter("workload.attestation.failure", 1);
          if (production) {
            incrementCounter("workload.attestation.block", 1);
            return {
              ok: false,
              code: "WORKLOAD_ATTESTATION_NOT_TRUSTED",
              message: sanitizeMessageForClient("WORKLOAD_ATTESTATION_NOT_TRUSTED"),
            };
          }
        }

        const peerAttestationSummary = workloadAttestationRuntime.evaluatePeerAttestationPosture(integrityMetadata.peers || []);
        if (!peerAttestationSummary.ok) {
          incrementCounter("workload.attestation.peer_untrusted", peerAttestationSummary.criticalMismatches.length || 1);
        }

        const attestationState = workloadAttestationRuntime.getAttestationState();
        if (production && !attestationState.trusted) {
          incrementCounter("workload.attestation.block", 1);
          return {
            ok: false,
            code: "WORKLOAD_ATTESTATION_NOT_TRUSTED",
            message: sanitizeMessageForClient("WORKLOAD_ATTESTATION_NOT_TRUSTED"),
          };
        }
      }

      const registry = await getRegistry();
      const definition = registry.find((entry) => entry.name === toolName);

      if (!definition) {
        const strictExternalNoLegacy = supervisorMode && supervisorAuthPhase === "strict" && !trustedInternal;
        if (strictExternalNoLegacy) {
          incrementCounter("unauthorized_tool_attempts", 1);
          return {
            ok: false,
            code: "UNAUTHORIZED_TOOL",
            message: sanitizeMessageForClient("UNAUTHORIZED_TOOL"),
          };
        }

        if (context.legacyExecute && rolePolicy.canUseLegacy) {
          incrementCounter("legacy_fallback_used", 1);
          try {
            const legacyResult = await context.legacyExecute(toolName, args, context);
            auditLogger.append({
              requestId: context.requestId,
              tool: toolName,
              caller: context.caller,
              timestamp: new Date().toISOString(),
              argsHash: hashArgs(args),
              resultStatus: "ok",
              role,
              source: context.source,
              code: "LEGACY_FALLBACK",
            });
            return {
              ok: true,
              data: legacyResult,
            };
          } catch (error) {
            const code =
              error && typeof error === "object" && "code" in error && typeof (error as { code?: unknown }).code === "string"
                ? String((error as { code?: unknown }).code)
                : "LEGACY_EXECUTION_FAILED";

            auditLogger.append({
              requestId: context.requestId,
              tool: toolName,
              caller: context.caller,
              timestamp: new Date().toISOString(),
              argsHash: hashArgs(args),
              resultStatus: "error",
              role,
              source: context.source,
              code,
            });
            return {
              ok: false,
              code,
              message: sanitizeMessageForClient(code, sanitizeMessageForClient("LEGACY_EXECUTION_FAILED")),
            };
          }
        }

        incrementCounter("unauthorized_tool_attempts", 1);
        return {
          ok: false,
          code: "UNAUTHORIZED_TOOL",
          message: sanitizeMessageForClient("UNAUTHORIZED_TOOL"),
        };
      }

      if (!definition.roles.includes(role as "supervisor" | "internal" | "admin")) {
        incrementCounter("unauthorized_tool_attempts", 1);
        return {
          ok: false,
          code: "UNAUTHORIZED_TOOL",
          message: sanitizeMessageForClient("UNAUTHORIZED_TOOL"),
        };
      }

      const argValidationIssue = validateToolArgs(definition.inputSchema, args);
      if (argValidationIssue) {
        incrementCounter("invalid_argument_rejections", 1);
        return {
          ok: false,
          code: argValidationIssue.code,
          message: sanitizeMessageForClient(argValidationIssue.code, argValidationIssue.message),
        };
      }

      if (mutationGuardEnabled && definition.mutationClass !== "read" && role === "supervisor") {
        incrementCounter("mutation_guard_blocks", 1);
        return {
          ok: false,
          code: "MUTATION_GUARD_BLOCKED",
          message: sanitizeMessageForClient("MUTATION_GUARD_BLOCKED"),
        };
      }

      if (Array.isArray(definition.workspacePathArgs) && definition.workspacePathArgs.length > 0) {
        const canonicalRoot = await getCanonicalWorkspaceRoot();
        for (const pathKey of definition.workspacePathArgs) {
          if (typeof args[pathKey] === "string" && String(args[pathKey]).trim()) {
            try {
              args[pathKey] = await assertPathInsideWorkspace(String(args[pathKey]), canonicalRoot);
            } catch {
              incrementCounter("workspace_path_blocks", 1);
              return {
                ok: false,
                code: "PATH_OUTSIDE_WORKSPACE",
                message: sanitizeMessageForClient("PATH_OUTSIDE_WORKSPACE"),
              };
            }
          }
        }
      }

      if (HIGH_RISK_MUTATION_CLASSES.has(definition.mutationClass)) {
        // Alert hook placeholder for SIEM/SOC integrations.
        try {
          options.onHighRiskToolEvent?.({
            requestId: context.requestId,
            tool: toolName,
            mutationClass: definition.mutationClass,
            role,
            source: context.source,
          });
        } catch {
          incrementCounter("high_risk_alert_failures", 1);
        }
      }

      try {
        const customHandler = supervisorHandlers[toolName];
        const result = customHandler ? await customHandler(args, context) : await runDefaultSupervisorHandler(toolName, args);

        auditLogger.append({
          requestId: context.requestId,
          tool: toolName,
          caller: context.caller,
          timestamp: new Date().toISOString(),
          argsHash: hashArgs(args),
          resultStatus: "ok",
          role,
          source: context.source,
        });

        return {
          ok: true,
          data: result,
        };
      } catch (error) {
        const code =
          error && typeof error === "object" && "code" in error && typeof (error as { code?: unknown }).code === "string"
            ? String((error as { code?: unknown }).code)
            : "SUPERVISOR_TOOL_FAILED";

        auditLogger.append({
          requestId: context.requestId,
          tool: toolName,
          caller: context.caller,
          timestamp: new Date().toISOString(),
          argsHash: hashArgs(args),
          resultStatus: "error",
          role,
          source: context.source,
          code,
        });

        return {
          ok: false,
          code,
          message: sanitizeMessageForClient(code),
        };
      }
    } catch (error) {
      const code =
        error && typeof error === "object" && "code" in error && typeof (error as { code?: unknown }).code === "string"
          ? String((error as { code?: unknown }).code)
          : "SUPERVISOR_TOOL_FAILED";
      return {
        ok: false,
        code,
        message: sanitizeMessageForClient(code),
      };
    } finally {
      releaseRatePermit(context);
    }
  }

  function getMetrics(): ExecutionRouterMetrics {
    return {
      counters: { ...counters },
      audit: auditLogger.getStats(),
    };
  }

  function getWorkloadIntegrityMetadata() {
    if (!workloadIntegrityVerifier) {
      return {
        nodeId: normalizeString(process.env.SUPERVISOR_NODE_ID) || "node-unknown",
        workloadManifestHash: "",
        workloadManifestLoaded: false,
        startupVerified: false,
        blocked: false,
        blockedReason: "",
      };
    }
    return workloadIntegrityVerifier.getActiveMetadata();
  }

  function evaluateWorkloadPeerPosture(peers: Array<Record<string, unknown>> = []) {
    if (!workloadIntegrityVerifier) {
      return {
        ok: true,
        status: "not_evaluated" as const,
        criticalMismatches: [],
        warnings: [],
        timestamp: Date.now(),
      };
    }
    return workloadIntegrityVerifier.evaluatePeerWorkloadPosture(peers);
  }

  function getWorkloadAttestationMetadata() {
    if (!workloadAttestationRuntime) {
      return {
        nodeId: normalizeString(process.env.SUPERVISOR_NODE_ID) || "node-unknown",
        trusted: false,
        blockedReason: "",
        referenceHash: "",
        lastEvidenceHash: "",
        lastVerifiedAt: 0,
        peerTrustMap: {},
      };
    }
    return getRuntimeAttestationState(workloadAttestationRuntime);
  }

  function evaluateWorkloadAttestationPeerPosture(peers: Array<Record<string, unknown>> = []) {
    if (!workloadAttestationRuntime) {
      return {
        ok: true,
        status: "not_evaluated" as const,
        criticalMismatches: [],
        warnings: [],
        timestamp: Date.now(),
      };
    }
    return workloadAttestationRuntime.evaluatePeerAttestationPosture(peers);
  }

  function generateAttestationEvidence(
    challenge: WorkloadAttestationChallenge = {},
    context: { localMetadata?: Record<string, unknown>; runtimeMeasurements?: Record<string, unknown> } = {},
  ) {
    if (!workloadAttestationRuntime) {
      return {
        ok: false,
        code: "WORKLOAD_ATTESTATION_NOT_TRUSTED",
        message: "Workload attestation runtime is not available",
        details: {},
      };
    }
    return generateAttestationEvidenceFromRuntime(workloadAttestationRuntime, challenge, context);
  }

  function verifyPeerAttestationEvidence(input: {
    peerId: string;
    evidence: unknown;
    challenge?: WorkloadAttestationChallenge;
  }): WorkloadAttestationVerificationResult {
    if (!workloadAttestationRuntime) {
      return {
        ok: false,
        code: "WORKLOAD_ATTESTATION_NOT_TRUSTED",
        message: "Workload attestation runtime is not available",
        details: {},
      };
    }
    return workloadAttestationRuntime.verifyPeerAttestationEvidence(
      normalizeString(input.peerId),
      input.evidence,
      input.challenge || {},
    );
  }

  return {
    execute,
    listTools,
    resolveRole,
    getMetrics,
    getWorkloadIntegrityMetadata,
    evaluateWorkloadPeerPosture,
    getWorkloadAttestationMetadata,
    evaluateWorkloadAttestationPeerPosture,
    generateAttestationEvidence,
    verifyPeerAttestationEvidence,
  };
}
