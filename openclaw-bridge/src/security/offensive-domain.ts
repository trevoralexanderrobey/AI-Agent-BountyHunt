import crypto from "node:crypto";
import net from "node:net";
import {
  LoadedOffensiveManifest,
  OffensiveIsolationProfile,
  OffensiveToolManifestEntry,
  OffensiveWorkloadManifest,
  loadOffensiveManifestFromDisk,
} from "./offensive-workload-manifest";

type JsonObject = Record<string, unknown>;

export interface OffensiveDomainMetrics {
  increment?: (name: string, labels?: Record<string, unknown>) => void;
  gauge?: (name: string, value: number, labels?: Record<string, unknown>) => void;
}

export interface OffensiveDomainAuditEvent {
  event: string;
  status: "ok" | "warning" | "error";
  code?: string;
  details?: Record<string, unknown>;
}

export interface OffensiveDomainRuntimeOptions {
  production?: boolean;
  nodeId?: string;
  manifestPath?: string;
  hashPath?: string;
  signaturePath?: string;
  publicKeyPath?: string;
  expectedManifestHash?: string;
  allowProductionPathOverride?: boolean;
  productionContainerMode?: boolean;
  rateLimitWindowMs?: number;
  maxPerToolPerWindow?: number;
  maxConcurrentOffensive?: number;
  maxConcurrentPerTool?: number;
  backoffBaseMs?: number;
  backoffMaxMs?: number;
  metrics?: OffensiveDomainMetrics;
  auditLog?: (event: OffensiveDomainAuditEvent) => void;
}

export interface OffensiveExecutionPlan {
  toolName: string;
  toolVersion: string;
  workloadID: string;
  containerImageDigest: string;
  offensiveManifestHash: string;
  isolationProfile: OffensiveIsolationProfile;
  isolationProfileHash: string;
  runtimeConfigHash: string;
  nonInteractive: true;
  resourceLimits: {
    cpuShares: number;
    memoryLimitMb: number;
    maxRuntimeSeconds: number;
    maxOutputBytes: number;
  };
  executionConstraints: {
    networkScope: "internal" | "external" | "target-bound";
    requiresTarget: boolean;
    allowedProtocols: string[];
    maxRuntimeSeconds: number;
    allowPrivateTargets: boolean;
    allowCidrs: boolean;
    singleTarget: boolean;
    maxThreads: number;
  };
  forcedFlags: string[];
  allowedFlags: string[];
  deniedFlags: string[];
  args: JsonObject;
  target: string;
  protocol: string;
}

export interface OffensiveDomainState {
  nodeId: string;
  trusted: boolean;
  blockedReason: string;
  manifestHash: string;
  manifestPath: string;
  lastVerifiedAt: number;
  toolCount: number;
  tools: string[];
}

export interface OffensivePrepareInput {
  tool: string;
  args: JsonObject;
  requestId: string;
  principalId: string;
}

export interface OffensivePrepareResult {
  ok: boolean;
  code: string;
  message: string;
  details: Record<string, unknown>;
  plan?: OffensiveExecutionPlan;
  leaseId?: string;
}

export interface OffensiveCompleteInput {
  leaseId: string;
  status: "success" | "blocked" | "timeout" | "error";
}

export interface OffensiveDomainRuntime {
  initialize: () => OffensivePrepareResult;
  isOffensiveTool: (tool: string) => boolean;
  prepareExecution: (input: OffensivePrepareInput) => OffensivePrepareResult;
  completeExecution: (input: OffensiveCompleteInput) => void;
  getState: () => OffensiveDomainState;
  getToolRuntimeConfigHash: (tool: string) => string;
}

interface SchemaValidationIssue {
  code: string;
  message: string;
}

interface BackoffState {
  level: number;
  untilMs: number;
}

interface LeaseRecord {
  leaseId: string;
  toolName: string;
}

const SQLMAP_DENYLIST = Object.freeze([
  "--os-shell",
  "--os-pwn",
  "--file-write",
  "--file-read",
  "--udf-inject",
  "--tamper",
  "--payload",
  "--eval",
  "--shell",
]);

const DEFAULT_RATE_LIMIT_WINDOW_MS = 60_000;
const DEFAULT_MAX_PER_TOOL_PER_WINDOW = 12;
const DEFAULT_MAX_CONCURRENT_OFFENSIVE = 8;
const DEFAULT_MAX_CONCURRENT_PER_TOOL = 3;
const DEFAULT_BACKOFF_BASE_MS = 3_000;
const DEFAULT_BACKOFF_MAX_MS = 60_000;
const CIDR_PATTERN = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;

function normalizeString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function normalizeToolName(value: unknown): string {
  return normalizeString(value).toLowerCase();
}

function normalizeRecord(value: unknown): JsonObject {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as JsonObject) : {};
}

function parsePositiveInt(value: unknown, fallback: number): number {
  const parsed = Number.parseInt(String(value ?? "").trim(), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((entry) => canonicalize(entry));
  }
  if (!value || typeof value !== "object") {
    return value;
  }
  const source = value as Record<string, unknown>;
  const ordered: Record<string, unknown> = {};
  for (const key of Object.keys(source).sort((left, right) => left.localeCompare(right))) {
    ordered[key] = canonicalize(source[key]);
  }
  return ordered;
}

function sha256HexFromObject(value: unknown): string {
  return crypto.createHash("sha256").update(JSON.stringify(canonicalize(value)), "utf8").digest("hex");
}

function makeResult(
  code: string,
  message: string,
  details: Record<string, unknown> = {},
  ok = false,
): OffensivePrepareResult {
  return {
    ok,
    code,
    message,
    details,
  };
}

function createSafeMetrics(metrics?: OffensiveDomainMetrics): Required<OffensiveDomainMetrics> {
  const source = metrics && typeof metrics === "object" ? metrics : {};
  return {
    increment: (name, labels = {}) => {
      try {
        source.increment?.(name, labels);
      } catch {
        // fail-open metrics
      }
    },
    gauge: (name, value, labels = {}) => {
      try {
        source.gauge?.(name, value, labels);
      } catch {
        // fail-open metrics
      }
    },
  };
}

function createSafeAudit(log?: (event: OffensiveDomainAuditEvent) => void): (event: OffensiveDomainAuditEvent) => void {
  return (event) => {
    try {
      log?.(event);
    } catch {
      // fail-open audit
    }
  };
}

function validateValueAgainstSchema(schemaRaw: unknown, value: unknown, fieldPath: string): SchemaValidationIssue | null {
  const schema = normalizeRecord(schemaRaw);
  const type = typeof schema.type === "string" ? schema.type : "";

  if (!type) {
    return {
      code: "OFFENSIVE_ARGUMENTS_INVALID",
      message: `${fieldPath} schema type is not declared`,
    };
  }

  if (type === "string") {
    if (typeof value !== "string") {
      return { code: "OFFENSIVE_ARGUMENTS_INVALID", message: `${fieldPath} must be a string` };
    }
    const minLength = typeof schema.minLength === "number" ? Math.max(0, schema.minLength) : undefined;
    const maxLength = typeof schema.maxLength === "number" ? Math.max(0, schema.maxLength) : undefined;
    if (typeof minLength === "number" && value.length < minLength) {
      return { code: "OFFENSIVE_ARGUMENTS_INVALID", message: `${fieldPath} must be at least ${minLength} characters` };
    }
    if (typeof maxLength === "number" && value.length > maxLength) {
      return { code: "OFFENSIVE_ARGUMENTS_INVALID", message: `${fieldPath} must be at most ${maxLength} characters` };
    }
    if (typeof schema.pattern === "string") {
      try {
        const pattern = new RegExp(schema.pattern);
        if (!pattern.test(value)) {
          return { code: "OFFENSIVE_ARGUMENTS_INVALID", message: `${fieldPath} has invalid format` };
        }
      } catch {
        return { code: "OFFENSIVE_ARGUMENTS_INVALID", message: `${fieldPath} schema pattern is invalid` };
      }
    }
    if (Array.isArray(schema.enum) && !schema.enum.includes(value)) {
      return { code: "OFFENSIVE_ARGUMENTS_INVALID", message: `${fieldPath} is not an allowed value` };
    }
    return null;
  }

  if (type === "number" || type === "integer") {
    if (typeof value !== "number" || !Number.isFinite(value)) {
      return { code: "OFFENSIVE_ARGUMENTS_INVALID", message: `${fieldPath} must be a finite number` };
    }
    if (type === "integer" && !Number.isInteger(value)) {
      return { code: "OFFENSIVE_ARGUMENTS_INVALID", message: `${fieldPath} must be an integer` };
    }
    const minimum = typeof schema.minimum === "number" ? schema.minimum : undefined;
    const maximum = typeof schema.maximum === "number" ? schema.maximum : undefined;
    if (typeof minimum === "number" && value < minimum) {
      return { code: "OFFENSIVE_ARGUMENTS_INVALID", message: `${fieldPath} must be >= ${minimum}` };
    }
    if (typeof maximum === "number" && value > maximum) {
      return { code: "OFFENSIVE_ARGUMENTS_INVALID", message: `${fieldPath} must be <= ${maximum}` };
    }
    return null;
  }

  if (type === "boolean") {
    if (typeof value !== "boolean") {
      return { code: "OFFENSIVE_ARGUMENTS_INVALID", message: `${fieldPath} must be a boolean` };
    }
    return null;
  }

  if (type === "array") {
    if (!Array.isArray(value)) {
      return { code: "OFFENSIVE_ARGUMENTS_INVALID", message: `${fieldPath} must be an array` };
    }
    const maxItems = typeof schema.maxItems === "number" ? Math.max(0, schema.maxItems) : undefined;
    if (typeof maxItems === "number" && value.length > maxItems) {
      return { code: "OFFENSIVE_ARGUMENTS_INVALID", message: `${fieldPath} must contain <= ${maxItems} items` };
    }
    if (schema.items) {
      for (let i = 0; i < value.length; i += 1) {
        const issue = validateValueAgainstSchema(schema.items, value[i], `${fieldPath}[${i}]`);
        if (issue) {
          return issue;
        }
      }
    }
    return null;
  }

  if (type === "object") {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      return { code: "OFFENSIVE_ARGUMENTS_INVALID", message: `${fieldPath} must be an object` };
    }
    const record = value as JsonObject;
    const properties = normalizeRecord(schema.properties);
    const required = Array.isArray(schema.required) ? schema.required.filter((entry) => typeof entry === "string") : [];
    for (const requiredKey of required) {
      if (!Object.prototype.hasOwnProperty.call(record, requiredKey)) {
        return { code: "OFFENSIVE_ARGUMENTS_INVALID", message: `${fieldPath}.${requiredKey} is required` };
      }
    }
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(record)) {
        if (!Object.prototype.hasOwnProperty.call(properties, key)) {
          return { code: "OFFENSIVE_ARGUMENTS_INVALID", message: `${fieldPath}.${key} is not allowed` };
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

  return { code: "OFFENSIVE_ARGUMENTS_INVALID", message: `${fieldPath} schema type '${type}' is unsupported` };
}

function hasControlCharacters(value: string): boolean {
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

function hasShellCharacters(value: string): boolean {
  return /[;&|`<>]/.test(value) || /\$\(|\)\s*\{/.test(value);
}

function scanUnsafeStringValues(value: unknown, fieldPath = "args"): SchemaValidationIssue | null {
  if (typeof value === "string") {
    if (hasControlCharacters(value)) {
      return { code: "OFFENSIVE_ARGUMENTS_INVALID", message: `${fieldPath} contains control characters` };
    }
    if (hasShellCharacters(value)) {
      return { code: "OFFENSIVE_ARGUMENTS_INVALID", message: `${fieldPath} contains shell control characters` };
    }
    return null;
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) {
      const issue = scanUnsafeStringValues(value[i], `${fieldPath}[${i}]`);
      if (issue) {
        return issue;
      }
    }
    return null;
  }
  if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value as JsonObject)) {
      const issue = scanUnsafeStringValues(child, `${fieldPath}.${key}`);
      if (issue) {
        return issue;
      }
    }
    return null;
  }
  return null;
}

function extractFlagValues(args: JsonObject): string[] {
  const output: string[] = [];
  const direct = args.flags;
  if (Array.isArray(direct)) {
    for (const entry of direct) {
      const value = normalizeString(entry);
      if (value) {
        output.push(value.toLowerCase());
      }
    }
  }
  const extraArgs = args.extraArgs;
  if (Array.isArray(extraArgs)) {
    for (const entry of extraArgs) {
      const value = normalizeString(entry);
      if (value && value.startsWith("-")) {
        output.push(value.toLowerCase());
      }
    }
  }
  return output;
}

function applyForcedFlags(args: JsonObject, forcedFlags: string[]): JsonObject {
  const nextArgs: JsonObject = { ...args };
  const existingFlags = Array.isArray(nextArgs.flags)
    ? nextArgs.flags.map((entry) => normalizeString(entry).toLowerCase()).filter(Boolean)
    : [];
  const flagSet = new Set(existingFlags);
  for (const forced of forcedFlags) {
    const normalizedForced = normalizeString(forced).toLowerCase();
    if (!normalizedForced) {
      continue;
    }
    flagSet.add(normalizedForced);
  }
  nextArgs.flags = Array.from(flagSet).sort((left, right) => left.localeCompare(right));
  return nextArgs;
}

function normalizeTarget(raw: string): {
  normalizedTarget: string;
  host: string;
  protocol: string;
  isIp: boolean;
  isCidr: boolean;
  isLoopback: boolean;
  isLocalhost: boolean;
  isPrivate: boolean;
} {
  const value = normalizeString(raw);
  let host = value;
  let protocol = "";

  if (/^https?:\/\//i.test(value)) {
    try {
      const parsed = new URL(value);
      host = normalizeString(parsed.hostname);
      protocol = normalizeString(parsed.protocol.replace(":", "")).toLowerCase();
    } catch {
      // fallthrough to raw host mode
    }
  }

  const isCidr = CIDR_PATTERN.test(host);
  const ipCandidate = isCidr ? host.split("/")[0] : host;
  const ipVersion = net.isIP(ipCandidate);
  const isIp = ipVersion !== 0;
  const isLocalhost = host.toLowerCase() === "localhost";
  const isLoopback =
    isLocalhost ||
    (ipVersion === 4 && ipCandidate.startsWith("127.")) ||
    (ipVersion === 6 && (ipCandidate === "::1" || ipCandidate.toLowerCase().startsWith("fe80:")));

  let isPrivate = false;
  if (ipVersion === 4) {
    const octets = ipCandidate.split(".").map((part) => Number.parseInt(part, 10));
    if (octets.length === 4 && octets.every((part) => Number.isFinite(part) && part >= 0 && part <= 255)) {
      if (octets[0] === 10) isPrivate = true;
      if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) isPrivate = true;
      if (octets[0] === 192 && octets[1] === 168) isPrivate = true;
    }
  }

  return {
    normalizedTarget: value,
    host: host.toLowerCase(),
    protocol,
    isIp,
    isCidr,
    isLoopback,
    isLocalhost,
    isPrivate,
  };
}

function computeExponentialBackoff(baseMs: number, maxMs: number, level: number): number {
  const exponent = Math.max(0, Math.min(level, 10));
  return Math.min(maxMs, baseMs * Math.pow(2, exponent));
}

export function createOffensiveDomainRuntime(options: OffensiveDomainRuntimeOptions = {}): OffensiveDomainRuntime {
  const production = options.production === true || normalizeString(process.env.NODE_ENV).toLowerCase() === "production";
  const nodeId = normalizeString(options.nodeId || process.env.SUPERVISOR_NODE_ID) || "node-unknown";
  const metrics = createSafeMetrics(options.metrics);
  const audit = createSafeAudit(options.auditLog);

  const rateLimitWindowMs = parsePositiveInt(options.rateLimitWindowMs || process.env.OFFENSIVE_RATE_LIMIT_WINDOW_MS, DEFAULT_RATE_LIMIT_WINDOW_MS);
  const maxPerToolPerWindow = parsePositiveInt(
    options.maxPerToolPerWindow || process.env.OFFENSIVE_MAX_PER_TOOL_PER_WINDOW,
    DEFAULT_MAX_PER_TOOL_PER_WINDOW,
  );
  const maxConcurrentOffensive = parsePositiveInt(
    options.maxConcurrentOffensive || process.env.OFFENSIVE_MAX_CONCURRENT,
    DEFAULT_MAX_CONCURRENT_OFFENSIVE,
  );
  const maxConcurrentPerTool = parsePositiveInt(
    options.maxConcurrentPerTool || process.env.OFFENSIVE_MAX_CONCURRENT_PER_TOOL,
    DEFAULT_MAX_CONCURRENT_PER_TOOL,
  );
  const backoffBaseMs = parsePositiveInt(options.backoffBaseMs || process.env.OFFENSIVE_BACKOFF_BASE_MS, DEFAULT_BACKOFF_BASE_MS);
  const backoffMaxMs = parsePositiveInt(options.backoffMaxMs || process.env.OFFENSIVE_BACKOFF_MAX_MS, DEFAULT_BACKOFF_MAX_MS);

  let loadedManifest: LoadedOffensiveManifest | null = null;
  let manifestByToolName = new Map<string, OffensiveToolManifestEntry>();
  let trusted = false;
  let blockedReason = "";
  let lastVerifiedAt = 0;

  const perToolWindowState = new Map<string, { windowStartedAt: number; count: number }>();
  const activeByTool = new Map<string, number>();
  const backoffByTool = new Map<string, BackoffState>();
  const leases = new Map<string, LeaseRecord>();
  let activeTotal = 0;

  function recordFailure(code: string, details: Record<string, unknown>): OffensivePrepareResult {
    metrics.increment("offensive.execution.block", {
      node_id: nodeId,
      reason: code,
    });
    audit({
      event: "offensive_execution_validation",
      status: "error",
      code,
      details: {
        nodeId,
        ...details,
      },
    });
    return makeResult(code, "Offensive execution validation failed", details, false);
  }

  function recordSuccess(details: Record<string, unknown>): void {
    metrics.increment("offensive.execution.allow", {
      node_id: nodeId,
    });
    audit({
      event: "offensive_execution_validation",
      status: "ok",
      code: "OFFENSIVE_VALIDATION_OK",
      details: {
        nodeId,
        ...details,
      },
    });
  }

  function resetWindow(toolName: string, now: number): { windowStartedAt: number; count: number } {
    const current = perToolWindowState.get(toolName);
    if (!current || now - current.windowStartedAt >= rateLimitWindowMs) {
      const next = {
        windowStartedAt: now,
        count: 0,
      };
      perToolWindowState.set(toolName, next);
      return next;
    }
    return current;
  }

  function resolveOffensiveEntry(tool: string): OffensiveToolManifestEntry | null {
    const toolName = normalizeToolName(tool);
    const slug = toolName.split(".")[0];
    if (!slug) {
      return null;
    }
    return manifestByToolName.get(slug) || null;
  }

  function ensureBackoff(toolName: string, now: number): OffensivePrepareResult | null {
    const backoff = backoffByTool.get(toolName);
    if (!backoff) {
      return null;
    }
    if (backoff.untilMs <= now) {
      backoffByTool.delete(toolName);
      return null;
    }
    metrics.increment("offensive.execution.backoff.active", {
      node_id: nodeId,
      tool: toolName,
    });
    return makeResult(
      "OFFENSIVE_BACKOFF_ACTIVE",
      "Offensive execution backoff is active",
      {
        toolName,
        retryAfterMs: Math.max(0, backoff.untilMs - now),
      },
      false,
    );
  }

  function applyBackoff(toolName: string): void {
    const existing = backoffByTool.get(toolName) || { level: 0, untilMs: 0 };
    const nextLevel = existing.level + 1;
    const durationMs = computeExponentialBackoff(backoffBaseMs, backoffMaxMs, nextLevel);
    backoffByTool.set(toolName, {
      level: nextLevel,
      untilMs: Date.now() + durationMs,
    });
  }

  function clearBackoff(toolName: string): void {
    backoffByTool.delete(toolName);
  }

  function buildOffensivePlan(entry: OffensiveToolManifestEntry, args: JsonObject): OffensiveExecutionPlan {
    const governedArgs = applyForcedFlags(args, entry.forcedFlags);
    const targetRaw =
      normalizeString(governedArgs.target) ||
      normalizeString(governedArgs.url) ||
      normalizeString(governedArgs.host);
    const target = normalizeString(targetRaw);
    const normalizedTarget = normalizeTarget(target);
    const protocolFromArgs = normalizeString(governedArgs.protocol).toLowerCase();
    const protocol = normalizedTarget.protocol || protocolFromArgs;

    const isolationProfileHash = sha256HexFromObject(entry.isolationProfile);
    return {
      toolName: entry.toolName,
      toolVersion: entry.toolVersion,
      workloadID: entry.workloadID,
      containerImageDigest: entry.containerImageDigest,
      offensiveManifestHash: loadedManifest ? loadedManifest.canonicalPayloadHash : "",
      isolationProfile: entry.isolationProfile,
      isolationProfileHash,
      runtimeConfigHash: entry.runtimeConfigHash,
      nonInteractive: true,
      resourceLimits: {
        cpuShares: entry.executionConstraints.resourceLimits.cpuShares,
        memoryLimitMb: entry.executionConstraints.resourceLimits.memoryLimitMb,
        maxRuntimeSeconds: entry.executionConstraints.resourceLimits.maxRuntimeSeconds,
        maxOutputBytes: entry.executionConstraints.resourceLimits.maxOutputBytes,
      },
      executionConstraints: {
        networkScope: entry.executionConstraints.networkScope,
        requiresTarget: entry.executionConstraints.requiresTarget,
        allowedProtocols: entry.executionConstraints.allowedProtocols.slice(),
        maxRuntimeSeconds: entry.executionConstraints.maxRuntimeSeconds,
        allowPrivateTargets: entry.executionConstraints.allowPrivateTargets,
        allowCidrs: entry.executionConstraints.allowCidrs,
        singleTarget: entry.executionConstraints.singleTarget,
        maxThreads: entry.executionConstraints.maxThreads,
      },
      forcedFlags: entry.forcedFlags.slice(),
      allowedFlags: entry.allowedFlags.slice(),
      deniedFlags: entry.deniedFlags.slice(),
      args: governedArgs,
      target,
      protocol,
    };
  }

  function initializeManifestState(loaded: LoadedOffensiveManifest): void {
    loadedManifest = loaded;
    manifestByToolName = new Map(
      loaded.manifest.tools.map((tool) => [normalizeToolName(tool.toolName), tool]),
    );
    trusted = true;
    blockedReason = "";
    lastVerifiedAt = Date.now();
    metrics.gauge("offensive.manifest.loaded", 1, {
      node_id: nodeId,
      offensive_manifest_hash: loaded.canonicalPayloadHash,
    });
  }

  function initialize(): OffensivePrepareResult {
    try {
      const loaded = loadOffensiveManifestFromDisk({
        production,
        manifestPath: options.manifestPath,
        hashPath: options.hashPath,
        signaturePath: options.signaturePath,
        publicKeyPath: options.publicKeyPath,
        expectedManifestHash: options.expectedManifestHash,
        allowProductionPathOverride: options.allowProductionPathOverride,
        productionContainerMode: options.productionContainerMode,
      });
      initializeManifestState(loaded);
      return makeResult(
        "OFFENSIVE_DOMAIN_TRUSTED",
        "Offensive domain initialized",
        {
          offensiveManifestHash: loaded.canonicalPayloadHash,
          toolCount: loaded.manifest.tools.length,
        },
        true,
      );
    } catch (error) {
      trusted = false;
      blockedReason =
        error && typeof error === "object" && "code" in error && typeof (error as { code?: unknown }).code === "string"
          ? String((error as { code?: unknown }).code)
          : "OFFENSIVE_DOMAIN_NOT_TRUSTED";
      const details =
        error && typeof error === "object" && "details" in error && (error as { details?: unknown }).details
          ? ((error as { details: Record<string, unknown> }).details as Record<string, unknown>)
          : {};
      return makeResult(
        "OFFENSIVE_DOMAIN_NOT_TRUSTED",
        error instanceof Error ? error.message : "Offensive domain initialization failed",
        {
          failureReason: blockedReason,
          ...details,
        },
        false,
      );
    }
  }

  function isOffensiveTool(tool: string): boolean {
    if (!trusted && !loadedManifest) {
      const firstSegment = normalizeToolName(tool).split(".")[0];
      return ["nmap", "sqlmap", "nikto", "ffuf"].includes(firstSegment);
    }
    return Boolean(resolveOffensiveEntry(tool));
  }

  function validateArgs(entry: OffensiveToolManifestEntry, args: JsonObject): SchemaValidationIssue | null {
    const schemaIssue = validateValueAgainstSchema(entry.allowedArgsSchema, args, "args");
    if (schemaIssue) {
      return schemaIssue;
    }
    const unsafeStringIssue = scanUnsafeStringValues(args, "args");
    if (unsafeStringIssue) {
      return unsafeStringIssue;
    }

    const flags = extractFlagValues(args);
    for (const forcedFlag of entry.forcedFlags) {
      const normalizedForcedFlag = normalizeString(forcedFlag).toLowerCase();
      if (normalizedForcedFlag && !flags.includes(normalizedForcedFlag)) {
        flags.push(normalizedForcedFlag);
      }
    }
    const allowedFlags = new Set(entry.allowedFlags.map((flag) => flag.toLowerCase()));
    const deniedFlags = new Set(entry.deniedFlags.map((flag) => flag.toLowerCase()));

    for (const flag of flags) {
      if (deniedFlags.has(flag)) {
        return {
          code: "OFFENSIVE_ARGUMENTS_INVALID",
          message: `Flag '${flag}' is forbidden`,
        };
      }
      if (flag.startsWith("-") && allowedFlags.size > 0 && !allowedFlags.has(flag)) {
        return {
          code: "OFFENSIVE_ARGUMENTS_INVALID",
          message: `Flag '${flag}' is not allowed`,
        };
      }
      if (entry.toolName === "sqlmap") {
        if (SQLMAP_DENYLIST.some((denied) => flag === denied || flag.startsWith(`${denied}=`))) {
          return {
            code: "OFFENSIVE_ARGUMENTS_INVALID",
            message: `SQLMap flag '${flag}' is forbidden`,
          };
        }
      }
    }

    if (entry.toolName === "sqlmap") {
      if (!flags.includes("--batch")) {
        return {
          code: "OFFENSIVE_ARGUMENTS_INVALID",
          message: "SQLMap requires --batch in non-interactive mode",
        };
      }
      const providedThreads = Number(args.threads);
      if (Number.isFinite(providedThreads) && providedThreads > entry.executionConstraints.maxThreads) {
        return {
          code: "OFFENSIVE_ARGUMENTS_INVALID",
          message: `threads must be <= ${entry.executionConstraints.maxThreads}`,
        };
      }
    }

    return null;
  }

  function validateTarget(entry: OffensiveToolManifestEntry, args: JsonObject): SchemaValidationIssue | null {
    const target =
      normalizeString(args.target) ||
      normalizeString(args.url) ||
      normalizeString(args.host);
    const normalized = normalizeTarget(target);
    const protocol = normalized.protocol || normalizeString(args.protocol).toLowerCase();
    const constraints = entry.executionConstraints;

    if (constraints.requiresTarget && !normalized.normalizedTarget) {
      return {
        code: "OFFENSIVE_TARGET_INVALID",
        message: "Target is required for this offensive tool",
      };
    }

    if (!normalized.normalizedTarget) {
      return null;
    }

    if (normalized.normalizedTarget === "*" || normalized.normalizedTarget.includes("*")) {
      return {
        code: "OFFENSIVE_TARGET_INVALID",
        message: "Wildcard targets are forbidden",
      };
    }
    if (constraints.singleTarget && /[,\s]/.test(normalized.normalizedTarget)) {
      return {
        code: "OFFENSIVE_TARGET_INVALID",
        message: "Single target mode forbids target lists",
      };
    }
    if (normalized.isCidr && !constraints.allowCidrs) {
      return {
        code: "OFFENSIVE_TARGET_INVALID",
        message: "CIDR targets are not allowed",
      };
    }
    if (normalized.isLocalhost || normalized.isLoopback) {
      return {
        code: "OFFENSIVE_TARGET_INVALID",
        message: "localhost/loopback targets are forbidden",
      };
    }
    if (normalized.isPrivate && !constraints.allowPrivateTargets) {
      return {
        code: "OFFENSIVE_TARGET_INVALID",
        message: "Private RFC1918 targets are forbidden",
      };
    }
    if (constraints.allowedProtocols.length > 0 && protocol && !constraints.allowedProtocols.includes(protocol)) {
      return {
        code: "OFFENSIVE_PROTOCOL_NOT_ALLOWED",
        message: `Protocol '${protocol}' is not allowed`,
      };
    }
    if (constraints.networkScope === "internal" && !normalized.isPrivate) {
      return {
        code: "OFFENSIVE_TARGET_INVALID",
        message: "Internal network scope requires private/internal targets",
      };
    }
    return null;
  }

  function prepareExecution(input: OffensivePrepareInput): OffensivePrepareResult {
    if (!loadedManifest) {
      const startup = initialize();
      if (!startup.ok) {
        return makeResult(
          "OFFENSIVE_DOMAIN_NOT_TRUSTED",
          "Offensive domain is not trusted",
          {
            failureReason: blockedReason || startup.details.failureReason || startup.code,
          },
          false,
        );
      }
    }

    if (!trusted || !loadedManifest) {
      return makeResult(
        "OFFENSIVE_DOMAIN_NOT_TRUSTED",
        "Offensive domain is not trusted",
        {
          failureReason: blockedReason || "OFFENSIVE_DOMAIN_NOT_TRUSTED",
        },
        false,
      );
    }

    const entry = resolveOffensiveEntry(input.tool);
    if (!entry) {
      return recordFailure("UNREGISTERED_OFFENSIVE_TOOL", {
        tool: normalizeToolName(input.tool),
      });
    }

    const toolName = normalizeToolName(entry.toolName);
    const now = Date.now();

    const backoff = ensureBackoff(toolName, now);
    if (backoff) {
      return backoff;
    }

    const windowState = resetWindow(toolName, now);
    if (windowState.count >= maxPerToolPerWindow) {
      applyBackoff(toolName);
      return recordFailure("OFFENSIVE_RATE_LIMIT_EXCEEDED", {
        toolName,
        maxPerToolPerWindow,
        rateLimitWindowMs,
      });
    }

    const activeForTool = activeByTool.get(toolName) || 0;
    if (activeTotal >= maxConcurrentOffensive || activeForTool >= maxConcurrentPerTool) {
      applyBackoff(toolName);
      return recordFailure("OFFENSIVE_CONCURRENCY_EXCEEDED", {
        toolName,
        maxConcurrentOffensive,
        maxConcurrentPerTool,
      });
    }

    const args = normalizeRecord(input.args);
    const argIssue = validateArgs(entry, args);
    if (argIssue) {
      return recordFailure(argIssue.code, {
        toolName,
        reason: argIssue.message,
      });
    }

    const targetIssue = validateTarget(entry, args);
    if (targetIssue) {
      return recordFailure(targetIssue.code, {
        toolName,
        reason: targetIssue.message,
      });
    }

    const plan = buildOffensivePlan(entry, args);
    const leaseId = typeof crypto.randomUUID === "function" ? crypto.randomUUID() : crypto.randomBytes(16).toString("hex");
    leases.set(leaseId, {
      leaseId,
      toolName,
    });
    activeTotal += 1;
    activeByTool.set(toolName, activeForTool + 1);
    windowState.count += 1;
    clearBackoff(toolName);
    recordSuccess({
      toolName,
      requestId: normalizeString(input.requestId),
      principalId: normalizeString(input.principalId) || "anonymous",
      offensiveManifestHash: loadedManifest.canonicalPayloadHash,
    });

    return {
      ok: true,
      code: "OFFENSIVE_EXECUTION_ALLOWED",
      message: "Offensive execution allowed",
      details: {
        toolName,
        leaseId,
      },
      plan,
      leaseId,
    };
  }

  function completeExecution(input: OffensiveCompleteInput): void {
    const leaseId = normalizeString(input.leaseId);
    if (!leaseId) {
      return;
    }
    const lease = leases.get(leaseId);
    if (!lease) {
      return;
    }
    leases.delete(leaseId);
    activeTotal = Math.max(0, activeTotal - 1);
    const currentToolCount = activeByTool.get(lease.toolName) || 0;
    if (currentToolCount <= 1) {
      activeByTool.delete(lease.toolName);
    } else {
      activeByTool.set(lease.toolName, currentToolCount - 1);
    }

    if (input.status === "timeout" || input.status === "blocked") {
      applyBackoff(lease.toolName);
      metrics.increment("offensive.execution.backoff.applied", {
        node_id: nodeId,
        tool: lease.toolName,
        status: input.status,
      });
    } else if (input.status === "success") {
      clearBackoff(lease.toolName);
    }
  }

  function getState(): OffensiveDomainState {
    return {
      nodeId,
      trusted,
      blockedReason,
      manifestHash: loadedManifest?.canonicalPayloadHash || "",
      manifestPath: loadedManifest?.manifestPath || "",
      lastVerifiedAt,
      toolCount: manifestByToolName.size,
      tools: Array.from(manifestByToolName.keys()).sort((left, right) => left.localeCompare(right)),
    };
  }

  function getToolRuntimeConfigHash(tool: string): string {
    const entry = resolveOffensiveEntry(tool);
    if (!entry) {
      return "";
    }
    return normalizeString(entry.runtimeConfigHash).toLowerCase();
  }

  return {
    initialize,
    isOffensiveTool,
    prepareExecution,
    completeExecution,
    getState,
    getToolRuntimeConfigHash,
  };
}
