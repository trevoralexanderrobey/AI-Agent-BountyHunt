import crypto, { KeyObject } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const REQUIRED_PROVENANCE_KEYS = Object.freeze([
  "provenanceVersion",
  "gitCommitSha",
  "repository",
  "buildTimestamp",
  "workloadManifestHash",
  "executionPolicyHash",
  "secretManifestHash",
  "attestationReferenceHash",
  "containerImageDigests",
  "dependencyLockHash",
  "nodeVersion",
  "buildEnvironmentFingerprint",
  "signatureAlgorithm",
  "provenanceSignature",
  "provenanceHash",
]);

const DETACHED_PAYLOAD_KEYS = Object.freeze(
  REQUIRED_PROVENANCE_KEYS.filter((key) => key !== "provenanceSignature" && key !== "provenanceHash"),
);

const DEFAULT_REVERIFY_TTL_MS = 120_000;
const MAX_REVERIFY_TTL_MS = 300_000;
const SHA256_HEX_PATTERN = /^[a-f0-9]{64}$/;
const SHA256_DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;

export interface WorkloadProvenanceDocument {
  provenanceVersion: number;
  gitCommitSha: string;
  repository: string;
  buildTimestamp: string;
  workloadManifestHash: string;
  executionPolicyHash: string;
  secretManifestHash: string;
  attestationReferenceHash: string;
  containerImageDigests: Record<string, string>;
  dependencyLockHash: string;
  nodeVersion: string;
  buildEnvironmentFingerprint: string;
  signatureAlgorithm: "ed25519";
  provenanceSignature: string;
  provenanceHash: string;
}

export interface WorkloadProvenanceValidation {
  valid: boolean;
  errors: string[];
}

export interface WorkloadProvenanceMetrics {
  increment?: (name: string, labels?: Record<string, unknown>) => void;
  gauge?: (name: string, value: number, labels?: Record<string, unknown>) => void;
}

export interface WorkloadProvenanceAuditEvent {
  event: string;
  status: "ok" | "warning" | "error";
  code?: string;
  details?: Record<string, unknown>;
}

export interface WorkloadProvenanceVerificationResult {
  ok: boolean;
  code: string;
  message: string;
  details: Record<string, unknown>;
}

export interface WorkloadProvenanceState {
  nodeId: string;
  trusted: boolean;
  blockedReason: string;
  provenanceHash: string;
  gitCommitSha: string;
  lastVerifiedAt: number;
  ttlMs: number;
  stale: boolean;
}

export interface WorkloadProvenanceRuntimeOptions {
  production?: boolean;
  nodeId?: string;
  provenancePath?: string;
  provenanceHashPath?: string;
  publicKeyPath?: string;
  publicKey?: string;
  dependencyLockPath?: string;
  expectedProvenanceHash?: string;
  allowProductionPathOverride?: boolean;
  reverifyTtlMs?: number;
  productionContainerMode?: boolean;
  metrics?: WorkloadProvenanceMetrics;
  auditLog?: (event: WorkloadProvenanceAuditEvent) => void;
}

export interface VerifyWorkloadProvenanceInput {
  workloadID: string;
  runtimeDigest?: string;
  localMetadata?: Record<string, unknown>;
}

export interface LoadedBuildProvenance {
  provenance: WorkloadProvenanceDocument;
  provenancePath: string;
  hashPath: string;
  publicKeyPath: string;
  dependencyLockPath: string;
  canonicalPayloadBytes: Buffer;
  canonicalPayloadHash: string;
}

export interface WorkloadProvenanceRuntime {
  initializeProvenance: () => WorkloadProvenanceVerificationResult;
  verifyExecution: (input: VerifyWorkloadProvenanceInput) => Promise<WorkloadProvenanceVerificationResult>;
  getProvenanceState: () => WorkloadProvenanceState;
  isTrusted: () => boolean;
}

interface ResolvedProvenancePaths {
  provenancePath: string;
  hashPath: string;
  publicKeyPath: string;
  dependencyLockPath: string;
  securityDirectory: string;
  configuredProvenancePath: string;
  configuredHashPath: string;
  configuredKeyPath: string;
}

interface ProductionFilesystemOptions {
  productionContainerMode: boolean;
  securityDirectory: string;
}

function normalizeString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function normalizeHash(value: unknown): string {
  return normalizeString(value).toLowerCase();
}

function normalizeToolKey(value: unknown): string {
  return normalizeString(value).toLowerCase();
}

function parseBoolean(value: unknown, fallback = false): boolean {
  if (typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    return value !== 0;
  }
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (normalized === "true" || normalized === "1" || normalized === "yes") {
      return true;
    }
    if (normalized === "false" || normalized === "0" || normalized === "no") {
      return false;
    }
  }
  return fallback;
}

function parsePositiveInt(value: unknown, fallback: number): number {
  const parsed = Number.parseInt(String(value ?? "").trim(), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((entry) => canonicalize(entry));
  }
  if (!isPlainObject(value)) {
    return value;
  }

  const ordered: Record<string, unknown> = {};
  for (const key of Object.keys(value).sort((left, right) => left.localeCompare(right))) {
    ordered[key] = canonicalize(value[key]);
  }
  return ordered;
}

function serializeCanonical(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function sha256HexFromBuffer(buffer: Buffer): string {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function sha256HexFromString(value: string): string {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function computeFileSha256(filePath: string): string {
  return sha256HexFromBuffer(fs.readFileSync(filePath));
}

function normalizeDigest(value: unknown): string {
  const source = normalizeString(value).toLowerCase();
  if (!source) {
    return "";
  }
  if (SHA256_DIGEST_PATTERN.test(source)) {
    return source;
  }
  const anchored = source.match(/@sha256:([a-f0-9]{64})/);
  if (anchored && anchored[1]) {
    return `sha256:${anchored[1]}`;
  }
  return "";
}

function decodeMountComponent(value: string): string {
  return value.replace(/\\([0-7]{3})/g, (_, octal: string) => String.fromCharCode(Number.parseInt(octal, 8)));
}

function makeResult(
  code: string,
  message: string,
  details: Record<string, unknown> = {},
  ok = false,
): WorkloadProvenanceVerificationResult {
  return {
    ok,
    code,
    message,
    details,
  };
}

function makeError(code: string, message: string, details: Record<string, unknown> = {}): Error {
  const error = new Error(message) as Error & { code?: string; details?: unknown };
  error.code = code;
  error.details = details;
  return error;
}

function createSafeMetrics(metrics?: WorkloadProvenanceMetrics): Required<WorkloadProvenanceMetrics> {
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

function createSafeAudit(log?: (event: WorkloadProvenanceAuditEvent) => void): (event: WorkloadProvenanceAuditEvent) => void {
  return (event) => {
    try {
      log?.(event);
    } catch {
      // fail-open audit
    }
  };
}

function resolveProjectRootFromCurrentDir(): string {
  const srcRoot = path.resolve(__dirname, "..", "..");
  const srcLockfile = path.resolve(srcRoot, "package-lock.json");
  const srcSecurityDir = path.resolve(srcRoot, "security");
  if (fs.existsSync(srcLockfile) && fs.existsSync(srcSecurityDir)) {
    return srcRoot;
  }
  return path.resolve(__dirname, "..", "..", "..");
}

export function resolveDefaultBuildProvenancePath(): string {
  return path.resolve(resolveProjectRootFromCurrentDir(), "security", "build-provenance.json");
}

export function resolveDefaultBuildProvenanceHashPath(): string {
  return path.resolve(resolveProjectRootFromCurrentDir(), "security", "build-provenance.hash");
}

export function resolveDefaultBuildProvenancePublicKeyPath(): string {
  return path.resolve(resolveProjectRootFromCurrentDir(), "security", "build-provenance.pub");
}

export function resolveDefaultDependencyLockPath(): string {
  return path.resolve(resolveProjectRootFromCurrentDir(), "package-lock.json");
}

function parseProductionContainerMode(options: WorkloadProvenanceRuntimeOptions, production: boolean): boolean {
  if (typeof options.productionContainerMode === "boolean") {
    return options.productionContainerMode;
  }
  const executionMode = normalizeString(process.env.TOOL_EXECUTION_MODE).toLowerCase();
  const runtimeEnabled = parseBoolean(process.env.CONTAINER_RUNTIME_ENABLED, false);
  return production && (executionMode === "container" || runtimeEnabled);
}

function parseHashFileValue(rawHashValue: string): string {
  const trimmed = normalizeString(rawHashValue).toLowerCase();
  if (!trimmed) {
    return "";
  }

  const direct = trimmed.startsWith("sha256:") ? trimmed.slice("sha256:".length) : trimmed;
  const firstToken = normalizeString(direct.split(/\s+/)[0]);
  return SHA256_HEX_PATTERN.test(firstToken) ? firstToken : "";
}

function assertNoSymlinkSegments(targetPath: string, code: string): void {
  const resolved = path.resolve(targetPath);
  const parsed = path.parse(resolved);
  const relative = path.relative(parsed.root, resolved);
  const segments = relative.split(path.sep).filter(Boolean);

  let cursor = parsed.root;
  for (const segment of segments) {
    cursor = path.join(cursor, segment);
    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(cursor);
    } catch (error) {
      throw makeError(code, "Provenance path segment metadata could not be loaded", {
        path: cursor,
        reason: error instanceof Error ? error.message : String(error),
      });
    }

    if (stat.isSymbolicLink()) {
      throw makeError(code, "Symlink paths are forbidden for provenance artifacts in production", {
        path: cursor,
      });
    }
  }
}

function assertResolvedPathEqualsRealPath(targetPath: string, code: string): void {
  const resolvedPath = path.resolve(targetPath);
  let realPath = "";
  try {
    realPath = fs.realpathSync(targetPath);
  } catch (error) {
    throw makeError(code, "Provenance artifact realpath could not be resolved", {
      path: resolvedPath,
      reason: error instanceof Error ? error.message : String(error),
    });
  }

  if (resolvedPath !== realPath) {
    throw makeError(code, "Provenance artifact must not resolve through symlink indirection", {
      resolvedPath,
      realPath,
    });
  }
}

function assertOwnerUid(targetPath: string, code: string): void {
  if (typeof process.getuid !== "function") {
    throw makeError(code, "Runtime UID introspection is unavailable in this environment", {
      path: targetPath,
    });
  }

  const expectedUid = process.getuid();
  const stat = fs.lstatSync(targetPath);
  if (stat.uid !== expectedUid) {
    throw makeError(code, "Provenance artifact owner UID does not match runtime UID", {
      path: targetPath,
      expectedUid,
      actualUid: stat.uid,
    });
  }
}

function assertReadOnlyFileMode(targetPath: string, missingCode: string, writableCode: string): void {
  if (!fs.existsSync(targetPath)) {
    throw makeError(missingCode, "Provenance artifact is missing", {
      path: targetPath,
    });
  }

  const stat = fs.lstatSync(targetPath);
  if (!stat.isFile()) {
    throw makeError(missingCode, "Provenance artifact must be a regular file", {
      path: targetPath,
    });
  }

  if ((stat.mode & 0o022) !== 0) {
    throw makeError(writableCode, "Provenance artifact must not be group/world writable in production", {
      path: targetPath,
      mode: stat.mode & 0o777,
    });
  }
}

function assertNonWritableParentDirectories(targetPath: string, securityDirectory: string, code: string): void {
  const resolvedTarget = path.resolve(targetPath);
  const resolvedSecurityDir = path.resolve(securityDirectory);

  let cursor = path.dirname(resolvedTarget);
  while (true) {
    const stat = fs.lstatSync(cursor);
    if (stat.isSymbolicLink()) {
      throw makeError(code, "Provenance parent directory must not be symlinked in production", {
        path: cursor,
      });
    }
    if (!stat.isDirectory()) {
      throw makeError(code, "Provenance parent path must be a directory", {
        path: cursor,
      });
    }
    if ((stat.mode & 0o022) !== 0) {
      throw makeError(code, "Provenance parent directory must not be group/world writable in production", {
        path: cursor,
        mode: stat.mode & 0o777,
      });
    }

    if (cursor === resolvedSecurityDir) {
      break;
    }

    const next = path.dirname(cursor);
    if (next === cursor) {
      break;
    }
    cursor = next;
  }
}

function isPathWithin(parentPath: string, childPath: string): boolean {
  if (parentPath === "/") {
    return true;
  }
  return childPath === parentPath || childPath.startsWith(`${parentPath}${path.sep}`);
}

function assertReadOnlyMount(targetDirectory: string, code: string): void {
  let rawMountInfo = "";
  try {
    rawMountInfo = fs.readFileSync("/proc/self/mountinfo", "utf8");
  } catch (error) {
    throw makeError(code, "Unable to verify read-only mount for provenance directory", {
      targetDirectory,
      reason: error instanceof Error ? error.message : String(error),
    });
  }

  const lines = rawMountInfo
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  let selectedMountPoint = "";
  let selectedMountOptions: string[] = [];

  const resolvedTargetDirectory = path.resolve(targetDirectory);

  for (const line of lines) {
    const fields = line.split(" ");
    if (fields.length < 7) {
      continue;
    }

    const mountPointRaw = fields[4];
    const mountOptionsRaw = fields[5];
    if (!mountPointRaw || !mountOptionsRaw) {
      continue;
    }

    const mountPoint = path.resolve(decodeMountComponent(mountPointRaw));
    if (!isPathWithin(mountPoint, resolvedTargetDirectory)) {
      continue;
    }

    if (mountPoint.length > selectedMountPoint.length) {
      selectedMountPoint = mountPoint;
      selectedMountOptions = mountOptionsRaw.split(",").map((entry) => entry.trim()).filter(Boolean);
    }
  }

  if (!selectedMountPoint) {
    throw makeError(code, "Unable to determine mount point for provenance directory", {
      targetDirectory: resolvedTargetDirectory,
    });
  }

  if (!selectedMountOptions.includes("ro")) {
    throw makeError(code, "Provenance directory mount must be read-only in production container mode", {
      targetDirectory: resolvedTargetDirectory,
      mountPoint: selectedMountPoint,
      mountOptions: selectedMountOptions,
    });
  }
}

function resolveProvenancePaths(options: WorkloadProvenanceRuntimeOptions, production: boolean): ResolvedProvenancePaths {
  const defaultProvenancePath = resolveDefaultBuildProvenancePath();
  const defaultHashPath = resolveDefaultBuildProvenanceHashPath();
  const defaultPublicKeyPath = resolveDefaultBuildProvenancePublicKeyPath();

  const configuredProvenancePath = normalizeString(options.provenancePath || process.env.WORKLOAD_PROVENANCE_PATH);
  const configuredHashPath = normalizeString(options.provenanceHashPath || process.env.WORKLOAD_PROVENANCE_HASH_PATH);
  const configuredKeyPath = normalizeString(options.publicKeyPath || process.env.WORKLOAD_PROVENANCE_PUBLIC_KEY_PATH);

  const provenancePath = configuredProvenancePath ? path.resolve(configuredProvenancePath) : defaultProvenancePath;
  const hashPath = configuredHashPath ? path.resolve(configuredHashPath) : defaultHashPath;
  const publicKeyPath = configuredKeyPath ? path.resolve(configuredKeyPath) : defaultPublicKeyPath;
  const dependencyLockPath = path.resolve(
    normalizeString(options.dependencyLockPath || process.env.WORKLOAD_PROVENANCE_LOCK_PATH) ||
      resolveDefaultDependencyLockPath(),
  );

  if (production && options.allowProductionPathOverride !== true) {
    if (configuredProvenancePath && provenancePath !== path.resolve(defaultProvenancePath)) {
      throw makeError("WORKLOAD_PROVENANCE_PATH_OVERRIDE_FORBIDDEN", "Build provenance path override is forbidden in production", {
        configuredPath: provenancePath,
        requiredPath: path.resolve(defaultProvenancePath),
      });
    }
    if (configuredHashPath && hashPath !== path.resolve(defaultHashPath)) {
      throw makeError(
        "WORKLOAD_PROVENANCE_HASH_PATH_OVERRIDE_FORBIDDEN",
        "Build provenance hash path override is forbidden in production",
        {
          configuredPath: hashPath,
          requiredPath: path.resolve(defaultHashPath),
        },
      );
    }
    if (configuredKeyPath && publicKeyPath !== path.resolve(defaultPublicKeyPath)) {
      throw makeError(
        "WORKLOAD_PROVENANCE_KEY_PATH_OVERRIDE_FORBIDDEN",
        "Build provenance public key path override is forbidden in production",
        {
          configuredPath: publicKeyPath,
          requiredPath: path.resolve(defaultPublicKeyPath),
        },
      );
    }
  }

  return {
    provenancePath,
    hashPath,
    publicKeyPath,
    dependencyLockPath,
    securityDirectory: path.dirname(defaultProvenancePath),
    configuredProvenancePath,
    configuredHashPath,
    configuredKeyPath,
  };
}

function assertProductionFilesystemIntegrity(paths: ResolvedProvenancePaths, options: ProductionFilesystemOptions): void {
  const provenancePath = path.resolve(paths.provenancePath);
  const hashPath = path.resolve(paths.hashPath);
  const publicKeyPath = path.resolve(paths.publicKeyPath);

  const checks: Array<{
    filePath: string;
    missingCode: string;
  }> = [
    { filePath: provenancePath, missingCode: "WORKLOAD_PROVENANCE_MISSING" },
    { filePath: hashPath, missingCode: "WORKLOAD_PROVENANCE_HASH_MISSING" },
    { filePath: publicKeyPath, missingCode: "WORKLOAD_PROVENANCE_KEY_MISSING" },
  ];

  for (const check of checks) {
    assertNoSymlinkSegments(check.filePath, "WORKLOAD_PROVENANCE_SYMLINK_FORBIDDEN");
    assertResolvedPathEqualsRealPath(check.filePath, "WORKLOAD_PROVENANCE_SYMLINK_FORBIDDEN");
    assertReadOnlyFileMode(check.filePath, check.missingCode, "WORKLOAD_PROVENANCE_WRITABLE_IN_PRODUCTION");
    assertOwnerUid(check.filePath, "WORKLOAD_PROVENANCE_OWNER_INVALID");
    assertNonWritableParentDirectories(check.filePath, options.securityDirectory, "WORKLOAD_PROVENANCE_PARENT_DIR_WRITABLE");
  }

  if (options.productionContainerMode) {
    assertReadOnlyMount(path.dirname(provenancePath), "WORKLOAD_PROVENANCE_MOUNT_NOT_READONLY");
  }
}

function readJsonFile(targetPath: string, missingCode: string, schemaCode: string): unknown {
  if (!fs.existsSync(targetPath)) {
    throw makeError(missingCode, "Required provenance artifact is missing", {
      path: targetPath,
    });
  }

  try {
    return JSON.parse(fs.readFileSync(targetPath, "utf8"));
  } catch (error) {
    throw makeError(schemaCode, "Build provenance JSON is invalid", {
      path: targetPath,
      reason: error instanceof Error ? error.message : String(error),
    });
  }
}

function decodeSignature(signature: string): Buffer {
  try {
    const buffer = Buffer.from(signature, "base64");
    if (buffer.length === 0) {
      throw new Error("empty signature");
    }
    return buffer;
  } catch (error) {
    throw makeError("WORKLOAD_PROVENANCE_SIGNATURE_INVALID", "Build provenance signature is not valid base64", {
      reason: error instanceof Error ? error.message : String(error),
    });
  }
}

function buildPublicKeyFromString(source: string): KeyObject {
  const trimmed = normalizeString(source);
  if (!trimmed) {
    throw makeError("WORKLOAD_PROVENANCE_KEY_MISSING", "Build provenance public key source is empty", {});
  }

  try {
    if (trimmed.includes("BEGIN PUBLIC KEY")) {
      return crypto.createPublicKey(trimmed);
    }

    const der = Buffer.from(trimmed, "base64");
    return crypto.createPublicKey({
      key: der,
      format: "der",
      type: "spki",
    });
  } catch (error) {
    throw makeError("WORKLOAD_PROVENANCE_KEY_INVALID", "Unable to parse build provenance public key", {
      reason: error instanceof Error ? error.message : String(error),
    });
  }
}

function loadPublicVerificationKey(paths: ResolvedProvenancePaths, options: WorkloadProvenanceRuntimeOptions, production: boolean): KeyObject {
  const inlinePublicKey = normalizeString(options.publicKey || process.env.WORKLOAD_PROVENANCE_PUBLIC_KEY);
  if (production && inlinePublicKey) {
    throw makeError("WORKLOAD_PROVENANCE_KEY_OVERRIDE_FORBIDDEN", "Inline build provenance public key override is forbidden in production", {});
  }

  if (inlinePublicKey) {
    return buildPublicKeyFromString(inlinePublicKey);
  }

  if (!fs.existsSync(paths.publicKeyPath)) {
    throw makeError("WORKLOAD_PROVENANCE_KEY_MISSING", "Build provenance public key file is missing", {
      path: paths.publicKeyPath,
    });
  }

  const raw = fs.readFileSync(paths.publicKeyPath, "utf8");
  return buildPublicKeyFromString(raw);
}

export function validateBuildProvenance(input: unknown): WorkloadProvenanceValidation {
  const errors: string[] = [];

  if (!isPlainObject(input)) {
    return {
      valid: false,
      errors: ["build provenance must be an object"],
    };
  }

  for (const key of REQUIRED_PROVENANCE_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(input, key)) {
      errors.push(`missing required field '${key}'`);
    }
  }

  const unknownKeys = Object.keys(input).filter((key) => !REQUIRED_PROVENANCE_KEYS.includes(key));
  if (unknownKeys.length > 0) {
    errors.push(`unknown fields: ${unknownKeys.join(",")}`);
  }

  const version = Number(input.provenanceVersion);
  if (!Number.isInteger(version) || version <= 0) {
    errors.push("provenanceVersion must be a positive integer");
  }

  const gitCommitSha = normalizeHash(input.gitCommitSha);
  if (!/^[a-f0-9]{7,64}$/.test(gitCommitSha)) {
    errors.push("gitCommitSha must be a lowercase hex string (7-64 chars)");
  }

  const repository = normalizeString(input.repository);
  if (!repository) {
    errors.push("repository must be a non-empty string");
  }

  const buildTimestamp = normalizeString(input.buildTimestamp);
  if (!buildTimestamp || !Number.isFinite(Date.parse(buildTimestamp))) {
    errors.push("buildTimestamp must be a valid ISO-8601 timestamp");
  }

  const hashFields: Array<keyof WorkloadProvenanceDocument> = [
    "workloadManifestHash",
    "executionPolicyHash",
    "secretManifestHash",
    "attestationReferenceHash",
    "dependencyLockHash",
    "provenanceHash",
  ];

  for (const hashField of hashFields) {
    const value = normalizeHash(input[hashField]);
    if (!SHA256_HEX_PATTERN.test(value)) {
      errors.push(`${hashField} must be a 64-character lowercase hex string`);
    }
  }

  if (normalizeString(input.signatureAlgorithm).toLowerCase() !== "ed25519") {
    errors.push("signatureAlgorithm must equal 'ed25519'");
  }

  const signature = normalizeString(input.provenanceSignature);
  if (!signature) {
    errors.push("provenanceSignature must be a non-empty base64 string");
  } else {
    try {
      const decoded = Buffer.from(signature, "base64");
      if (decoded.length === 0) {
        errors.push("provenanceSignature must decode to non-empty bytes");
      }
    } catch {
      errors.push("provenanceSignature must be valid base64");
    }
  }

  const nodeVersion = normalizeString(input.nodeVersion);
  if (!nodeVersion) {
    errors.push("nodeVersion must be a non-empty string");
  }

  const environmentFingerprint = normalizeString(input.buildEnvironmentFingerprint);
  if (!environmentFingerprint) {
    errors.push("buildEnvironmentFingerprint must be a non-empty string");
  }

  const digestMapRaw = input.containerImageDigests;
  if (!isPlainObject(digestMapRaw)) {
    errors.push("containerImageDigests must be an object");
  } else {
    const digestEntries = Object.entries(digestMapRaw);
    if (digestEntries.length === 0) {
      errors.push("containerImageDigests must contain at least one workload digest");
    }

    for (const [rawKey, rawDigest] of digestEntries) {
      const key = normalizeToolKey(rawKey);
      if (!key) {
        errors.push("containerImageDigests contains an empty workload key");
      }
      const digest = normalizeDigest(rawDigest);
      if (!digest || !SHA256_DIGEST_PATTERN.test(digest)) {
        errors.push(`containerImageDigests.${rawKey} must match sha256:<64hex>`);
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

export function getCanonicalBuildProvenance(input: unknown): WorkloadProvenanceDocument {
  const validation = validateBuildProvenance(input);
  if (!validation.valid) {
    throw makeError("WORKLOAD_PROVENANCE_SCHEMA_INVALID", "Build provenance schema validation failed", {
      errors: validation.errors,
    });
  }

  const source = input as Record<string, unknown>;
  const digestMapSource = source.containerImageDigests as Record<string, unknown>;
  const normalizedDigestMap: Record<string, string> = {};

  for (const key of Object.keys(digestMapSource).sort((left, right) => left.localeCompare(right))) {
    const normalizedKey = normalizeToolKey(key);
    if (!normalizedKey) {
      continue;
    }
    normalizedDigestMap[normalizedKey] = normalizeDigest(digestMapSource[key]);
  }

  const buildTimestamp = new Date(normalizeString(source.buildTimestamp)).toISOString();

  return canonicalize({
    provenanceVersion: Number(source.provenanceVersion),
    gitCommitSha: normalizeHash(source.gitCommitSha),
    repository: normalizeString(source.repository),
    buildTimestamp,
    workloadManifestHash: normalizeHash(source.workloadManifestHash),
    executionPolicyHash: normalizeHash(source.executionPolicyHash),
    secretManifestHash: normalizeHash(source.secretManifestHash),
    attestationReferenceHash: normalizeHash(source.attestationReferenceHash),
    containerImageDigests: normalizedDigestMap,
    dependencyLockHash: normalizeHash(source.dependencyLockHash),
    nodeVersion: normalizeString(source.nodeVersion),
    buildEnvironmentFingerprint: normalizeString(source.buildEnvironmentFingerprint),
    signatureAlgorithm: "ed25519",
    provenanceSignature: normalizeString(source.provenanceSignature),
    provenanceHash: normalizeHash(source.provenanceHash),
  }) as WorkloadProvenanceDocument;
}

export function getDetachedProvenancePayload(provenance: WorkloadProvenanceDocument): Record<string, unknown> {
  const payload: Record<string, unknown> = {};
  const source = provenance as unknown as Record<string, unknown>;
  for (const key of DETACHED_PAYLOAD_KEYS) {
    payload[key] = source[key];
  }
  return payload;
}

export function computeDetachedProvenancePayloadBytes(provenance: WorkloadProvenanceDocument): Buffer {
  return Buffer.from(serializeCanonical(getDetachedProvenancePayload(provenance)), "utf8");
}

export function computeBuildProvenanceHash(input: unknown): string {
  const canonical = getCanonicalBuildProvenance(input);
  return sha256HexFromBuffer(computeDetachedProvenancePayloadBytes(canonical));
}

export function verifyBuildProvenance(
  options: WorkloadProvenanceRuntimeOptions = {},
): WorkloadProvenanceVerificationResult {
  try {
    const loaded = loadBuildProvenanceFromDisk(options);
    return makeResult(
      "WORKLOAD_PROVENANCE_VERIFIED",
      "Build provenance verification succeeded",
      {
        provenancePath: loaded.provenancePath,
        hashPath: loaded.hashPath,
        publicKeyPath: loaded.publicKeyPath,
        dependencyLockPath: loaded.dependencyLockPath,
        provenanceHash: loaded.canonicalPayloadHash,
        gitCommitSha: loaded.provenance.gitCommitSha,
      },
      true,
    );
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error ? String((error as { code?: unknown }).code || "") : "";
    const details =
      error && typeof error === "object" && "details" in error && isPlainObject((error as { details?: unknown }).details)
        ? ((error as { details: Record<string, unknown> }).details as Record<string, unknown>)
        : {};
    return makeResult(
      code || "WORKLOAD_PROVENANCE_NOT_TRUSTED",
      error instanceof Error ? error.message : "Build provenance verification failed",
      details,
      false,
    );
  }
}

export function loadBuildProvenanceFromDisk(options: WorkloadProvenanceRuntimeOptions = {}): LoadedBuildProvenance {
  const production = options.production === true || normalizeString(process.env.NODE_ENV).toLowerCase() === "production";
  const paths = resolveProvenancePaths(options, production);

  if (production) {
    assertProductionFilesystemIntegrity(paths, {
      productionContainerMode: parseProductionContainerMode(options, production),
      securityDirectory: paths.securityDirectory,
    });
  }

  const rawDocument = readJsonFile(
    paths.provenancePath,
    "WORKLOAD_PROVENANCE_MISSING",
    "WORKLOAD_PROVENANCE_SCHEMA_INVALID",
  );

  const canonical = getCanonicalBuildProvenance(rawDocument);
  const payloadBytes = computeDetachedProvenancePayloadBytes(canonical);
  const payloadHash = sha256HexFromBuffer(payloadBytes);

  const hashFileRaw = fs.existsSync(paths.hashPath) ? fs.readFileSync(paths.hashPath, "utf8") : "";
  const hashFromFile = parseHashFileValue(hashFileRaw);
  if (!hashFromFile) {
    throw makeError("WORKLOAD_PROVENANCE_HASH_MISSING", "Build provenance hash file is missing or malformed", {
      hashPath: paths.hashPath,
    });
  }

  if (hashFromFile !== payloadHash || canonical.provenanceHash !== payloadHash) {
    throw makeError("WORKLOAD_PROVENANCE_HASH_MISMATCH", "Build provenance hash mismatch detected", {
      expectedFromHashFile: hashFromFile,
      expectedFromJson: canonical.provenanceHash,
      actualHash: payloadHash,
    });
  }

  const expectedHash = normalizeHash(options.expectedProvenanceHash || process.env.WORKLOAD_PROVENANCE_EXPECTED_HASH);
  if (expectedHash && expectedHash !== payloadHash) {
    throw makeError("WORKLOAD_PROVENANCE_HASH_MISMATCH", "Build provenance hash does not match expected hash", {
      expectedHash,
      actualHash: payloadHash,
    });
  }

  const publicKey = loadPublicVerificationKey(paths, options, production);
  const signatureBytes = decodeSignature(canonical.provenanceSignature);

  let signatureValid = false;
  try {
    signatureValid = crypto.verify(null, payloadBytes, publicKey, signatureBytes);
  } catch (error) {
    throw makeError("WORKLOAD_PROVENANCE_SIGNATURE_INVALID", "Build provenance signature verification threw an error", {
      reason: error instanceof Error ? error.message : String(error),
    });
  }

  if (!signatureValid) {
    throw makeError("WORKLOAD_PROVENANCE_SIGNATURE_INVALID", "Build provenance signature verification failed", {
      provenanceHash: payloadHash,
    });
  }

  if (!fs.existsSync(paths.dependencyLockPath)) {
    throw makeError("WORKLOAD_PROVENANCE_LOCK_MISMATCH", "Dependency lockfile is missing", {
      dependencyLockPath: paths.dependencyLockPath,
    });
  }

  const dependencyLockHash = computeFileSha256(paths.dependencyLockPath);
  if (dependencyLockHash !== canonical.dependencyLockHash) {
    throw makeError("WORKLOAD_PROVENANCE_LOCK_MISMATCH", "Dependency lockfile hash mismatch", {
      expectedLockHash: canonical.dependencyLockHash,
      actualLockHash: dependencyLockHash,
      dependencyLockPath: paths.dependencyLockPath,
    });
  }

  return {
    provenance: canonical,
    provenancePath: paths.provenancePath,
    hashPath: paths.hashPath,
    publicKeyPath: paths.publicKeyPath,
    dependencyLockPath: paths.dependencyLockPath,
    canonicalPayloadBytes: payloadBytes,
    canonicalPayloadHash: payloadHash,
  };
}

function evaluateSnapshotBinding(
  provenance: WorkloadProvenanceDocument,
  localMetadataRaw: Record<string, unknown> = {},
): WorkloadProvenanceVerificationResult {
  const localMetadata = isPlainObject(localMetadataRaw) ? localMetadataRaw : {};

  const localExecutionPolicyHash = normalizeHash(localMetadata.executionPolicyHash || localMetadata.execution_policy_hash);
  const localSecretManifestHash = normalizeHash(localMetadata.secretManifestHash || localMetadata.secret_manifest_hash);
  const localWorkloadManifestHash = normalizeHash(localMetadata.workloadManifestHash || localMetadata.workload_manifest_hash);
  const localAttestationReferenceHash = normalizeHash(
    localMetadata.attestationReferenceHash || localMetadata.attestation_reference_hash,
  );

  const missing: string[] = [];
  if (!localExecutionPolicyHash) missing.push("executionPolicyHash");
  if (!localSecretManifestHash) missing.push("secretManifestHash");
  if (!localWorkloadManifestHash) missing.push("workloadManifestHash");
  if (!localAttestationReferenceHash) missing.push("attestationReferenceHash");

  if (missing.length > 0) {
    return makeResult(
      "WORKLOAD_PROVENANCE_SNAPSHOT_MISMATCH",
      "Snapshot metadata is incomplete for provenance binding",
      {
        missing,
      },
      false,
    );
  }

  const mismatches: Array<Record<string, unknown>> = [];

  if (localExecutionPolicyHash !== provenance.executionPolicyHash) {
    mismatches.push({
      field: "executionPolicyHash",
      expected: provenance.executionPolicyHash,
      actual: localExecutionPolicyHash,
    });
  }

  if (localSecretManifestHash !== provenance.secretManifestHash) {
    mismatches.push({
      field: "secretManifestHash",
      expected: provenance.secretManifestHash,
      actual: localSecretManifestHash,
    });
  }

  if (localWorkloadManifestHash !== provenance.workloadManifestHash) {
    mismatches.push({
      field: "workloadManifestHash",
      expected: provenance.workloadManifestHash,
      actual: localWorkloadManifestHash,
    });
  }

  if (localAttestationReferenceHash !== provenance.attestationReferenceHash) {
    mismatches.push({
      field: "attestationReferenceHash",
      expected: provenance.attestationReferenceHash,
      actual: localAttestationReferenceHash,
    });
  }

  if (mismatches.length > 0) {
    return makeResult(
      "WORKLOAD_PROVENANCE_SNAPSHOT_MISMATCH",
      "Snapshot hash mismatch against build provenance",
      {
        mismatches,
      },
      false,
    );
  }

  return makeResult("WORKLOAD_PROVENANCE_SNAPSHOT_BOUND", "Snapshot hashes match build provenance", {}, true);
}

function evaluateDigestBinding(
  provenance: WorkloadProvenanceDocument,
  workloadID: string,
  runtimeDigestRaw: unknown,
): WorkloadProvenanceVerificationResult {
  const normalizedWorkloadID = normalizeToolKey(workloadID);
  const expectedDigest = normalizeDigest(provenance.containerImageDigests[normalizedWorkloadID]);
  if (!expectedDigest) {
    return makeResult(
      "WORKLOAD_PROVENANCE_DIGEST_MISMATCH",
      "No build provenance digest mapping found for workload",
      {
        workloadID: normalizedWorkloadID,
      },
      false,
    );
  }

  const runtimeDigest = normalizeDigest(runtimeDigestRaw);
  if (!runtimeDigest) {
    return makeResult(
      "WORKLOAD_PROVENANCE_DIGEST_MISMATCH",
      "Runtime execution digest is missing",
      {
        workloadID: normalizedWorkloadID,
        expectedDigest,
      },
      false,
    );
  }

  if (runtimeDigest !== expectedDigest) {
    return makeResult(
      "WORKLOAD_PROVENANCE_DIGEST_MISMATCH",
      "Runtime execution digest does not match build provenance digest",
      {
        workloadID: normalizedWorkloadID,
        expectedDigest,
        actualDigest: runtimeDigest,
      },
      false,
    );
  }

  return makeResult(
    "WORKLOAD_PROVENANCE_DIGEST_MATCH",
    "Runtime execution digest matches build provenance digest",
    {
      workloadID: normalizedWorkloadID,
      digest: runtimeDigest,
    },
    true,
  );
}

export function createWorkloadProvenanceRuntime(options: WorkloadProvenanceRuntimeOptions = {}): WorkloadProvenanceRuntime {
  const production = options.production === true || normalizeString(process.env.NODE_ENV).toLowerCase() === "production";
  const nodeId = normalizeString(options.nodeId || process.env.SUPERVISOR_NODE_ID) || "node-unknown";
  const metrics = createSafeMetrics(options.metrics);
  const audit = createSafeAudit(options.auditLog);
  const ttlMs = production
    ? DEFAULT_REVERIFY_TTL_MS
    : Math.min(MAX_REVERIFY_TTL_MS, parsePositiveInt(options.reverifyTtlMs, DEFAULT_REVERIFY_TTL_MS));

  let initialized = false;
  let trusted = false;
  let blockedReason = "";
  let lastVerifiedAt = 0;
  let loaded: LoadedBuildProvenance | null = null;
  let reverifyInFlight: Promise<WorkloadProvenanceVerificationResult> | null = null;

  function trackFailure(code: string, details: Record<string, unknown>): void {
    metrics.increment("workload.provenance.failure", {
      node_id: nodeId,
      reason: code,
    });
    metrics.increment("workload.provenance.block", {
      node_id: nodeId,
      reason: code,
    });

    if (code === "WORKLOAD_PROVENANCE_SIGNATURE_INVALID") {
      metrics.increment("workload.provenance.signature_invalid", { node_id: nodeId });
    }
    if (code === "WORKLOAD_PROVENANCE_DIGEST_MISMATCH") {
      metrics.increment("workload.provenance.digest_mismatch", { node_id: nodeId });
    }
    if (code === "WORKLOAD_PROVENANCE_LOCK_MISMATCH") {
      metrics.increment("workload.provenance.lock_mismatch", { node_id: nodeId });
    }

    audit({
      event: "workload_provenance_verification",
      status: "error",
      code,
      details: {
        nodeId,
        verificationResult: "failure",
        failureReason: code,
        gitCommitSha: loaded?.provenance.gitCommitSha || "",
        provenanceHash: loaded?.canonicalPayloadHash || "",
        ...details,
      },
    });
  }

  function trackSuccess(details: Record<string, unknown>): void {
    metrics.increment("workload.provenance.success", {
      node_id: nodeId,
    });

    audit({
      event: "workload_provenance_verification",
      status: "ok",
      code: "WORKLOAD_PROVENANCE_VERIFIED",
      details: {
        nodeId,
        verificationResult: "success",
        failureReason: "",
        gitCommitSha: loaded?.provenance.gitCommitSha || "",
        provenanceHash: loaded?.canonicalPayloadHash || "",
        ...details,
      },
    });
  }

  function performVerification(reason: string): WorkloadProvenanceVerificationResult {
    try {
      const next = loadBuildProvenanceFromDisk({
        ...options,
        production,
      });

      loaded = next;
      initialized = true;
      trusted = true;
      blockedReason = "";
      lastVerifiedAt = Date.now();

      metrics.gauge("workload.provenance.last_verified_at", lastVerifiedAt, {
        node_id: nodeId,
      });

      trackSuccess({
        reason,
        gitCommitSha: next.provenance.gitCommitSha,
        provenanceHash: next.canonicalPayloadHash,
      });

      return makeResult(
        "WORKLOAD_PROVENANCE_VERIFIED",
        "Workload provenance verification succeeded",
        {
          reason,
          gitCommitSha: next.provenance.gitCommitSha,
          provenanceHash: next.canonicalPayloadHash,
        },
        true,
      );
    } catch (error) {
      const code =
        error && typeof error === "object" && "code" in error && typeof (error as { code?: unknown }).code === "string"
          ? String((error as { code?: unknown }).code)
          : "WORKLOAD_PROVENANCE_NOT_TRUSTED";
      const details =
        error && typeof error === "object" && "details" in error && isPlainObject((error as { details?: unknown }).details)
          ? ((error as { details: Record<string, unknown> }).details as Record<string, unknown>)
          : {};

      initialized = true;
      trusted = false;
      blockedReason = code;

      trackFailure(code, {
        reason,
        ...details,
      });

      return makeResult(
        code,
        error instanceof Error ? error.message : "Workload provenance verification failed",
        {
          reason,
          ...details,
        },
        false,
      );
    }
  }

  async function ensureFreshVerification(): Promise<WorkloadProvenanceVerificationResult> {
    if (!initialized) {
      return performVerification("startup");
    }

    if (!trusted) {
      return makeResult(
        "WORKLOAD_PROVENANCE_NOT_TRUSTED",
        "Workload provenance is not trusted",
        {
          blockedReason,
        },
        false,
      );
    }

    const now = Date.now();
    if (now - lastVerifiedAt <= ttlMs) {
      return makeResult(
        "WORKLOAD_PROVENANCE_FRESH",
        "Workload provenance verification is fresh",
        {
          lastVerifiedAt,
          ttlMs,
        },
        true,
      );
    }

    if (!reverifyInFlight) {
      reverifyInFlight = Promise.resolve()
        .then(() => performVerification("ttl_reverify"))
        .finally(() => {
          reverifyInFlight = null;
        });
    }

    return reverifyInFlight;
  }

  function asNotTrusted(result: WorkloadProvenanceVerificationResult): WorkloadProvenanceVerificationResult {
    if (!result.ok) {
      return makeResult(
        "WORKLOAD_PROVENANCE_NOT_TRUSTED",
        "Workload provenance is not trusted",
        {
          failureReason: result.code,
          ...result.details,
        },
        false,
      );
    }
    return result;
  }

  async function verifyExecution(input: VerifyWorkloadProvenanceInput): Promise<WorkloadProvenanceVerificationResult> {
    const freshness = await ensureFreshVerification();
    if (!freshness.ok) {
      return asNotTrusted(freshness);
    }

    if (!loaded) {
      return makeResult(
        "WORKLOAD_PROVENANCE_NOT_TRUSTED",
        "Workload provenance state is unavailable",
        {
          failureReason: blockedReason || "WORKLOAD_PROVENANCE_NOT_TRUSTED",
        },
        false,
      );
    }

    const snapshot = evaluateSnapshotBinding(loaded.provenance, input.localMetadata || {});
    if (!snapshot.ok) {
      trusted = false;
      blockedReason = snapshot.code;
      trackFailure(snapshot.code, {
        workloadID: normalizeToolKey(input.workloadID),
        ...snapshot.details,
      });
      return asNotTrusted(snapshot);
    }

    const digest = evaluateDigestBinding(loaded.provenance, input.workloadID, input.runtimeDigest);
    if (!digest.ok) {
      trackFailure(digest.code, {
        workloadID: normalizeToolKey(input.workloadID),
        ...digest.details,
      });
      return asNotTrusted(digest);
    }

    trackSuccess({
      workloadID: normalizeToolKey(input.workloadID),
      provenanceHash: loaded.canonicalPayloadHash,
      gitCommitSha: loaded.provenance.gitCommitSha,
    });

    return makeResult(
      "WORKLOAD_PROVENANCE_VERIFIED",
      "Workload provenance verification succeeded",
      {
        workloadID: normalizeToolKey(input.workloadID),
        provenanceHash: loaded.canonicalPayloadHash,
        gitCommitSha: loaded.provenance.gitCommitSha,
        verifiedAt: lastVerifiedAt,
      },
      true,
    );
  }

  function getProvenanceState(): WorkloadProvenanceState {
    const stale = !lastVerifiedAt || Date.now() - lastVerifiedAt > ttlMs;
    return {
      nodeId,
      trusted,
      blockedReason,
      provenanceHash: loaded?.canonicalPayloadHash || "",
      gitCommitSha: loaded?.provenance.gitCommitSha || "",
      lastVerifiedAt,
      ttlMs,
      stale,
    };
  }

  return {
    initializeProvenance: () => performVerification("startup"),
    verifyExecution,
    getProvenanceState,
    isTrusted: () => trusted,
  };
}

export function generateDetachedProvenanceSignature(input: {
  provenance: unknown;
  privateKeyPem: string;
}): { provenanceHash: string; provenanceSignature: string } {
  const canonical = getCanonicalBuildProvenance(input.provenance);
  const payloadBytes = computeDetachedProvenancePayloadBytes(canonical);
  const provenanceHash = sha256HexFromBuffer(payloadBytes);
  const privateKey = crypto.createPrivateKey(input.privateKeyPem);
  const signature = crypto.sign(null, payloadBytes, privateKey).toString("base64");
  return {
    provenanceHash,
    provenanceSignature: signature,
  };
}

export function computeBuildEnvironmentFingerprint(input: {
  nodeVersion?: string;
  platform?: string;
  arch?: string;
  ci?: string;
}): string {
  const payload = serializeCanonical({
    nodeVersion: normalizeString(input.nodeVersion || process.version),
    platform: normalizeString(input.platform || process.platform),
    arch: normalizeString(input.arch || process.arch),
    ci: normalizeString(input.ci || process.env.CI || ""),
  });
  return sha256HexFromString(payload);
}
