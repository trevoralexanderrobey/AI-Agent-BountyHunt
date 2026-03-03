import crypto, { KeyObject } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const SHA256_HEX_PATTERN = /^[a-f0-9]{64}$/;
const SHA256_DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const SIGNATURE_BASE64_PATTERN = /^[a-z0-9+/=]+$/i;

const ROOT_KEYS = Object.freeze(["manifestVersion", "manifestHash", "manifestSignature", "tools"]);
const TOOL_KEYS = Object.freeze([
  "toolName",
  "toolVersion",
  "workloadID",
  "containerImageDigest",
  "runtimeConfigHash",
  "allowedArgsSchema",
  "executionConstraints",
  "isolationProfile",
  "capabilityScope",
  "allowedFlags",
  "deniedFlags",
  "forcedFlags",
]);
const EXECUTION_CONSTRAINT_KEYS = Object.freeze([
  "networkScope",
  "requiresTarget",
  "allowedProtocols",
  "maxRuntimeSeconds",
  "resourceLimits",
  "nonInteractive",
  "allowPrivateTargets",
  "allowCidrs",
  "singleTarget",
  "maxThreads",
]);
const RESOURCE_LIMIT_KEYS = Object.freeze(["cpuShares", "memoryLimitMb", "maxRuntimeSeconds", "maxOutputBytes"]);
const ISOLATION_PROFILE_KEYS = Object.freeze([
  "runAsNonRoot",
  "dropCapabilities",
  "privileged",
  "hostPID",
  "hostNetwork",
  "hostMounts",
  "readOnlyRootFilesystem",
  "writableVolumes",
  "seccompProfile",
  "appArmorProfile",
  "tty",
  "stdin",
]);

const DETACHED_PAYLOAD_KEYS = Object.freeze(ROOT_KEYS.filter((key) => key !== "manifestHash" && key !== "manifestSignature"));

export type OffensiveNetworkScope = "internal" | "external" | "target-bound";

export interface OffensiveResourceLimits {
  cpuShares: number;
  memoryLimitMb: number;
  maxRuntimeSeconds: number;
  maxOutputBytes: number;
}

export interface OffensiveExecutionConstraints {
  networkScope: OffensiveNetworkScope;
  requiresTarget: boolean;
  allowedProtocols: string[];
  maxRuntimeSeconds: number;
  resourceLimits: OffensiveResourceLimits;
  nonInteractive: boolean;
  allowPrivateTargets: boolean;
  allowCidrs: boolean;
  singleTarget: boolean;
  maxThreads: number;
}

export interface OffensiveIsolationProfile {
  runAsNonRoot: true;
  dropCapabilities: ["ALL"];
  privileged: false;
  hostPID: false;
  hostNetwork: false;
  hostMounts: false;
  readOnlyRootFilesystem: true;
  writableVolumes: ["scratch"];
  seccompProfile: string;
  appArmorProfile: string;
  tty: false;
  stdin: false;
}

export interface OffensiveToolManifestEntry {
  toolName: string;
  toolVersion: string;
  workloadID: string;
  containerImageDigest: string;
  runtimeConfigHash: string;
  allowedArgsSchema: Record<string, unknown>;
  executionConstraints: OffensiveExecutionConstraints;
  isolationProfile: OffensiveIsolationProfile;
  capabilityScope: string[];
  allowedFlags: string[];
  deniedFlags: string[];
  forcedFlags: string[];
}

export interface OffensiveWorkloadManifest {
  manifestVersion: number;
  manifestHash: string;
  manifestSignature: string;
  tools: OffensiveToolManifestEntry[];
}

export interface OffensiveManifestValidation {
  valid: boolean;
  errors: string[];
}

export interface OffensiveManifestPaths {
  manifestPath: string;
  hashPath: string;
  signaturePath: string;
  publicKeyPath: string;
  securityDirectory: string;
  configuredManifestPath: string;
  configuredHashPath: string;
  configuredSignaturePath: string;
  configuredPublicKeyPath: string;
}

export interface OffensiveManifestLoadOptions {
  production?: boolean;
  manifestPath?: string;
  hashPath?: string;
  signaturePath?: string;
  publicKeyPath?: string;
  expectedManifestHash?: string;
  allowProductionPathOverride?: boolean;
  productionContainerMode?: boolean;
}

export interface LoadedOffensiveManifest {
  manifest: OffensiveWorkloadManifest;
  manifestPath: string;
  hashPath: string;
  signaturePath: string;
  publicKeyPath: string;
  canonicalPayloadBytes: Buffer;
  canonicalPayloadHash: string;
  publicKey: KeyObject;
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

function sha256HexFromBuffer(value: Buffer): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function isPathWithin(parent: string, child: string): boolean {
  const relative = path.relative(path.resolve(parent), path.resolve(child));
  if (!relative) {
    return true;
  }
  return !relative.startsWith("..") && !path.isAbsolute(relative);
}

function makeError(code: string, message: string, details: Record<string, unknown> = {}): Error {
  const error = new Error(String(message || "Offensive workload manifest verification failed"));
  (error as Error & { code?: string; details?: unknown }).code = code;
  (error as Error & { code?: string; details?: unknown }).details = details;
  return error;
}

function assertNoSymlinkSegments(targetPath: string, code: string): void {
  const resolved = path.resolve(targetPath);
  const parsed = path.parse(resolved);
  const relative = path.relative(parsed.root, resolved);
  const segments = relative ? relative.split(path.sep).filter(Boolean) : [];

  let cursor = parsed.root;
  for (const segment of segments) {
    cursor = path.join(cursor, segment);
    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(cursor);
    } catch (error) {
      if (error && typeof error === "object" && "code" in error && String((error as { code?: unknown }).code || "") === "ENOENT") {
        continue;
      }
      throw error;
    }
    if (stat.isSymbolicLink()) {
      throw makeError(code, "Symlink paths are forbidden for offensive manifest artifacts in production", {
        path: targetPath,
        segmentPath: cursor,
      });
    }
  }
}

function assertResolvedPathEqualsRealPath(targetPath: string, code: string): void {
  const resolvedPath = path.resolve(targetPath);
  let realPath = "";
  try {
    realPath = fs.realpathSync.native(resolvedPath);
  } catch (error) {
    throw makeError(code, "Offensive artifact realpath could not be resolved", {
      path: resolvedPath,
      reason: error instanceof Error ? error.message : String(error),
    });
  }
  if (resolvedPath !== realPath) {
    throw makeError(code, "Offensive artifact must not resolve through symlink indirection", {
      resolvedPath,
      realPath,
    });
  }
}

function assertReadOnlyFileMode(targetPath: string, missingCode: string, writableCode: string): void {
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(targetPath);
  } catch (error) {
    throw makeError(missingCode, "Required offensive artifact is missing", {
      path: targetPath,
      reason: error instanceof Error ? error.message : String(error),
    });
  }

  if (!stat.isFile()) {
    throw makeError(missingCode, "Offensive artifact must be a regular file", {
      path: targetPath,
    });
  }

  if ((stat.mode & 0o222) !== 0) {
    throw makeError(writableCode, "Offensive artifact must not be writable in production", {
      path: targetPath,
      mode: (stat.mode & 0o777).toString(8),
    });
  }
}

function assertOwnerUid(targetPath: string, code: string): void {
  if (typeof process.getuid !== "function") {
    return;
  }
  const expectedUid = process.getuid();
  if (!Number.isFinite(expectedUid) || expectedUid < 0) {
    return;
  }
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(targetPath);
  } catch (error) {
    throw makeError(code, "Unable to read offensive artifact owner UID", {
      path: targetPath,
      reason: error instanceof Error ? error.message : String(error),
    });
  }
  if (stat.uid !== expectedUid) {
    throw makeError(code, "Offensive artifact owner UID does not match runtime UID", {
      path: targetPath,
      expectedUid,
      actualUid: stat.uid,
    });
  }
}

function assertNonWritableParentDirectories(targetPath: string, securityDirectory: string, code: string): void {
  const resolvedTarget = path.resolve(targetPath);
  const resolvedSecurityDir = path.resolve(securityDirectory);

  let cursor = path.dirname(resolvedTarget);
  while (isPathWithin(resolvedSecurityDir, cursor)) {
    const stat = fs.lstatSync(cursor);
    if (stat.isSymbolicLink()) {
      throw makeError(code, "Offensive parent directory must not be symlinked in production", {
        path: cursor,
      });
    }

    if ((stat.mode & 0o222) !== 0) {
      throw makeError(code, "Offensive parent directory must not be writable in production", {
        path: cursor,
        mode: (stat.mode & 0o777).toString(8),
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

function decodeMountComponent(value: string): string {
  return value.replace(/\\([0-7]{3})/g, (_m, octal) => String.fromCharCode(Number.parseInt(octal, 8)));
}

function assertReadOnlyMount(targetDirectory: string, code: string): void {
  let rawMountInfo = "";
  try {
    rawMountInfo = fs.readFileSync("/proc/self/mountinfo", "utf8");
  } catch (error) {
    throw makeError(code, "Unable to verify read-only mount for offensive directory", {
      targetDirectory,
      reason: error instanceof Error ? error.message : String(error),
    });
  }

  const resolvedTargetDirectory = path.resolve(targetDirectory);
  const lines = rawMountInfo.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  let selectedMountPoint = "";
  let selectedMountOptions: string[] = [];

  for (const line of lines) {
    const fields = line.split(" ");
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
    throw makeError(code, "Unable to determine mount point for offensive directory", {
      targetDirectory: resolvedTargetDirectory,
    });
  }

  if (!selectedMountOptions.includes("ro")) {
    throw makeError(code, "Offensive directory mount must be read-only in production container mode", {
      targetDirectory: resolvedTargetDirectory,
      mountPoint: selectedMountPoint,
      mountOptions: selectedMountOptions,
    });
  }
}

function resolveProjectRootFromCurrentDir(): string {
  const srcRoot = path.resolve(__dirname, "..", "..");
  const srcCandidate = path.resolve(srcRoot, "security", "offensive-workloads", "manifest.json");
  if (fs.existsSync(srcCandidate)) {
    return srcRoot;
  }
  return path.resolve(__dirname, "..", "..", "..");
}

export function resolveDefaultOffensiveManifestPath(): string {
  return path.resolve(resolveProjectRootFromCurrentDir(), "security", "offensive-workloads", "manifest.json");
}

export function resolveDefaultOffensiveManifestHashPath(): string {
  return path.resolve(resolveProjectRootFromCurrentDir(), "security", "offensive-workloads", "manifest.hash");
}

export function resolveDefaultOffensiveManifestSignaturePath(): string {
  return path.resolve(resolveProjectRootFromCurrentDir(), "security", "offensive-workloads", "manifest.sig");
}

export function resolveDefaultOffensiveManifestPublicKeyPath(): string {
  return path.resolve(resolveProjectRootFromCurrentDir(), "security", "offensive-workloads", "manifest.pub");
}

function resolvePaths(options: OffensiveManifestLoadOptions, production: boolean): OffensiveManifestPaths {
  const defaultManifestPath = resolveDefaultOffensiveManifestPath();
  const defaultHashPath = resolveDefaultOffensiveManifestHashPath();
  const defaultSignaturePath = resolveDefaultOffensiveManifestSignaturePath();
  const defaultPublicKeyPath = resolveDefaultOffensiveManifestPublicKeyPath();

  const configuredManifestPath = normalizeString(options.manifestPath || process.env.OFFENSIVE_MANIFEST_PATH);
  const configuredHashPath = normalizeString(options.hashPath || process.env.OFFENSIVE_MANIFEST_HASH_PATH);
  const configuredSignaturePath = normalizeString(options.signaturePath || process.env.OFFENSIVE_MANIFEST_SIGNATURE_PATH);
  const configuredPublicKeyPath = normalizeString(options.publicKeyPath || process.env.OFFENSIVE_MANIFEST_PUBLIC_KEY_PATH);

  const manifestPath = configuredManifestPath ? path.resolve(configuredManifestPath) : defaultManifestPath;
  const hashPath = configuredHashPath ? path.resolve(configuredHashPath) : defaultHashPath;
  const signaturePath = configuredSignaturePath ? path.resolve(configuredSignaturePath) : defaultSignaturePath;
  const publicKeyPath = configuredPublicKeyPath ? path.resolve(configuredPublicKeyPath) : defaultPublicKeyPath;
  const securityDirectory = path.resolve(path.dirname(defaultManifestPath));

  if (production && options.allowProductionPathOverride !== true) {
    if (configuredManifestPath && manifestPath !== path.resolve(defaultManifestPath)) {
      throw makeError("OFFENSIVE_MANIFEST_PATH_OVERRIDE_FORBIDDEN", "Offensive manifest path override is forbidden in production", {
        configuredPath: manifestPath,
        requiredPath: path.resolve(defaultManifestPath),
      });
    }
    if (configuredHashPath && hashPath !== path.resolve(defaultHashPath)) {
      throw makeError("OFFENSIVE_MANIFEST_HASH_PATH_OVERRIDE_FORBIDDEN", "Offensive manifest hash path override is forbidden in production", {
        configuredPath: hashPath,
        requiredPath: path.resolve(defaultHashPath),
      });
    }
    if (configuredSignaturePath && signaturePath !== path.resolve(defaultSignaturePath)) {
      throw makeError(
        "OFFENSIVE_MANIFEST_SIGNATURE_PATH_OVERRIDE_FORBIDDEN",
        "Offensive manifest signature path override is forbidden in production",
        {
          configuredPath: signaturePath,
          requiredPath: path.resolve(defaultSignaturePath),
        },
      );
    }
    if (configuredPublicKeyPath && publicKeyPath !== path.resolve(defaultPublicKeyPath)) {
      throw makeError(
        "OFFENSIVE_MANIFEST_PUBLIC_KEY_PATH_OVERRIDE_FORBIDDEN",
        "Offensive manifest public key path override is forbidden in production",
        {
          configuredPath: publicKeyPath,
          requiredPath: path.resolve(defaultPublicKeyPath),
        },
      );
    }
  }

  return {
    manifestPath,
    hashPath,
    signaturePath,
    publicKeyPath,
    securityDirectory,
    configuredManifestPath,
    configuredHashPath,
    configuredSignaturePath,
    configuredPublicKeyPath,
  };
}

function assertProductionFilesystemIntegrity(paths: OffensiveManifestPaths, productionContainerMode: boolean): void {
  const checks = [
    { path: path.resolve(paths.manifestPath), missingCode: "OFFENSIVE_MANIFEST_MISSING" },
    { path: path.resolve(paths.hashPath), missingCode: "OFFENSIVE_MANIFEST_HASH_MISSING" },
    { path: path.resolve(paths.signaturePath), missingCode: "OFFENSIVE_MANIFEST_SIGNATURE_MISSING" },
    { path: path.resolve(paths.publicKeyPath), missingCode: "OFFENSIVE_MANIFEST_PUBLIC_KEY_MISSING" },
  ];

  for (const check of checks) {
    assertNoSymlinkSegments(check.path, "OFFENSIVE_MANIFEST_SYMLINK_FORBIDDEN");
    assertResolvedPathEqualsRealPath(check.path, "OFFENSIVE_MANIFEST_SYMLINK_FORBIDDEN");
    assertReadOnlyFileMode(check.path, check.missingCode, "OFFENSIVE_MANIFEST_WRITABLE_IN_PRODUCTION");
    assertOwnerUid(check.path, "OFFENSIVE_MANIFEST_OWNER_INVALID");
    assertNonWritableParentDirectories(check.path, paths.securityDirectory, "OFFENSIVE_MANIFEST_PARENT_DIR_WRITABLE");
  }

  if (productionContainerMode) {
    assertReadOnlyMount(path.dirname(path.resolve(paths.manifestPath)), "OFFENSIVE_MANIFEST_MOUNT_NOT_READONLY");
  }
}

function validateUnknownKeys(value: Record<string, unknown>, allowed: readonly string[], label: string, errors: string[]): void {
  const allowedSet = new Set(allowed);
  for (const key of Object.keys(value)) {
    if (!allowedSet.has(key)) {
      errors.push(`${label} contains unknown field '${key}'`);
    }
  }
}

function validateStringArray(value: unknown, label: string, errors: string[], allowEmpty = true): string[] {
  if (!Array.isArray(value)) {
    errors.push(`${label} must be an array`);
    return [];
  }
  const out: string[] = [];
  for (let i = 0; i < value.length; i += 1) {
    const entry = normalizeString(value[i]);
    if (!entry) {
      errors.push(`${label}[${i}] must be a non-empty string`);
      continue;
    }
    out.push(entry);
  }
  if (!allowEmpty && out.length === 0) {
    errors.push(`${label} must not be empty`);
  }
  return out;
}

export function validateOffensiveWorkloadManifest(input: unknown): OffensiveManifestValidation {
  const errors: string[] = [];
  if (!isPlainObject(input)) {
    return { valid: false, errors: ["offensive manifest must be an object"] };
  }

  validateUnknownKeys(input, ROOT_KEYS, "offensive manifest", errors);

  const manifestVersion = Number(input.manifestVersion);
  if (!Number.isInteger(manifestVersion) || manifestVersion <= 0) {
    errors.push("manifestVersion must be a positive integer");
  }
  if (!SHA256_HEX_PATTERN.test(normalizeHash(input.manifestHash))) {
    errors.push("manifestHash must be a 64-character lowercase hex string");
  }
  const signature = normalizeString(input.manifestSignature);
  if (!signature || !SIGNATURE_BASE64_PATTERN.test(signature)) {
    errors.push("manifestSignature must be a non-empty base64 string");
  }

  if (!Array.isArray(input.tools) || input.tools.length === 0) {
    errors.push("tools must be a non-empty array");
    return { valid: errors.length === 0, errors };
  }

  const seen = new Set<string>();

  for (let i = 0; i < input.tools.length; i += 1) {
    const item = input.tools[i];
    const label = `tools[${i}]`;
    if (!isPlainObject(item)) {
      errors.push(`${label} must be an object`);
      continue;
    }

    validateUnknownKeys(item, TOOL_KEYS, label, errors);

    const toolName = normalizeToolKey(item.toolName);
    if (!/^[a-z0-9][a-z0-9_-]{0,127}$/.test(toolName)) {
      errors.push(`${label}.toolName must match /^[a-z0-9][a-z0-9_-]{0,127}$/`);
    } else if (seen.has(toolName)) {
      errors.push(`${label}.toolName must be unique`);
    } else {
      seen.add(toolName);
    }

    const toolVersion = normalizeString(item.toolVersion);
    if (!toolVersion) {
      errors.push(`${label}.toolVersion must be a non-empty string`);
    }

    const workloadID = normalizeString(item.workloadID);
    if (!/^[a-z0-9_.-]{1,128}$/i.test(workloadID)) {
      errors.push(`${label}.workloadID is invalid`);
    }

    if (!SHA256_DIGEST_PATTERN.test(normalizeString(item.containerImageDigest).toLowerCase())) {
      errors.push(`${label}.containerImageDigest must match sha256:<64hex>`);
    }

    if (!SHA256_HEX_PATTERN.test(normalizeHash(item.runtimeConfigHash))) {
      errors.push(`${label}.runtimeConfigHash must be 64-char hex sha256`);
    }

    if (!isPlainObject(item.allowedArgsSchema)) {
      errors.push(`${label}.allowedArgsSchema must be an object`);
    }

    if (!isPlainObject(item.executionConstraints)) {
      errors.push(`${label}.executionConstraints must be an object`);
    } else {
      const constraints = item.executionConstraints as Record<string, unknown>;
      validateUnknownKeys(constraints, EXECUTION_CONSTRAINT_KEYS, `${label}.executionConstraints`, errors);
      const networkScope = normalizeString(constraints.networkScope);
      if (!["internal", "external", "target-bound"].includes(networkScope)) {
        errors.push(`${label}.executionConstraints.networkScope must be internal|external|target-bound`);
      }
      if (typeof constraints.requiresTarget !== "boolean") {
        errors.push(`${label}.executionConstraints.requiresTarget must be boolean`);
      }
      validateStringArray(constraints.allowedProtocols, `${label}.executionConstraints.allowedProtocols`, errors, false);
      if (!Number.isInteger(Number(constraints.maxRuntimeSeconds)) || Number(constraints.maxRuntimeSeconds) <= 0) {
        errors.push(`${label}.executionConstraints.maxRuntimeSeconds must be positive integer`);
      }
      if (!Number.isInteger(Number(constraints.maxThreads)) || Number(constraints.maxThreads) <= 0) {
        errors.push(`${label}.executionConstraints.maxThreads must be positive integer`);
      }
      if (constraints.nonInteractive !== true) {
        errors.push(`${label}.executionConstraints.nonInteractive must be true`);
      }
      if (typeof constraints.allowPrivateTargets !== "boolean") {
        errors.push(`${label}.executionConstraints.allowPrivateTargets must be boolean`);
      }
      if (typeof constraints.allowCidrs !== "boolean") {
        errors.push(`${label}.executionConstraints.allowCidrs must be boolean`);
      }
      if (typeof constraints.singleTarget !== "boolean") {
        errors.push(`${label}.executionConstraints.singleTarget must be boolean`);
      }

      if (!isPlainObject(constraints.resourceLimits)) {
        errors.push(`${label}.executionConstraints.resourceLimits must be an object`);
      } else {
        const resourceLimits = constraints.resourceLimits as Record<string, unknown>;
        validateUnknownKeys(resourceLimits, RESOURCE_LIMIT_KEYS, `${label}.executionConstraints.resourceLimits`, errors);
        for (const key of RESOURCE_LIMIT_KEYS) {
          const parsed = Number(resourceLimits[key]);
          if (!Number.isInteger(parsed) || parsed <= 0) {
            errors.push(`${label}.executionConstraints.resourceLimits.${key} must be positive integer`);
          }
        }
      }
    }

    if (!isPlainObject(item.isolationProfile)) {
      errors.push(`${label}.isolationProfile must be an object`);
    } else {
      const profile = item.isolationProfile as Record<string, unknown>;
      validateUnknownKeys(profile, ISOLATION_PROFILE_KEYS, `${label}.isolationProfile`, errors);
      if (profile.runAsNonRoot !== true) errors.push(`${label}.isolationProfile.runAsNonRoot must be true`);
      if (profile.privileged !== false) errors.push(`${label}.isolationProfile.privileged must be false`);
      if (profile.hostPID !== false) errors.push(`${label}.isolationProfile.hostPID must be false`);
      if (profile.hostNetwork !== false) errors.push(`${label}.isolationProfile.hostNetwork must be false`);
      if (profile.hostMounts !== false) errors.push(`${label}.isolationProfile.hostMounts must be false`);
      if (profile.readOnlyRootFilesystem !== true) errors.push(`${label}.isolationProfile.readOnlyRootFilesystem must be true`);
      if (profile.tty !== false) errors.push(`${label}.isolationProfile.tty must be false`);
      if (profile.stdin !== false) errors.push(`${label}.isolationProfile.stdin must be false`);
      const dropCapabilities = validateStringArray(profile.dropCapabilities, `${label}.isolationProfile.dropCapabilities`, errors, false);
      if (dropCapabilities.length !== 1 || dropCapabilities[0] !== "ALL") {
        errors.push(`${label}.isolationProfile.dropCapabilities must equal ['ALL']`);
      }
      const writableVolumes = validateStringArray(profile.writableVolumes, `${label}.isolationProfile.writableVolumes`, errors, false);
      if (writableVolumes.length !== 1 || writableVolumes[0] !== "scratch") {
        errors.push(`${label}.isolationProfile.writableVolumes must equal ['scratch']`);
      }
      if (!normalizeString(profile.seccompProfile)) errors.push(`${label}.isolationProfile.seccompProfile is required`);
      if (!normalizeString(profile.appArmorProfile)) errors.push(`${label}.isolationProfile.appArmorProfile is required`);
    }

    validateStringArray(item.capabilityScope, `${label}.capabilityScope`, errors, false);
    validateStringArray(item.allowedFlags, `${label}.allowedFlags`, errors, true);
    validateStringArray(item.deniedFlags, `${label}.deniedFlags`, errors, true);
    validateStringArray(item.forcedFlags, `${label}.forcedFlags`, errors, true);
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

function normalizeStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((entry) => normalizeString(entry)).filter(Boolean).sort((left, right) => left.localeCompare(right));
}

function normalizeTool(input: OffensiveToolManifestEntry): OffensiveToolManifestEntry {
  const executionConstraintsSource = isPlainObject(input.executionConstraints) ? input.executionConstraints : ({} as OffensiveExecutionConstraints);
  const resourceLimitsSource = isPlainObject(executionConstraintsSource.resourceLimits)
    ? executionConstraintsSource.resourceLimits
    : ({} as OffensiveResourceLimits);
  const isolationProfileSource = isPlainObject(input.isolationProfile) ? input.isolationProfile : ({} as OffensiveIsolationProfile);
  const schema = isPlainObject(input.allowedArgsSchema) ? (canonicalize(input.allowedArgsSchema) as Record<string, unknown>) : {};

  return {
    toolName: normalizeToolKey(input.toolName),
    toolVersion: normalizeString(input.toolVersion),
    workloadID: normalizeString(input.workloadID),
    containerImageDigest: normalizeString(input.containerImageDigest).toLowerCase(),
    runtimeConfigHash: normalizeHash(input.runtimeConfigHash),
    allowedArgsSchema: schema,
    executionConstraints: {
      networkScope: normalizeString(executionConstraintsSource.networkScope) as OffensiveNetworkScope,
      requiresTarget: executionConstraintsSource.requiresTarget === true,
      allowedProtocols: normalizeStringArray(executionConstraintsSource.allowedProtocols),
      maxRuntimeSeconds: parsePositiveInt(executionConstraintsSource.maxRuntimeSeconds, 60),
      resourceLimits: {
        cpuShares: parsePositiveInt(resourceLimitsSource.cpuShares, 256),
        memoryLimitMb: parsePositiveInt(resourceLimitsSource.memoryLimitMb, 256),
        maxRuntimeSeconds: parsePositiveInt(resourceLimitsSource.maxRuntimeSeconds, 60),
        maxOutputBytes: parsePositiveInt(resourceLimitsSource.maxOutputBytes, 1024 * 1024),
      },
      nonInteractive: executionConstraintsSource.nonInteractive === true,
      allowPrivateTargets: executionConstraintsSource.allowPrivateTargets === true,
      allowCidrs: executionConstraintsSource.allowCidrs === true,
      singleTarget: parseBoolean(executionConstraintsSource.singleTarget, true),
      maxThreads: parsePositiveInt(executionConstraintsSource.maxThreads, 1),
    },
    isolationProfile: {
      runAsNonRoot: true,
      dropCapabilities: ["ALL"],
      privileged: false,
      hostPID: false,
      hostNetwork: false,
      hostMounts: false,
      readOnlyRootFilesystem: true,
      writableVolumes: ["scratch"],
      seccompProfile: normalizeString(isolationProfileSource.seccompProfile) || "runtime/default",
      appArmorProfile: normalizeString(isolationProfileSource.appArmorProfile) || "openclaw-default",
      tty: false,
      stdin: false,
    },
    capabilityScope: normalizeStringArray(input.capabilityScope),
    allowedFlags: normalizeStringArray(input.allowedFlags),
    deniedFlags: normalizeStringArray(input.deniedFlags),
    forcedFlags: normalizeStringArray(input.forcedFlags),
  };
}

function computeRuntimeConfigProjection(tool: OffensiveToolManifestEntry): Record<string, unknown> {
  return canonicalize({
    toolName: normalizeToolKey(tool.toolName),
    toolVersion: normalizeString(tool.toolVersion),
    workloadID: normalizeString(tool.workloadID),
    containerImageDigest: normalizeString(tool.containerImageDigest).toLowerCase(),
    allowedArgsSchema: canonicalize(isPlainObject(tool.allowedArgsSchema) ? tool.allowedArgsSchema : {}),
    executionConstraints: canonicalize(isPlainObject(tool.executionConstraints) ? tool.executionConstraints : {}),
    isolationProfile: canonicalize(isPlainObject(tool.isolationProfile) ? tool.isolationProfile : {}),
    capabilityScope: normalizeStringArray(tool.capabilityScope),
    allowedFlags: normalizeStringArray(tool.allowedFlags),
    deniedFlags: normalizeStringArray(tool.deniedFlags),
    forcedFlags: normalizeStringArray(tool.forcedFlags),
  }) as Record<string, unknown>;
}

export function computeOffensiveToolRuntimeConfigHash(tool: OffensiveToolManifestEntry): string {
  const projection = computeRuntimeConfigProjection(tool);
  return sha256HexFromBuffer(Buffer.from(serializeCanonical(projection), "utf8"));
}

export function getCanonicalOffensiveWorkloadManifest(input: unknown): OffensiveWorkloadManifest {
  const validation = validateOffensiveWorkloadManifest(input);
  if (!validation.valid) {
    throw makeError("OFFENSIVE_MANIFEST_SCHEMA_INVALID", "Offensive manifest schema validation failed", {
      errors: validation.errors,
    });
  }
  const source = input as OffensiveWorkloadManifest;
  const normalized: OffensiveWorkloadManifest = {
    manifestVersion: Number(source.manifestVersion),
    manifestHash: normalizeHash(source.manifestHash),
    manifestSignature: normalizeString(source.manifestSignature),
    tools: source.tools.map((tool) => normalizeTool(tool)).sort((left, right) => left.toolName.localeCompare(right.toolName)),
  };
  for (const tool of normalized.tools) {
    const expectedRuntimeConfigHash = computeOffensiveToolRuntimeConfigHash(tool);
    if (normalizeHash(tool.runtimeConfigHash) !== expectedRuntimeConfigHash) {
      throw makeError("OFFENSIVE_MANIFEST_SCHEMA_INVALID", "Offensive tool runtimeConfigHash mismatch", {
        toolName: tool.toolName,
        expectedRuntimeConfigHash,
        actualRuntimeConfigHash: normalizeHash(tool.runtimeConfigHash),
      });
    }
  }
  return canonicalize(normalized) as OffensiveWorkloadManifest;
}

export function getDetachedOffensiveManifestPayload(manifest: OffensiveWorkloadManifest): Record<string, unknown> {
  const source = manifest as unknown as Record<string, unknown>;
  const detached: Record<string, unknown> = {};
  for (const key of DETACHED_PAYLOAD_KEYS) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      detached[key] = source[key];
    }
  }
  return canonicalize(detached) as Record<string, unknown>;
}

export function computeDetachedOffensiveManifestPayloadBytes(manifest: OffensiveWorkloadManifest): Buffer {
  return Buffer.from(serializeCanonical(getDetachedOffensiveManifestPayload(manifest)), "utf8");
}

function parseHashFileValue(value: string): string {
  const normalized = normalizeHash(value.split(/\r?\n/).find((line) => line.trim()) || "");
  if (!SHA256_HEX_PATTERN.test(normalized)) {
    return "";
  }
  return normalized;
}

function decodeSignature(value: string): Buffer {
  const normalized = normalizeString(value);
  if (!normalized || !SIGNATURE_BASE64_PATTERN.test(normalized)) {
    throw makeError("OFFENSIVE_MANIFEST_SIGNATURE_INVALID", "Offensive manifest signature is invalid base64", {});
  }
  let decoded: Buffer;
  try {
    decoded = Buffer.from(normalized, "base64");
  } catch (error) {
    throw makeError("OFFENSIVE_MANIFEST_SIGNATURE_INVALID", "Unable to decode offensive manifest signature", {
      reason: error instanceof Error ? error.message : String(error),
    });
  }
  if (decoded.length === 0) {
    throw makeError("OFFENSIVE_MANIFEST_SIGNATURE_INVALID", "Offensive manifest signature decoded to empty bytes", {});
  }
  return decoded;
}

function loadPublicVerificationKey(pathToKey: string): KeyObject {
  const keySource = fs.existsSync(pathToKey) ? fs.readFileSync(pathToKey, "utf8") : "";
  if (!normalizeString(keySource)) {
    throw makeError("OFFENSIVE_MANIFEST_PUBLIC_KEY_MISSING", "Offensive manifest public key file is missing", {
      publicKeyPath: pathToKey,
    });
  }
  try {
    return crypto.createPublicKey(keySource);
  } catch (error) {
    throw makeError("OFFENSIVE_MANIFEST_PUBLIC_KEY_INVALID", "Unable to parse offensive manifest public key", {
      publicKeyPath: pathToKey,
      reason: error instanceof Error ? error.message : String(error),
    });
  }
}

export function loadOffensiveManifestFromDisk(options: OffensiveManifestLoadOptions = {}): LoadedOffensiveManifest {
  const production = options.production === true || normalizeString(process.env.NODE_ENV).toLowerCase() === "production";
  const productionContainerMode =
    options.productionContainerMode === true ||
    parseBoolean(process.env.PRODUCTION_CONTAINER_MODE, false) ||
    parseBoolean(process.env.OPENCLAW_PRODUCTION_CONTAINER_MODE, false);

  const paths = resolvePaths(options, production);
  if (production) {
    assertProductionFilesystemIntegrity(paths, productionContainerMode);
  }

  const rawManifest = fs.existsSync(paths.manifestPath) ? fs.readFileSync(paths.manifestPath, "utf8") : "";
  if (!rawManifest) {
    throw makeError("OFFENSIVE_MANIFEST_MISSING", "Offensive manifest file is missing", {
      manifestPath: paths.manifestPath,
    });
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawManifest);
  } catch (error) {
    throw makeError("OFFENSIVE_MANIFEST_SCHEMA_INVALID", "Offensive manifest JSON is invalid", {
      manifestPath: paths.manifestPath,
      reason: error instanceof Error ? error.message : String(error),
    });
  }

  const canonical = getCanonicalOffensiveWorkloadManifest(parsed);
  const payloadBytes = computeDetachedOffensiveManifestPayloadBytes(canonical);
  const payloadHash = sha256HexFromBuffer(payloadBytes);

  const hashFileRaw = fs.existsSync(paths.hashPath) ? fs.readFileSync(paths.hashPath, "utf8") : "";
  const hashFromFile = parseHashFileValue(hashFileRaw);
  if (!hashFromFile) {
    throw makeError("OFFENSIVE_MANIFEST_HASH_MISSING", "Offensive manifest hash file is missing or malformed", {
      hashPath: paths.hashPath,
    });
  }

  if (hashFromFile !== payloadHash || canonical.manifestHash !== payloadHash) {
    throw makeError("OFFENSIVE_MANIFEST_HASH_MISMATCH", "Offensive manifest hash mismatch detected", {
      expectedFromHashFile: hashFromFile,
      expectedFromJson: canonical.manifestHash,
      actualHash: payloadHash,
    });
  }

  const expectedHash = normalizeHash(options.expectedManifestHash || process.env.OFFENSIVE_MANIFEST_EXPECTED_HASH);
  if (expectedHash && expectedHash !== payloadHash) {
    throw makeError("OFFENSIVE_MANIFEST_HASH_MISMATCH", "Offensive manifest hash does not match expected hash", {
      expectedHash,
      actualHash: payloadHash,
    });
  }

  const signatureFromFileRaw = normalizeString(fs.existsSync(paths.signaturePath) ? fs.readFileSync(paths.signaturePath, "utf8") : "");
  if (!signatureFromFileRaw) {
    throw makeError("OFFENSIVE_MANIFEST_SIGNATURE_MISSING", "Offensive manifest signature file is missing", {
      signaturePath: paths.signaturePath,
    });
  }
  if (signatureFromFileRaw !== canonical.manifestSignature) {
    throw makeError("OFFENSIVE_MANIFEST_SIGNATURE_INVALID", "Offensive manifest signature file must match manifestSignature value", {
      signaturePath: paths.signaturePath,
    });
  }

  const publicKey = loadPublicVerificationKey(paths.publicKeyPath);
  const signatureBytes = decodeSignature(canonical.manifestSignature);

  let signatureValid = false;
  try {
    signatureValid = crypto.verify(null, payloadBytes, publicKey, signatureBytes);
  } catch (error) {
    throw makeError("OFFENSIVE_MANIFEST_SIGNATURE_INVALID", "Offensive manifest signature verification threw an error", {
      reason: error instanceof Error ? error.message : String(error),
    });
  }
  if (!signatureValid) {
    throw makeError("OFFENSIVE_MANIFEST_SIGNATURE_INVALID", "Offensive manifest signature verification failed", {
      manifestHash: payloadHash,
    });
  }

  return {
    manifest: canonical,
    manifestPath: paths.manifestPath,
    hashPath: paths.hashPath,
    signaturePath: paths.signaturePath,
    publicKeyPath: paths.publicKeyPath,
    canonicalPayloadBytes: payloadBytes,
    canonicalPayloadHash: payloadHash,
    publicKey,
  };
}

export function verifyOffensiveManifest(options: OffensiveManifestLoadOptions = {}): {
  ok: boolean;
  code: string;
  message: string;
  details: Record<string, unknown>;
} {
  try {
    const loaded = loadOffensiveManifestFromDisk(options);
    return {
      ok: true,
      code: "OFFENSIVE_MANIFEST_VERIFIED",
      message: "Offensive manifest verified",
      details: {
        manifestHash: loaded.canonicalPayloadHash,
        manifestPath: loaded.manifestPath,
        hashPath: loaded.hashPath,
        signaturePath: loaded.signaturePath,
        publicKeyPath: loaded.publicKeyPath,
      },
    };
  } catch (error) {
    const code =
      error && typeof error === "object" && "code" in error && typeof (error as { code?: unknown }).code === "string"
        ? String((error as { code?: unknown }).code)
        : "OFFENSIVE_MANIFEST_NOT_TRUSTED";
    const details =
      error && typeof error === "object" && "details" in error && isPlainObject((error as { details?: unknown }).details)
        ? ((error as { details: Record<string, unknown> }).details as Record<string, unknown>)
        : {};
    return {
      ok: false,
      code,
      message: error instanceof Error ? error.message : "Offensive manifest verification failed",
      details,
    };
  }
}

export function generateDetachedOffensiveManifestSignature(input: {
  manifest: OffensiveWorkloadManifest;
  privateKeyPem: string;
}): { manifestHash: string; manifestSignature: string } {
  const canonical = getCanonicalOffensiveWorkloadManifest(input.manifest);
  const payloadBytes = computeDetachedOffensiveManifestPayloadBytes(canonical);
  const manifestHash = sha256HexFromBuffer(payloadBytes);
  const privateKey = crypto.createPrivateKey(input.privateKeyPem);
  const manifestSignature = crypto.sign(null, payloadBytes, privateKey).toString("base64");
  return {
    manifestHash,
    manifestSignature,
  };
}
