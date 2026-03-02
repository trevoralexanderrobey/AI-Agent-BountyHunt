import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const ROOT_KEYS = Object.freeze(["workloads"]);
const REQUIRED_KEYS = Object.freeze([
  "workloadID",
  "adapterHash",
  "entrypointHash",
  "runtimeConfigHash",
  "workloadVersion",
  "productionRequired",
]);
const OPTIONAL_KEYS = Object.freeze(["containerImageDigest"]);
const ALLOWED_KEYS = Object.freeze([...REQUIRED_KEYS, ...OPTIONAL_KEYS]);

const FORBIDDEN_FIELD_PATTERN =
  /(timestamp|createdat|updatedat|lastmodified|nodeid|node_id|hostname|secret|token|password|privatekey|binary|blob|payload|env|dynamic)/i;

export interface WorkloadManifestEntry {
  workloadID: string;
  adapterHash: string;
  entrypointHash: string;
  runtimeConfigHash: string;
  containerImageDigest?: string;
  workloadVersion: number;
  productionRequired: boolean;
}

export interface WorkloadManifest {
  workloads: WorkloadManifestEntry[];
}

export interface WorkloadManifestValidation {
  valid: boolean;
  errors: string[];
}

export interface LoadWorkloadManifestOptions {
  manifestPath?: string;
  production?: boolean;
  allowProductionPathOverride?: boolean;
}

function normalizeString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function normalizeHash(value: unknown): string {
  return normalizeString(value).toLowerCase();
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function isPositiveInteger(value: unknown): boolean {
  return Number.isInteger(value) && Number(value) > 0;
}

function normalizeDigest(value: unknown): string {
  const normalized = normalizeString(value).toLowerCase();
  return normalized;
}

function unknownKeys(value: Record<string, unknown>, allowed: readonly string[]): string[] {
  const allowedSet = new Set(allowed);
  return Object.keys(value).filter((key) => !allowedSet.has(key));
}

function hasForbiddenFields(value: unknown): boolean {
  if (!value || typeof value !== "object") {
    return false;
  }
  if (Array.isArray(value)) {
    return value.some((item) => hasForbiddenFields(item));
  }
  return Object.entries(value).some(([key, child]) => {
    if (FORBIDDEN_FIELD_PATTERN.test(String(key || ""))) {
      return true;
    }
    return hasForbiddenFields(child);
  });
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => canonicalize(item));
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

function normalizeEntry(raw: WorkloadManifestEntry): WorkloadManifestEntry {
  const normalized: WorkloadManifestEntry = {
    workloadID: normalizeString(raw.workloadID),
    adapterHash: normalizeHash(raw.adapterHash),
    entrypointHash: normalizeHash(raw.entrypointHash),
    runtimeConfigHash: normalizeHash(raw.runtimeConfigHash),
    workloadVersion: Number(raw.workloadVersion),
    productionRequired: raw.productionRequired === true,
  };

  const digest = normalizeDigest(raw.containerImageDigest);
  if (digest) {
    normalized.containerImageDigest = digest;
  }

  return normalized;
}

function makeManifestError(code: string, message: string, details: Record<string, unknown> = {}): Error {
  const error = new Error(message);
  (error as Error & { code?: string; details?: unknown }).code = code;
  (error as Error & { code?: string; details?: unknown }).details = details;
  return error;
}

function resolveProjectRootFromCurrentDir(): string {
  const srcRoot = path.resolve(__dirname, "..", "..");
  const srcCandidate = path.resolve(srcRoot, "security", "workload-manifest.json");
  if (fs.existsSync(srcCandidate)) {
    return srcRoot;
  }
  return path.resolve(__dirname, "..", "..", "..");
}

function assertProductionPathSafety(
  manifestPath: string,
  canonicalPath: string,
  enforceCanonicalPath = true,
): void {
  const resolvedManifestPath = path.resolve(manifestPath);
  const resolvedCanonicalPath = path.resolve(canonicalPath);

  if (enforceCanonicalPath && resolvedManifestPath !== resolvedCanonicalPath) {
    throw makeManifestError(
      "WORKLOAD_MANIFEST_PATH_OVERRIDE_FORBIDDEN",
      "Workload manifest path override is forbidden in production",
      {
        manifestPath: resolvedManifestPath,
        requiredPath: resolvedCanonicalPath,
      },
    );
  }

  let stats: fs.Stats;
  try {
    stats = fs.lstatSync(resolvedManifestPath);
  } catch {
    throw makeManifestError("WORKLOAD_MANIFEST_MISSING", "Workload manifest file is missing", {
      manifestPath: resolvedManifestPath,
      requiredPath: resolvedCanonicalPath,
    });
  }

  if (stats.isSymbolicLink()) {
    throw makeManifestError(
      "WORKLOAD_MANIFEST_PATH_OVERRIDE_FORBIDDEN",
      "Workload manifest must not be symlinked in production",
      {
        manifestPath: resolvedManifestPath,
        requiredPath: resolvedCanonicalPath,
      },
    );
  }

  if (!stats.isFile()) {
    throw makeManifestError("WORKLOAD_MANIFEST_MISSING", "Workload manifest path must reference a regular file", {
      manifestPath: resolvedManifestPath,
      requiredPath: resolvedCanonicalPath,
    });
  }

  try {
    fs.accessSync(resolvedManifestPath, fs.constants.W_OK);
    throw makeManifestError(
      "WORKLOAD_MANIFEST_WRITABLE_IN_PRODUCTION",
      "Workload manifest must not be writable in production",
      {
        manifestPath: resolvedManifestPath,
        requiredPath: resolvedCanonicalPath,
      },
    );
  } catch (error) {
    if (
      error &&
      typeof error === "object" &&
      "code" in error &&
      String((error as { code?: unknown }).code || "") === "WORKLOAD_MANIFEST_WRITABLE_IN_PRODUCTION"
    ) {
      throw error;
    }
    // Expected when write access is denied.
  }
}

export function resolveDefaultWorkloadManifestPath(): string {
  const projectRoot = resolveProjectRootFromCurrentDir();
  return path.resolve(projectRoot, "security", "workload-manifest.json");
}

export function validateWorkloadManifest(manifest: unknown): WorkloadManifestValidation {
  const errors: string[] = [];

  if (!isPlainObject(manifest)) {
    return {
      valid: false,
      errors: ["workload manifest must be an object"],
    };
  }

  for (const key of ROOT_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(manifest, key)) {
      errors.push(`missing required field '${key}'`);
    }
  }

  const rootUnknown = unknownKeys(manifest, ROOT_KEYS);
  if (rootUnknown.length > 0) {
    errors.push(`unknown root fields: ${rootUnknown.join(",")}`);
  }

  const workloads = manifest.workloads;
  if (!Array.isArray(workloads) || workloads.length === 0) {
    errors.push("workloads must be a non-empty array");
  } else {
    const seenIds = new Set<string>();

    for (let index = 0; index < workloads.length; index += 1) {
      const item = workloads[index];
      const itemPath = `workloads[${index}]`;

      if (!isPlainObject(item)) {
        errors.push(`${itemPath} must be an object`);
        continue;
      }

      for (const key of REQUIRED_KEYS) {
        if (!Object.prototype.hasOwnProperty.call(item, key)) {
          errors.push(`${itemPath}.${key} is required`);
        }
      }

      const itemUnknown = unknownKeys(item, ALLOWED_KEYS);
      if (itemUnknown.length > 0) {
        errors.push(`${itemPath} contains unknown keys: ${itemUnknown.join(",")}`);
      }

      const workloadID = normalizeString(item.workloadID);
      if (!workloadID) {
        errors.push(`${itemPath}.workloadID must be a non-empty string`);
      } else {
        const key = workloadID.toLowerCase();
        if (seenIds.has(key)) {
          errors.push(`duplicate workloadID '${workloadID}'`);
        }
        seenIds.add(key);
      }

      if (!/^[a-f0-9]{64}$/.test(normalizeHash(item.adapterHash))) {
        errors.push(`${itemPath}.adapterHash must be a sha256 hex string`);
      }

      if (!/^[a-f0-9]{64}$/.test(normalizeHash(item.entrypointHash))) {
        errors.push(`${itemPath}.entrypointHash must be a sha256 hex string`);
      }

      if (!/^[a-f0-9]{64}$/.test(normalizeHash(item.runtimeConfigHash))) {
        errors.push(`${itemPath}.runtimeConfigHash must be a sha256 hex string`);
      }

      const digest = normalizeDigest(item.containerImageDigest);
      if (digest && !/^sha256:[a-f0-9]{64}$/.test(digest)) {
        errors.push(`${itemPath}.containerImageDigest must match sha256:<64hex>`);
      }

      if (!isPositiveInteger(item.workloadVersion)) {
        errors.push(`${itemPath}.workloadVersion must be a positive integer`);
      }

      if (typeof item.productionRequired !== "boolean") {
        errors.push(`${itemPath}.productionRequired must be a boolean`);
      }

      if (hasForbiddenFields(item)) {
        errors.push(`${itemPath} contains forbidden/dynamic metadata keys`);
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

export function getCanonicalWorkloadManifest(inputManifest: unknown): WorkloadManifest {
  const validation = validateWorkloadManifest(inputManifest);
  if (!validation.valid) {
    throw makeManifestError(
      "WORKLOAD_MANIFEST_SCHEMA_INVALID",
      `Workload manifest schema validation failed: ${validation.errors.join("; ")}`,
      { errors: validation.errors },
    );
  }

  const manifest = inputManifest as WorkloadManifest;
  const normalized: WorkloadManifest = {
    workloads: manifest.workloads
      .map((entry) => normalizeEntry(entry))
      .sort((left, right) => left.workloadID.localeCompare(right.workloadID)),
  };

  return canonicalize(normalized) as WorkloadManifest;
}

function serializeCanonical(manifest: WorkloadManifest): string {
  return JSON.stringify(manifest);
}

export function computeWorkloadManifestHash(inputManifest: unknown): string {
  const canonical = getCanonicalWorkloadManifest(inputManifest);
  return crypto.createHash("sha256").update(serializeCanonical(canonical), "utf8").digest("hex");
}

export function loadWorkloadManifestFromDisk(options: LoadWorkloadManifestOptions = {}): WorkloadManifest {
  const production =
    options.production === true ||
    normalizeString(process.env.NODE_ENV).toLowerCase() === "production";

  const defaultPath = resolveDefaultWorkloadManifestPath();
  const configuredPath = normalizeString(options.manifestPath || process.env.WORKLOAD_MANIFEST_PATH);
  const selectedPath = configuredPath ? path.resolve(configuredPath) : defaultPath;

  if (production) {
    if (
      configuredPath &&
      selectedPath !== defaultPath &&
      options.allowProductionPathOverride !== true
    ) {
      throw makeManifestError(
        "WORKLOAD_MANIFEST_PATH_OVERRIDE_FORBIDDEN",
        "Workload manifest path override is forbidden in production",
        {
          manifestPath: selectedPath,
          requiredPath: defaultPath,
        },
      );
    }
    assertProductionPathSafety(selectedPath, defaultPath, options.allowProductionPathOverride !== true);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(fs.readFileSync(selectedPath, "utf8"));
  } catch (error) {
    throw makeManifestError("WORKLOAD_MANIFEST_MISSING", "Workload manifest file could not be loaded", {
      manifestPath: selectedPath,
      reason: error instanceof Error ? error.message : String(error),
    });
  }

  return getCanonicalWorkloadManifest(parsed);
}
