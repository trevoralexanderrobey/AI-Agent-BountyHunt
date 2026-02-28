const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const {
  validatePolicySchema,
  serializeCanonical,
  computePolicyHash,
} = require("./execution-policy-manifest.js");

let activeAuthorityState = null;
const DEFAULT_POLICY_MANIFEST_PATH = path.resolve(__dirname, "execution-policy.json");
const DEFAULT_POLICY_SIGNATURE_PATH = path.resolve(__dirname, "execution-policy.json.sig");
const DEFAULT_POLICY_PUBLIC_KEY_PATH = path.resolve(__dirname, "execution-policy.pub.pem");

function normalizeString(value) {
  return typeof value === "string" ? value.trim() : "";
}

function parseBoolean(value, fallback = false) {
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

function parsePositiveInteger(value, fallback = 1) {
  const parsed = Number.parseInt(String(value ?? "").trim(), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
}

function safeResolvePath(value) {
  const normalized = normalizeString(value);
  if (!normalized) {
    return "";
  }
  try {
    return path.resolve(normalized);
  } catch {
    return normalized;
  }
}

function deepFreeze(value) {
  if (!value || typeof value !== "object") {
    return value;
  }
  Object.freeze(value);
  for (const key of Object.keys(value)) {
    const child = value[key];
    if (child && typeof child === "object" && !Object.isFrozen(child)) {
      deepFreeze(child);
    }
  }
  return value;
}

function makeFailure(code, message, details = {}) {
  const error = new Error(String(message || "Policy authority failure"));
  error.code = String(code || "POLICY_AUTHORITY_ERROR");
  error.details = details;
  return error;
}

function createNoopMetrics() {
  return {
    increment: () => {},
    gauge: () => {},
  };
}

function createSafeMetrics(rawMetrics) {
  const source = rawMetrics && typeof rawMetrics === "object" ? rawMetrics : createNoopMetrics();
  return {
    increment: (...args) => {
      try {
        if (typeof source.increment === "function") {
          source.increment(...args);
        }
      } catch {}
    },
    gauge: (...args) => {
      try {
        if (typeof source.gauge === "function") {
          source.gauge(...args);
        }
      } catch {}
    },
  };
}

function createNoopAuditLogger() {
  return {
    log: () => {},
  };
}

function createSafeAuditLogger(rawLogger) {
  const source = rawLogger && typeof rawLogger === "object" ? rawLogger : createNoopAuditLogger();
  return {
    log: (...args) => {
      try {
        if (typeof source.log === "function") {
          source.log(...args);
        }
      } catch {}
    },
  };
}

function parseVersionFromLegacy(raw) {
  if (Number.isInteger(raw) && raw > 0) {
    return raw;
  }
  const value = normalizeString(raw).toLowerCase();
  if (!value) {
    return 1;
  }
  const stripped = value.startsWith("v") ? value.slice(1) : value;
  return parsePositiveInteger(stripped, 1);
}

function sanitizeIntegerMap(rawValue) {
  const map = {};
  if (!rawValue || typeof rawValue !== "object" || Array.isArray(rawValue)) {
    return map;
  }
  for (const [rawKey, rawLimit] of Object.entries(rawValue)) {
    const key = normalizeString(rawKey).toLowerCase();
    const limit = parsePositiveInteger(rawLimit, 0);
    if (!key || limit <= 0) {
      continue;
    }
    map[key] = limit;
  }
  return map;
}

function sanitizeResourceCaps(rawPolicies) {
  const policies = {};
  if (!rawPolicies || typeof rawPolicies !== "object" || Array.isArray(rawPolicies)) {
    return policies;
  }
  for (const [rawSlug, rawLimits] of Object.entries(rawPolicies)) {
    const slug = normalizeString(rawSlug).toLowerCase();
    if (!slug || !rawLimits || typeof rawLimits !== "object" || Array.isArray(rawLimits)) {
      continue;
    }
    const cpuShares = parsePositiveInteger(rawLimits.cpuShares, 0);
    const memoryLimitMb = parsePositiveInteger(rawLimits.memoryLimitMb, 0);
    const maxRuntimeSeconds = parsePositiveInteger(rawLimits.maxRuntimeSeconds, 0);
    const maxOutputBytes = parsePositiveInteger(rawLimits.maxOutputBytes, 0);
    if (!cpuShares || !memoryLimitMb || !maxRuntimeSeconds || !maxOutputBytes) {
      continue;
    }
    policies[slug] = {
      cpuShares,
      memoryLimitMb,
      maxRuntimeSeconds,
      maxOutputBytes,
    };
  }
  return policies;
}

function synthesizePolicyFromLegacy(options = {}) {
  const execution = options.legacyExecution && typeof options.legacyExecution === "object" ? options.legacyExecution : {};
  const security = options.security && typeof options.security === "object" ? options.security : {};
  const observability = options.observability && typeof options.observability === "object" ? options.observability : {};
  const alertThresholds =
    observability.alertThresholds && typeof observability.alertThresholds === "object" ? observability.alertThresholds : {};

  const resourceCaps = sanitizeResourceCaps(execution.resourcePolicies);
  if (Object.keys(resourceCaps).length === 0) {
    resourceCaps.curl = {
      cpuShares: 256,
      memoryLimitMb: 256,
      maxRuntimeSeconds: 30,
      maxOutputBytes: 5 * 1024 * 1024,
    };
  }

  const perToolConcurrencyLimits = sanitizeIntegerMap(execution.toolConcurrencyLimits);
  if (Object.keys(perToolConcurrencyLimits).length === 0) {
    perToolConcurrencyLimits.curl = 1;
  }

  const policy = {
    policyVersion: parseVersionFromLegacy(execution.policyVersion || execution.configVersion),
    executionMode: normalizeString(execution.executionMode) || "host",
    containerRuntimeEnabled: execution.containerRuntimeEnabled === true,
    resourceCaps,
    perToolConcurrencyLimits,
    nodeConcurrencyCaps: {
      maxConcurrentContainersPerNode: parsePositiveInteger(execution.maxConcurrentContainersPerNode, 16),
      nodeMemoryHardCapMb: parsePositiveInteger(execution.nodeMemoryHardCapMb, 8192),
      nodeCpuHardCapShares: parsePositiveInteger(execution.nodeCpuHardCapShares, 8192),
    },
    registryAllowlist:
      Array.isArray(execution.allowedImageRegistries) && execution.allowedImageRegistries.length > 0
        ? execution.allowedImageRegistries.map((item) => normalizeString(item)).filter(Boolean)
        : ["ghcr.io"],
    signatureEnforcement: {
      requireInProduction: execution.requireSignatureVerificationInProduction !== false,
      requireInNonProduction: false,
    },
    quotaConfig: {
      executionQuotaPerHour: parsePositiveInteger(security.executionQuotaPerHour, 0),
      executionBurstLimitPerMinute: parsePositiveInteger(security.executionBurstLimitPerMinute, 0),
      quotaRedisUrl:
        normalizeString(security.quotaRedisUrl) || normalizeString(process.env.EXECUTION_QUOTA_REDIS_URL) || "redis://127.0.0.1:6379",
      quotaRedisPrefix:
        normalizeString(security.quotaRedisPrefix) || normalizeString(process.env.EXECUTION_QUOTA_REDIS_PREFIX) || "openclaw:quota",
    },
    arbitrationThresholds: {
      arbiterRebuildFailClosed: true,
    },
    observabilityThresholds: {
      circuitOpenRate: Number.isFinite(Number(alertThresholds.circuitOpenRate)) ? Number(alertThresholds.circuitOpenRate) : 0.2,
      executionRejectRate: Number.isFinite(Number(alertThresholds.executionRejectRate)) ? Number(alertThresholds.executionRejectRate) : 0.15,
      memoryPressureRate: Number.isFinite(Number(alertThresholds.memoryPressureRate)) ? Number(alertThresholds.memoryPressureRate) : 0.1,
    },
    policy: {
      allowedUpgradeWindowMinutes: parsePositiveInteger(execution.rollingUpgradeWindowMinutes, 0),
    },
    metadata: {
      allowDowngradeFromVersions: [],
      allowDowngradeFromHashes: [],
    },
  };

  return policy;
}

function shouldAllowProductionPathOverride(options = {}) {
  return parseBoolean(options.allowProductionPathOverride, false);
}

function getDefaultPolicyArtifactPaths() {
  return {
    manifestPath: DEFAULT_POLICY_MANIFEST_PATH,
    signaturePath: DEFAULT_POLICY_SIGNATURE_PATH,
    publicKeyPath: DEFAULT_POLICY_PUBLIC_KEY_PATH,
  };
}

function resolvePolicyArtifactPath(options = {}, production = false, descriptor = {}) {
  const defaultPath = safeResolvePath(descriptor.defaultPath);
  const optionPath = normalizeString(options[descriptor.optionKey]);
  const envPath = normalizeString(process.env[descriptor.envKey]);
  const configuredPath = optionPath || envPath;
  const allowProductionPathOverride = shouldAllowProductionPathOverride(options);

  if (!production) {
    return configuredPath ? configuredPath : "";
  }

  if (configuredPath && !allowProductionPathOverride) {
    const configuredResolved = safeResolvePath(configuredPath);
    if (configuredResolved !== defaultPath) {
      throw makeFailure("POLICY_PATH_OVERRIDE_FORBIDDEN", `${descriptor.label} path override is forbidden in production`, {
        field: descriptor.optionKey,
        env: descriptor.envKey,
        configuredPath: configuredResolved,
        requiredPath: defaultPath,
      });
    }
  }

  if (!configuredPath) {
    return defaultPath;
  }

  return configuredPath;
}

function resolveManifestPath(options = {}, production = false) {
  return resolvePolicyArtifactPath(options, production, {
    optionKey: "manifestPath",
    envKey: "EXECUTION_POLICY_MANIFEST_PATH",
    defaultPath: DEFAULT_POLICY_MANIFEST_PATH,
    label: "Policy manifest",
  });
}

function resolveSignaturePath(options = {}, production = false) {
  return resolvePolicyArtifactPath(options, production, {
    optionKey: "signaturePath",
    envKey: "EXECUTION_POLICY_SIGNATURE_PATH",
    defaultPath: DEFAULT_POLICY_SIGNATURE_PATH,
    label: "Policy signature",
  });
}

function resolvePublicKeyPath(options = {}, production = false) {
  return resolvePolicyArtifactPath(options, production, {
    optionKey: "publicKeyPath",
    envKey: "EXECUTION_POLICY_PUBLIC_KEY_PATH",
    defaultPath: DEFAULT_POLICY_PUBLIC_KEY_PATH,
    label: "Policy public key",
  });
}

function assertProductionArtifactPathSafety(artifactPath, requiredPath, artifactName) {
  const resolvedArtifactPath = safeResolvePath(artifactPath);
  const resolvedRequiredPath = safeResolvePath(requiredPath);
  if (!resolvedArtifactPath || !resolvedRequiredPath) {
    throw makeFailure("POLICY_FILE_NOT_PRESENT", `${artifactName} path is missing`, {
      artifactPath: resolvedArtifactPath,
      requiredPath: resolvedRequiredPath,
    });
  }
  if (resolvedArtifactPath !== resolvedRequiredPath) {
    throw makeFailure("POLICY_PATH_OVERRIDE_FORBIDDEN", `${artifactName} path override is forbidden in production`, {
      artifactPath: resolvedArtifactPath,
      requiredPath: resolvedRequiredPath,
    });
  }
  let stats;
  try {
    stats = fs.lstatSync(resolvedArtifactPath);
  } catch {
    throw makeFailure("POLICY_FILE_NOT_PRESENT", `${artifactName} file is missing`, {
      artifactPath: resolvedArtifactPath,
      requiredPath: resolvedRequiredPath,
    });
  }
  if (typeof stats.isSymbolicLink === "function" && stats.isSymbolicLink()) {
    throw makeFailure("POLICY_PATH_OVERRIDE_FORBIDDEN", `${artifactName} path must not be a symlink in production`, {
      artifactPath: resolvedArtifactPath,
      requiredPath: resolvedRequiredPath,
    });
  }
  if (typeof stats.isFile === "function" && !stats.isFile()) {
    throw makeFailure("POLICY_FILE_NOT_PRESENT", `${artifactName} path must reference a regular file`, {
      artifactPath: resolvedArtifactPath,
      requiredPath: resolvedRequiredPath,
    });
  }
}

function verifyPolicySignature(options = {}) {
  const canonicalJson = normalizeString(options.canonicalJson);
  if (!canonicalJson) {
    return {
      ok: false,
      code: "POLICY_SIGNATURE_INVALID",
      message: "canonicalJson is required for signature verification",
    };
  }

  let signatureB64 = normalizeString(options.signature);
  if (!signatureB64) {
    const signaturePath = resolveSignaturePath(options);
    if (!fs.existsSync(signaturePath)) {
      return {
        ok: false,
        code: "POLICY_SIGNATURE_INVALID",
        message: "Policy signature file is missing",
        details: { signaturePath },
      };
    }
    signatureB64 = normalizeString(fs.readFileSync(signaturePath, "utf8"));
  }

  let publicKeyPem = normalizeString(options.publicKey);
  if (!publicKeyPem) {
    const publicKeyPath = resolvePublicKeyPath(options);
    if (!fs.existsSync(publicKeyPath)) {
      return {
        ok: false,
        code: "POLICY_SIGNATURE_INVALID",
        message: "Policy public key file is missing",
        details: { publicKeyPath },
      };
    }
    publicKeyPem = fs.readFileSync(publicKeyPath, "utf8");
  }

  try {
    const signature = Buffer.from(signatureB64, "base64");
    const verified = crypto.verify(
      null,
      Buffer.from(canonicalJson, "utf8"),
      crypto.createPublicKey(publicKeyPem),
      signature,
    );

    return verified
      ? { ok: true }
      : {
          ok: false,
          code: "POLICY_SIGNATURE_INVALID",
          message: "Policy signature verification failed",
        };
  } catch (error) {
    return {
      ok: false,
      code: "POLICY_SIGNATURE_INVALID",
      message: "Policy signature verification failed",
      details: {
        reason: error && error.message ? error.message : String(error),
      },
    };
  }
}

function loadAndPublishPolicy(options = {}) {
  const production = parseBoolean(options.production, normalizeString(process.env.NODE_ENV).toLowerCase() === "production");
  const allowLegacyNonProdFallback = options.allowLegacyNonProdFallback !== false;
  const nodeId = normalizeString(options.nodeId) || normalizeString(process.env.SUPERVISOR_NODE_ID) || "node-unknown";
  const metrics = createSafeMetrics(options.metrics);
  const auditLogger = createSafeAuditLogger(options.auditLogger || options.logger);

  const manifestPath = resolveManifestPath(options, production);
  const signaturePath = resolveSignaturePath(options, production);
  const publicKeyPath = resolvePublicKeyPath(options, production);
  const expectedHash = normalizeString(options.expectedHash || process.env.EXECUTION_POLICY_EXPECTED_HASH).toLowerCase();

  if (production && !shouldAllowProductionPathOverride(options)) {
    const defaults = getDefaultPolicyArtifactPaths();
    assertProductionArtifactPathSafety(manifestPath, defaults.manifestPath, "Policy manifest");
    assertProductionArtifactPathSafety(signaturePath, defaults.signaturePath, "Policy signature");
    assertProductionArtifactPathSafety(publicKeyPath, defaults.publicKeyPath, "Policy public key");
  }

  let rawPolicy = null;
  let source = "manifest";

  auditLogger.log({
    event: "policy_load",
    principal_id: "system",
    slug: "",
    request_id: "",
    status: "success",
    details: {
      node_id: nodeId,
      production,
      manifestPath,
    },
  });

  if (!manifestPath || !fs.existsSync(manifestPath)) {
    if (production) {
      throw makeFailure("POLICY_FILE_NOT_PRESENT", "Policy manifest file not present", {
        manifestPath,
      });
    }

    if (!allowLegacyNonProdFallback) {
      throw makeFailure("POLICY_FILE_NOT_PRESENT", "Policy manifest file not present", {
        manifestPath,
      });
    }

    source = "legacy_non_prod_fallback";
    rawPolicy = synthesizePolicyFromLegacy(options);
  } else {
    const manifestRaw = fs.readFileSync(manifestPath, "utf8");
    rawPolicy = JSON.parse(manifestRaw);
  }

  const validation = validatePolicySchema(rawPolicy);
  if (!validation.valid) {
    throw makeFailure("POLICY_SCHEMA_INVALID", "Policy schema validation failed", {
      errors: validation.errors,
      source,
      manifestPath,
    });
  }

  const canonicalJson = serializeCanonical(rawPolicy);
  const policyHash = computePolicyHash(rawPolicy);

  if (expectedHash && expectedHash !== policyHash) {
    throw makeFailure("POLICY_HASH_MISMATCH", "Policy hash mismatch", {
      expectedHash,
      actualHash: policyHash,
    });
  }

  const signatureRequired = production
    ? true
    : rawPolicy.signatureEnforcement && rawPolicy.signatureEnforcement.requireInNonProduction === true;

  let signatureVerified = false;
  if (signatureRequired || (signaturePath && fs.existsSync(signaturePath))) {
    const verification = verifyPolicySignature({
      ...options,
      canonicalJson,
      signaturePath,
      publicKeyPath,
    });

    if (!verification.ok) {
      metrics.increment("policy.signature.invalid", {
        node_id: nodeId,
      });
      auditLogger.log({
        event: "policy_signature_verification_failure",
        principal_id: "system",
        slug: "",
        request_id: "",
        status: "failure",
        details: {
          node_id: nodeId,
          code: verification.code,
          message: verification.message,
        },
      });
      if (production || signatureRequired) {
        throw makeFailure("POLICY_SIGNATURE_INVALID", verification.message || "Policy signature verification failed", {
          verification,
        });
      }
    } else {
      signatureVerified = true;
    }
  }

  const canonicalPolicy = deepFreeze(JSON.parse(canonicalJson));

  const bundle = deepFreeze({
    source,
    policy: canonicalPolicy,
    policyHash,
    policyVersion: canonicalPolicy.policyVersion,
    signatureVerified,
    loadedAt: Date.now(),
  });

  if (options.policyRuntime && typeof options.policyRuntime.activatePolicy === "function") {
    options.policyRuntime.activatePolicy(bundle);
  }

  activeAuthorityState = {
    source,
    policyHash,
    policyVersion: canonicalPolicy.policyVersion,
    signatureVerified,
    loadedAt: bundle.loadedAt,
    production,
    manifestPath,
  };

  metrics.increment("policy.activation", {
    node_id: nodeId,
    source,
  });
  metrics.gauge("policy.version.active", canonicalPolicy.policyVersion, {
    node_id: nodeId,
  });

  auditLogger.log({
    event: "policy_activation",
    principal_id: "system",
    slug: "",
    request_id: "",
    status: "success",
    details: {
      node_id: nodeId,
      source,
      policy_version: canonicalPolicy.policyVersion,
      policy_hash: policyHash,
      signature_verified: signatureVerified,
    },
  });

  return bundle;
}

function getActiveAuthorityState() {
  if (!activeAuthorityState) {
    return null;
  }

  return {
    ...activeAuthorityState,
  };
}

module.exports = {
  loadAndPublishPolicy,
  verifyPolicySignature,
  getActiveAuthorityState,
  getDefaultPolicyArtifactPaths,
};
