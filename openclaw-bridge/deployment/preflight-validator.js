const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const { createVersionGuard } = require("./version-guard.js");
const { validateSandboxConfig } = require("../execution/sandbox-policy.js");
const { resolveResourceLimits } = require("../execution/resource-policy.js");
const { validateEgressPolicy } = require("../execution/egress-policy.js");
const { validateImageReference } = require("../execution/image-policy.js");
const { SUPPORTED_BACKENDS } = require("../execution/container-runtime.js");
const { resolveToolImageReference: resolveCatalogImageReference } = require("../execution/tool-image-catalog.js");
const { validatePolicySchema, serializeCanonical, computePolicyHash } = require("../policy/execution-policy-manifest.js");
const { verifyPolicySignature, getDefaultPolicyArtifactPaths } = require("../policy/policy-authority.js");
const {
  validateSecretSchema,
  getCanonicalSecretManifest,
  computeSecretManifestHash,
} = require("../security/secret-manifest.js");
const { createSecretAuthority, resolveDefaultSecretManifestPath } = require("../security/secret-authority.js");
const {
  validateWorkloadManifest,
  getCanonicalWorkloadManifest,
  computeWorkloadManifestHash,
  resolveDefaultWorkloadManifestPath,
} = require("../security/workload-manifest.js");
const {
  computeAttestationReferenceHash,
  loadAttestationReferenceFromDisk,
  resolveDefaultAttestationReferencePath,
} = require("../security/workload-attestation.js");
const {
  computeBuildProvenanceHash,
  loadBuildProvenanceFromDisk,
  resolveDefaultBuildProvenanceHashPath,
  resolveDefaultBuildProvenancePath,
  resolveDefaultBuildProvenancePublicKeyPath,
  resolveDefaultDependencyLockPath,
} = require("../security/workload-provenance.js");
const {
  loadOffensiveManifestFromDisk,
  resolveDefaultOffensiveManifestHashPath,
  resolveDefaultOffensiveManifestPath,
  resolveDefaultOffensiveManifestPublicKeyPath,
  resolveDefaultOffensiveManifestSignaturePath,
} = require("../security/offensive-workload-manifest.js");
const { createToolRegistry } = require("../tools/tool-registry.js");
const { registerBatch1Tools } = require("../tools/adapters/index.js");
const { registerBatch2Tools } = require("../tools/adapters/batch-2-index.js");
const { registerBatch3Tools } = require("../tools/adapters/batch-3-index.js");
const { createSpawnerV2 } = require("../spawner/spawner-v2.js");

const PARTITION_CONTAINMENT_METRICS = [
  "cluster.partition_state",
  "cluster.partition_detected",
  "cluster.partition_recovered",
  "cluster.convergence_delay_active",
];

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

function parsePositiveInt(value) {
  const parsed = Number.parseInt(String(value ?? "").trim(), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return null;
  }
  return parsed;
}

function normalizeString(value) {
  return typeof value === "string" ? value.trim() : "";
}

function isTruthyFlag(value) {
  if (typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    return value !== 0;
  }
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    return normalized !== "" && normalized !== "0" && normalized !== "false" && normalized !== "no";
  }
  return false;
}

function resolveProductionMode(options, cliEnv) {
  const optionEnv = normalizeString(options && options.env);
  const envVar = normalizeString(process.env.NODE_ENV);

  const resolved = cliEnv || optionEnv || envVar;
  return {
    mode: resolved || "development",
    isProduction: resolved === "production",
    source: cliEnv ? "cli" : optionEnv ? "options" : envVar ? "NODE_ENV" : "default",
  };
}

function resolvePath(inputPath) {
  if (!inputPath) {
    return "";
  }
  return path.resolve(String(inputPath));
}

function getManifest(options) {
  if (options && options.manifest && typeof options.manifest === "object") {
    return options.manifest;
  }
  if (options && options.deploymentManifest && typeof options.deploymentManifest === "object") {
    return options.deploymentManifest;
  }
  return {};
}

function resolveExpectedNodeCount(options, manifest) {
  const optionValue = parsePositiveInt(options && options.topology && options.topology.expectedNodeCount);
  if (optionValue) {
    return { value: optionValue, source: "options.topology.expectedNodeCount" };
  }

  const envValue = parsePositiveInt(process.env.TOPOLOGY_EXPECTED_NODE_COUNT);
  if (envValue) {
    return { value: envValue, source: "TOPOLOGY_EXPECTED_NODE_COUNT" };
  }

  const manifestValue = parsePositiveInt(manifest && manifest.topology && manifest.topology.expectedNodeCount);
  if (manifestValue) {
    return { value: manifestValue, source: "manifest.topology.expectedNodeCount" };
  }

  return { value: null, source: "unset" };
}

function resolveControlPlanePhase(options, manifest) {
  const optionValue = parsePositiveInt(options && options.cluster && options.cluster.controlPlanePhase);
  if (optionValue) {
    return { value: optionValue, source: "options.cluster.controlPlanePhase" };
  }

  const envValue = parsePositiveInt(process.env.CLUSTER_CONTROL_PLANE_PHASE);
  if (envValue) {
    return { value: envValue, source: "CLUSTER_CONTROL_PLANE_PHASE" };
  }

  const manifestValue = parsePositiveInt(manifest && manifest.cluster && manifest.cluster.controlPlanePhase);
  if (manifestValue) {
    return { value: manifestValue, source: "manifest.cluster.controlPlanePhase" };
  }

  return { value: null, source: "unset" };
}

function parseVersionTargets(raw) {
  if (Array.isArray(raw)) {
    return raw.map((item) => normalizeString(item)).filter(Boolean);
  }

  if (typeof raw === "string") {
    return raw
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
  }

  return [];
}

function resolveVersionTargets(options, manifest) {
  const optionTargets = parseVersionTargets(options && options.deployment && options.deployment.versionTargets);
  if (optionTargets.length > 0) {
    return { values: optionTargets, source: "options.deployment.versionTargets" };
  }

  const envTargets = parseVersionTargets(process.env.DEPLOYMENT_VERSION_TARGETS);
  if (envTargets.length > 0) {
    return { values: envTargets, source: "DEPLOYMENT_VERSION_TARGETS" };
  }

  const manifestTargets = parseVersionTargets(manifest && manifest.deployment && manifest.deployment.versionTargets);
  if (manifestTargets.length > 0) {
    return { values: manifestTargets, source: "manifest.deployment.versionTargets" };
  }

  return { values: [], source: "unset" };
}

function resolveSoftwareVersion(options) {
  const optionDeploymentVersion = normalizeString(options && options.deployment && options.deployment.softwareVersion);
  if (optionDeploymentVersion) {
    return { value: optionDeploymentVersion, source: "options.deployment.softwareVersion" };
  }

  const optionVersion = normalizeString(options && options.softwareVersion);
  if (optionVersion) {
    return { value: optionVersion, source: "options.softwareVersion" };
  }

  const envVersion = normalizeString(process.env.SUPERVISOR_SOFTWARE_VERSION);
  if (envVersion) {
    return { value: envVersion, source: "SUPERVISOR_SOFTWARE_VERSION" };
  }

  try {
    const packagePath = path.resolve(__dirname, "..", "package.json");
    const raw = fs.readFileSync(packagePath, "utf8");
    const parsed = JSON.parse(raw);
    const packageVersion = normalizeString(parsed && parsed.version);
    if (packageVersion) {
      return { value: packageVersion, source: "package.json" };
    }
  } catch {}

  return { value: "", source: "unset" };
}

function resolveClusterEnabled(options) {
  if (options && options.cluster && Object.prototype.hasOwnProperty.call(options.cluster, "enabled")) {
    return parseBoolean(options.cluster.enabled, false);
  }
  return parseBoolean(process.env.CLUSTER_ENABLED, false);
}

function resolveFederationEnabled(options) {
  if (options && options.federation && Object.prototype.hasOwnProperty.call(options.federation, "enabled")) {
    return parseBoolean(options.federation.enabled, false);
  }
  return parseBoolean(process.env.FEDERATION_ENABLED, false);
}

function resolvePartitionContainmentEnabled(options) {
  if (options && options.cluster && Object.prototype.hasOwnProperty.call(options.cluster, "partitionContainmentEnabled")) {
    return parseBoolean(options.cluster.partitionContainmentEnabled, false);
  }
  return parseBoolean(process.env.CLUSTER_PARTITION_CONTAINMENT_ENABLED, false);
}

function resolveClusterCapabilities(options, manifest) {
  const optionCapabilities =
    options && options.clusterCapabilities && typeof options.clusterCapabilities === "object" ? options.clusterCapabilities : null;
  if (optionCapabilities) {
    return optionCapabilities;
  }

  const nestedOptionCapabilities =
    options && options.cluster && options.cluster.capabilities && typeof options.cluster.capabilities === "object"
      ? options.cluster.capabilities
      : null;
  if (nestedOptionCapabilities) {
    return nestedOptionCapabilities;
  }

  const manifestCapabilities =
    manifest && manifest.clusterCapabilities && typeof manifest.clusterCapabilities === "object"
      ? manifest.clusterCapabilities
      : null;

  return manifestCapabilities || {};
}

function resolveNodeId(options) {
  const optionNodeId = normalizeString(options && options.cluster && options.cluster.nodeId);
  if (optionNodeId) {
    return optionNodeId;
  }

  const fallbackNodeId = normalizeString(options && options.nodeId);
  if (fallbackNodeId) {
    return fallbackNodeId;
  }

  return normalizeString(process.env.SUPERVISOR_NODE_ID);
}

function resolveClusterStatePathTemplate(options) {
  const optionPath = normalizeString(options && options.state && options.state.clusterManagerStatePath);
  if (optionPath) {
    return optionPath;
  }

  const fallbackPath = normalizeString(options && options.clusterManagerStatePath);
  if (fallbackPath) {
    return fallbackPath;
  }

  const envPath = normalizeString(process.env.CLUSTER_MANAGER_STATE_PATH);
  if (envPath) {
    return envPath;
  }

  return "./data/cluster-manager-state-{nodeId}.json";
}

function resolveClusterConfig(options) {
  const cluster = options && options.cluster && typeof options.cluster === "object" ? options.cluster : {};
  const shardCount = parsePositiveInt(cluster.shardCount || process.env.CLUSTER_SHARD_COUNT);
  const heartbeatIntervalMs = parsePositiveInt(cluster.heartbeatIntervalMs || process.env.CLUSTER_HEARTBEAT_INTERVAL_MS);
  const leaderTimeoutMs = parsePositiveInt(cluster.leaderTimeoutMs || process.env.CLUSTER_LEADER_TIMEOUT_MS);
  return {
    shardCount,
    heartbeatIntervalMs,
    leaderTimeoutMs,
  };
}

function resolveTlsConfig(options) {
  const tls = options && options.tls && typeof options.tls === "object" ? options.tls : {};
  const httpEnabled = parseBoolean(
    (options && options.http && options.http.enabled) || options.httpEnabled || process.env.HTTP_ENABLED,
    false,
  );
  const tlsEnabled = parseBoolean(tls.enabled, parseBoolean(process.env.TLS_ENABLED, false));
  const certPath = normalizeString(tls.certPath || process.env.TLS_CERT_PATH);
  const keyPath = normalizeString(tls.keyPath || process.env.TLS_KEY_PATH);
  const mtlsEnabled = parseBoolean(tls.mtlsEnabled, parseBoolean(process.env.MTLS_ENABLED, false));
  const caPath = normalizeString(tls.caPath || process.env.MTLS_CA_PATH);

  return {
    httpEnabled,
    tlsEnabled,
    certPath,
    keyPath,
    mtlsEnabled,
    caPath,
  };
}

function normalizeMode(value) {
  return normalizeString(value).toLowerCase();
}

function resolveExecutionMode(options, manifest) {
  const optionMode = normalizeMode(options && options.execution && options.execution.executionMode);
  if (optionMode) {
    return { value: optionMode, source: "options.execution.executionMode" };
  }

  const envMode = normalizeMode(process.env.TOOL_EXECUTION_MODE);
  if (envMode) {
    return { value: envMode, source: "TOOL_EXECUTION_MODE" };
  }

  const manifestMode = normalizeMode(manifest && manifest.execution && manifest.execution.executionMode);
  if (manifestMode) {
    return { value: manifestMode, source: "manifest.execution.executionMode" };
  }

  return { value: "", source: "unset" };
}

function resolveExecutionBackend(options, manifest) {
  const optionBackend = normalizeMode(options && options.execution && options.execution.backend);
  if (optionBackend) {
    return { value: optionBackend, source: "options.execution.backend" };
  }

  const envBackend = normalizeMode(process.env.CONTAINER_RUNTIME_BACKEND);
  if (envBackend) {
    return { value: envBackend, source: "CONTAINER_RUNTIME_BACKEND" };
  }

  const manifestBackend = normalizeMode(manifest && manifest.execution && manifest.execution.backend);
  if (manifestBackend) {
    return { value: manifestBackend, source: "manifest.execution.backend" };
  }

  return { value: "mock", source: "default" };
}

function resolveExecutionContainerRuntimeEnabled(options, manifest) {
  const optionExecution = options && options.execution && typeof options.execution === "object" ? options.execution : {};
  if (Object.prototype.hasOwnProperty.call(optionExecution, "containerRuntimeEnabled")) {
    return {
      value: optionExecution.containerRuntimeEnabled === true,
      source: "options.execution.containerRuntimeEnabled",
    };
  }

  if (typeof process.env.CONTAINER_RUNTIME_ENABLED !== "undefined") {
    return {
      value: parseBoolean(process.env.CONTAINER_RUNTIME_ENABLED, false),
      source: "CONTAINER_RUNTIME_ENABLED",
    };
  }

  const manifestExecution = manifest && manifest.execution && typeof manifest.execution === "object" ? manifest.execution : {};
  if (Object.prototype.hasOwnProperty.call(manifestExecution, "containerRuntimeEnabled")) {
    return {
      value: manifestExecution.containerRuntimeEnabled === true,
      source: "manifest.execution.containerRuntimeEnabled",
    };
  }

  return {
    value: false,
    source: "default",
  };
}

function extractConfiguredToolAdapterSlugs(toolAdapters) {
  const slugs = new Set();
  if (Array.isArray(toolAdapters)) {
    for (const item of toolAdapters) {
      if (!item || typeof item !== "object") {
        continue;
      }
      const slug = normalizeString(item.slug).toLowerCase();
      if (slug) {
        slugs.add(slug);
      }
    }
    return slugs;
  }

  if (toolAdapters && typeof toolAdapters === "object") {
    for (const key of Object.keys(toolAdapters)) {
      const slug = normalizeString(key).toLowerCase();
      if (slug) {
        slugs.add(slug);
      }
    }
  }

  return slugs;
}

function resolveAuthoritativeToolSlugs(options) {
  if (options && options.toolRegistry && typeof options.toolRegistry.list === "function") {
    const listed = options.toolRegistry.list();
    const set = new Set();
    for (const item of listed) {
      if (!item || typeof item !== "object") {
        continue;
      }
      const slug = normalizeString(item.slug).toLowerCase();
      if (slug) {
        set.add(slug);
      }
    }
    return set;
  }

  const registry = createToolRegistry({ strict: false });
  registerBatch1Tools(registry);
  registerBatch2Tools(registry);
  registerBatch3Tools(registry);
  const configured = extractConfiguredToolAdapterSlugs(options && options.toolAdapters);
  for (const slug of configured) {
    if (!registry.has(slug)) {
      registry.register(slug, {
        name: slug,
        slug,
        description: "Configured external adapter",
        execute: async () => ({ ok: true }),
        validateInput: async () => ({ valid: true }),
        normalizeOutput: async (output) => output,
        getResourceLimits: () => ({ timeoutMs: 1000, memoryMb: 64, maxOutputBytes: 1024 }),
      });
    }
  }

  const set = new Set();
  for (const item of registry.list()) {
    const slug = normalizeString(item.slug).toLowerCase();
    if (slug) {
      set.add(slug);
    }
  }

  const skillConfig = options && options.skillConfig && typeof options.skillConfig === "object" ? options.skillConfig : {};
  for (const slug of Object.keys(skillConfig)) {
    const normalized = normalizeString(slug).toLowerCase();
    if (normalized) {
      set.add(normalized);
    }
  }

  try {
    const spawnerConstants = createSpawnerV2().constants;
    if (spawnerConstants && spawnerConstants.IMAGE_ALLOWLIST && typeof spawnerConstants.IMAGE_ALLOWLIST === "object") {
      for (const slug of Object.keys(spawnerConstants.IMAGE_ALLOWLIST)) {
        const normalized = normalizeString(slug).toLowerCase();
        if (normalized) {
          set.add(normalized);
        }
      }
    }
  } catch {}

  return set;
}

function normalizeToolConfigMap(input) {
  if (Array.isArray(input)) {
    const map = {};
    for (const item of input) {
      const slug = normalizeString(item).toLowerCase();
      if (slug) {
        map[slug] = {};
      }
    }
    return map;
  }

  if (input && typeof input === "object") {
    const map = {};
    for (const key of Object.keys(input)) {
      const slug = normalizeString(key).toLowerCase();
      if (!slug) {
        continue;
      }
      const value = input[key];
      map[slug] = value && typeof value === "object" ? value : {};
    }
    return map;
  }

  return {};
}

function resolveExecutionConfig(options, manifest) {
  const manifestExecution = manifest && manifest.execution && typeof manifest.execution === "object" ? manifest.execution : {};
  const optionExecution = options && options.execution && typeof options.execution === "object" ? options.execution : {};

  const merged = {
    ...manifestExecution,
    ...optionExecution,
    tools: {
      ...normalizeToolConfigMap(manifestExecution.tools),
      ...normalizeToolConfigMap(optionExecution.tools),
    },
    resourcePolicies: {
      ...(manifestExecution.resourcePolicies && typeof manifestExecution.resourcePolicies === "object"
        ? manifestExecution.resourcePolicies
        : {}),
      ...(optionExecution.resourcePolicies && typeof optionExecution.resourcePolicies === "object"
        ? optionExecution.resourcePolicies
        : {}),
    },
    sandboxPolicies: {
      ...(manifestExecution.sandboxPolicies && typeof manifestExecution.sandboxPolicies === "object"
        ? manifestExecution.sandboxPolicies
        : {}),
      ...(optionExecution.sandboxPolicies && typeof optionExecution.sandboxPolicies === "object"
        ? optionExecution.sandboxPolicies
        : {}),
    },
    egressPolicies: {
      ...(manifestExecution.egressPolicies && typeof manifestExecution.egressPolicies === "object"
        ? manifestExecution.egressPolicies
        : {}),
      ...(optionExecution.egressPolicies && typeof optionExecution.egressPolicies === "object"
        ? optionExecution.egressPolicies
        : {}),
    },
    imagePolicies: {
      ...(manifestExecution.imagePolicies && typeof manifestExecution.imagePolicies === "object"
        ? manifestExecution.imagePolicies
        : {}),
      ...(optionExecution.imagePolicies && typeof optionExecution.imagePolicies === "object"
        ? optionExecution.imagePolicies
        : {}),
    },
    images: {
      ...(manifestExecution.images && typeof manifestExecution.images === "object" ? manifestExecution.images : {}),
      ...(optionExecution.images && typeof optionExecution.images === "object" ? optionExecution.images : {}),
    },
  };

  return merged;
}

function resolveSecurityConfig(options, manifest) {
  const manifestSecurity = manifest && manifest.security && typeof manifest.security === "object" ? manifest.security : {};
  const optionSecurity = options && options.security && typeof options.security === "object" ? options.security : {};
  return {
    ...manifestSecurity,
    ...optionSecurity,
  };
}

function resolveObservabilityConfig(options, manifest) {
  const manifestObservability =
    manifest && manifest.observability && typeof manifest.observability === "object" ? manifest.observability : {};
  const optionObservability =
    options && options.observability && typeof options.observability === "object" ? options.observability : {};
  const alertThresholds = {
    ...(manifestObservability.alertThresholds && typeof manifestObservability.alertThresholds === "object"
      ? manifestObservability.alertThresholds
      : {}),
    ...(optionObservability.alertThresholds && typeof optionObservability.alertThresholds === "object"
      ? optionObservability.alertThresholds
      : {}),
  };
  return {
    ...manifestObservability,
    ...optionObservability,
    alertThresholds,
  };
}

function validateToolConcurrencyMap(rawValue, label) {
  if (!rawValue || typeof rawValue !== "object" || Array.isArray(rawValue)) {
    return {
      valid: false,
      errors: [`${label} must be an object`],
    };
  }

  const errors = [];
  for (const [toolSlug, rawLimit] of Object.entries(rawValue)) {
    const slug = normalizeString(toolSlug).toLowerCase();
    if (!slug) {
      errors.push(`${label} contains an empty tool slug`);
      continue;
    }
    if (!Number.isFinite(Number(rawLimit)) || !Number.isInteger(Number(rawLimit)) || Number(rawLimit) <= 0) {
      errors.push(`${label}.${slug} must be a positive integer`);
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

function validatePhase21ExecutionConfig(executionConfig, errors, warnings, isProduction, mode) {
  if (mode !== "container") {
    return;
  }

  const maxConcurrentContainersPerNode = parsePositiveInt(executionConfig.maxConcurrentContainersPerNode);
  if (!maxConcurrentContainersPerNode) {
    addIssue(errors, "EXECUTION_NODE_CONCURRENCY_CAP_REQUIRED", "execution.maxConcurrentContainersPerNode is required", {});
  }

  const nodeMemoryHardCapMb = parsePositiveInt(executionConfig.nodeMemoryHardCapMb);
  if (!nodeMemoryHardCapMb) {
    addIssue(errors, "EXECUTION_NODE_MEMORY_CAP_REQUIRED", "execution.nodeMemoryHardCapMb is required", {});
  }

  const nodeCpuHardCapShares = parsePositiveInt(executionConfig.nodeCpuHardCapShares);
  if (!nodeCpuHardCapShares) {
    addIssue(errors, "EXECUTION_NODE_CPU_CAP_REQUIRED", "execution.nodeCpuHardCapShares is required", {});
  }

  const toolConcurrencyValidation = validateToolConcurrencyMap(
    executionConfig.toolConcurrencyLimits,
    "execution.toolConcurrencyLimits",
  );
  if (!toolConcurrencyValidation.valid) {
    addIssue(errors, "EXECUTION_TOOL_CONCURRENCY_LIMITS_INVALID", "execution.toolConcurrencyLimits is invalid", {
      errors: toolConcurrencyValidation.errors,
    });
  }

  const configVersion = normalizeString(executionConfig.configVersion);
  const expectedExecutionConfigVersion = normalizeString(executionConfig.expectedExecutionConfigVersion);
  const rollingUpgradeWindowMinutes = parsePositiveInt(executionConfig.rollingUpgradeWindowMinutes);
  const rolloutWindowStartedAt = normalizeString(executionConfig.rolloutWindowStartedAt);
  const allowedConfigHashesByVersion =
    executionConfig.allowedConfigHashesByVersion && typeof executionConfig.allowedConfigHashesByVersion === "object"
      ? executionConfig.allowedConfigHashesByVersion
      : {};

  if (isProduction && !configVersion) {
    addIssue(errors, "EXECUTION_CONFIG_VERSION_REQUIRED", "execution.configVersion is required in production container mode", {});
  }

  if (isProduction && !expectedExecutionConfigVersion) {
    addIssue(
      errors,
      "EXPECTED_EXECUTION_CONFIG_VERSION_REQUIRED",
      "execution.expectedExecutionConfigVersion is required in production container mode",
      {},
    );
  }

  if (isProduction && !rollingUpgradeWindowMinutes) {
    addIssue(
      errors,
      "EXECUTION_ROLLING_UPGRADE_WINDOW_REQUIRED",
      "execution.rollingUpgradeWindowMinutes must be a positive integer in production",
      {},
    );
  }

  if (rollingUpgradeWindowMinutes && !rolloutWindowStartedAt) {
    addIssue(errors, "EXECUTION_ROLLOUT_WINDOW_STARTED_AT_REQUIRED", "execution.rolloutWindowStartedAt is required", {});
  }

  const allowedVersions = Object.keys(allowedConfigHashesByVersion || {});
  if (isProduction && allowedVersions.length === 0) {
    addIssue(
      errors,
      "EXECUTION_ALLOWED_CONFIG_HASHES_REQUIRED",
      "execution.allowedConfigHashesByVersion must include at least one version entry in production",
      {},
    );
  }

  for (const version of allowedVersions) {
    const hashes = Array.isArray(allowedConfigHashesByVersion[version]) ? allowedConfigHashesByVersion[version] : [];
    if (hashes.length === 0) {
      addIssue(errors, "EXECUTION_ALLOWED_CONFIG_HASHES_INVALID", "allowed hash list must not be empty", {
        version,
      });
      continue;
    }
    for (const hash of hashes) {
      const normalized = normalizeString(hash).toLowerCase();
      if (!/^[a-f0-9]{64}$/.test(normalized)) {
        addIssue(errors, "EXECUTION_ALLOWED_CONFIG_HASHES_INVALID", "allowed config hash must be a sha256 hex digest", {
          version,
          hash,
        });
      }
    }
  }

  if (!isProduction && thresholdWarningNeeded(executionConfig)) {
    addIssue(
      warnings,
      "EXECUTION_PHASE21_CONFIG_INCOMPLETE_NON_PROD",
      "Phase 21 execution config is partially configured in non-production mode",
      {},
    );
  }
}

function thresholdWarningNeeded(executionConfig) {
  const requiredKeys = [
    "maxConcurrentContainersPerNode",
    "nodeMemoryHardCapMb",
    "nodeCpuHardCapShares",
    "toolConcurrencyLimits",
  ];
  return requiredKeys.some((key) => !Object.prototype.hasOwnProperty.call(executionConfig || {}, key));
}

function validatePhase21SecurityConfig(securityConfig, errors, isProduction, mode) {
  if (mode !== "container") {
    return;
  }

  const executionQuotaPerHour = parsePositiveInt(securityConfig.executionQuotaPerHour) || 0;
  const executionBurstLimitPerMinute = parsePositiveInt(securityConfig.executionBurstLimitPerMinute) || 0;
  const quotaRedisUrl = normalizeString(securityConfig.quotaRedisUrl);

  if (executionQuotaPerHour <= 0) {
    addIssue(errors, "EXECUTION_QUOTA_PER_HOUR_REQUIRED", "security.executionQuotaPerHour must be > 0", {});
  }

  if (executionBurstLimitPerMinute <= 0) {
    addIssue(errors, "EXECUTION_BURST_LIMIT_PER_MINUTE_REQUIRED", "security.executionBurstLimitPerMinute must be > 0", {});
  }

  if (isProduction && (!quotaRedisUrl || !/^redis(s)?:\/\//i.test(quotaRedisUrl))) {
    addIssue(errors, "EXECUTION_QUOTA_REDIS_URL_REQUIRED", "security.quotaRedisUrl must be set to a redis URL in production", {});
  }
}

function validatePhase21ObservabilityConfig(observabilityConfig, errors, warnings, isProduction) {
  const thresholdScope = normalizeString(observabilityConfig.thresholdScope).toLowerCase();
  const alertThresholds =
    observabilityConfig.alertThresholds && typeof observabilityConfig.alertThresholds === "object"
      ? observabilityConfig.alertThresholds
      : {};

  if (!thresholdScope) {
    addIssue(errors, "OBSERVABILITY_THRESHOLD_SCOPE_REQUIRED", "observability.thresholdScope is required", {});
  } else if (thresholdScope !== "node") {
    const collection = isProduction ? errors : warnings;
    addIssue(
      collection,
      "OBSERVABILITY_THRESHOLD_SCOPE_INVALID",
      "Phase 21 requires observability.thresholdScope='node'",
      {
        thresholdScope,
      },
    );
  }

  const requiredThresholds = ["circuitOpenRate", "executionRejectRate", "memoryPressureRate"];
  for (const key of requiredThresholds) {
    const rawValue = alertThresholds[key];
    const value = Number(rawValue);
    if (!Number.isFinite(value) || value < 0) {
      addIssue(errors, "OBSERVABILITY_ALERT_THRESHOLDS_INVALID", "observability.alertThresholds entry is invalid", {
        key,
        value: rawValue,
      });
    }
  }
}

function validatePhase22PolicyGovernance(executionConfig, errors, warnings, isProduction, mode) {
  if (mode !== "container") {
    return;
  }

  const defaultPolicyPaths = getDefaultPolicyArtifactPaths();
  const configuredManifestPath = normalizeString(executionConfig.policyManifestPath || process.env.EXECUTION_POLICY_MANIFEST_PATH);
  const configuredSignaturePath = normalizeString(executionConfig.policySignaturePath || process.env.EXECUTION_POLICY_SIGNATURE_PATH);
  const configuredPublicKeyPath = normalizeString(executionConfig.policyPublicKeyPath || process.env.EXECUTION_POLICY_PUBLIC_KEY_PATH);
  const expectedHash = normalizeString(executionConfig.policyExpectedHash || process.env.EXECUTION_POLICY_EXPECTED_HASH).toLowerCase();
  const manifestPath = isProduction ? defaultPolicyPaths.manifestPath : configuredManifestPath;
  const signaturePath = isProduction ? defaultPolicyPaths.signaturePath : configuredSignaturePath;
  const publicKeyPath = isProduction ? defaultPolicyPaths.publicKeyPath : configuredPublicKeyPath;

  const collection = isProduction ? errors : warnings;

  if (isProduction) {
    const overrideChecks = [
      {
        label: "execution.policyManifestPath",
        configuredPath: configuredManifestPath,
        requiredPath: defaultPolicyPaths.manifestPath,
      },
      {
        label: "execution.policySignaturePath",
        configuredPath: configuredSignaturePath,
        requiredPath: defaultPolicyPaths.signaturePath,
      },
      {
        label: "execution.policyPublicKeyPath",
        configuredPath: configuredPublicKeyPath,
        requiredPath: defaultPolicyPaths.publicKeyPath,
      },
    ];
    for (const check of overrideChecks) {
      if (!check.configuredPath) {
        continue;
      }
      if (resolvePath(check.configuredPath) !== resolvePath(check.requiredPath)) {
        addIssue(errors, "POLICY_PATH_OVERRIDE_FORBIDDEN", "Policy artifact path override is forbidden in production", {
          field: check.label,
          configuredPath: resolvePath(check.configuredPath),
          requiredPath: resolvePath(check.requiredPath),
        });
      }
    }
  }

  if (!manifestPath) {
    addIssue(collection, "POLICY_FILE_NOT_PRESENT", "execution.policyManifestPath is required for policy governance", {});
    return;
  }

  const resolvedManifestPath = resolvePath(manifestPath);
  if (!fs.existsSync(resolvedManifestPath)) {
    addIssue(collection, "POLICY_FILE_NOT_PRESENT", "Policy manifest file is missing", {
      manifestPath: resolvedManifestPath,
    });
    return;
  }

  if (isProduction) {
    if (!signaturePath || !publicKeyPath) {
      addIssue(errors, "POLICY_SIGNATURE_INVALID", "Policy signature and public key paths are required in production", {
        signaturePath,
        publicKeyPath,
      });
      return;
    }
    if (!expectedHash) {
      addIssue(errors, "POLICY_HASH_MISMATCH", "execution.policyExpectedHash is required in production", {});
      return;
    }
  }

  let policy;
  try {
    policy = JSON.parse(fs.readFileSync(resolvedManifestPath, "utf8"));
  } catch (error) {
    addIssue(collection, "POLICY_SCHEMA_INVALID", "Policy manifest JSON could not be parsed", {
      manifestPath: resolvedManifestPath,
      reason: error && error.message ? error.message : String(error),
    });
    return;
  }

  const schemaValidation = validatePolicySchema(policy);
  if (!schemaValidation.valid) {
    addIssue(collection, "POLICY_SCHEMA_INVALID", "Policy schema validation failed", {
      errors: schemaValidation.errors,
    });
    return;
  }

  let canonical;
  let actualHash;
  try {
    canonical = serializeCanonical(policy);
    actualHash = computePolicyHash(policy);
  } catch (error) {
    addIssue(collection, "POLICY_SCHEMA_INVALID", "Policy canonicalization failed", {
      reason: error && error.message ? error.message : String(error),
    });
    return;
  }

  if (expectedHash && expectedHash !== actualHash) {
    addIssue(collection, "POLICY_HASH_MISMATCH", "Policy hash does not match execution.policyExpectedHash", {
      expectedHash,
      actualHash,
    });
  }

  if (signaturePath || publicKeyPath || isProduction) {
    const verification = verifyPolicySignature({
      canonicalJson: canonical,
      signaturePath: signaturePath ? resolvePath(signaturePath) : "",
      publicKeyPath: publicKeyPath ? resolvePath(publicKeyPath) : "",
    });
    if (!verification.ok) {
      addIssue(collection, "POLICY_SIGNATURE_INVALID", "Policy signature verification failed", {
        code: verification.code,
        message: verification.message,
        details: verification.details || {},
      });
    }
  }
}

async function validatePhase23SecretGovernance(executionConfig, securityConfig, errors, warnings, isProduction, mode) {
  if (mode !== "container") {
    return;
  }

  const defaultManifestPath = resolveDefaultSecretManifestPath();
  const configuredManifestPath = normalizeString(executionConfig.secretManifestPath || process.env.SECRET_MANIFEST_PATH);
  const expectedManifestHash = normalizeString(
    executionConfig.secretManifestExpectedHash || process.env.SECRET_MANIFEST_EXPECTED_HASH,
  ).toLowerCase();
  const manifestPath = isProduction
    ? defaultManifestPath
    : configuredManifestPath
    ? configuredManifestPath
    : defaultManifestPath;

  const collection = isProduction ? errors : warnings;

  if (isProduction) {
    if (configuredManifestPath && resolvePath(configuredManifestPath) !== resolvePath(defaultManifestPath)) {
      addIssue(errors, "SECRET_MANIFEST_PATH_OVERRIDE_FORBIDDEN", "Secret manifest path override is forbidden in production", {
        configuredPath: resolvePath(configuredManifestPath),
        requiredPath: resolvePath(defaultManifestPath),
      });
    }
    if (!expectedManifestHash) {
      addIssue(errors, "SECRET_MANIFEST_MISMATCH", "execution.secretManifestExpectedHash is required in production", {});
    }
    if (securityConfig && securityConfig.allowEnvSecretFallbackNonProd === true) {
      addIssue(errors, "SECRET_ENV_FALLBACK_FORBIDDEN_PROD", "Environment fallback for secret fetch is forbidden in production", {});
    }
  }

  if (!manifestPath) {
    addIssue(collection, "SECRET_MANIFEST_MISSING", "execution.secretManifestPath is required for secret governance", {});
    return;
  }

  const resolvedManifestPath = resolvePath(manifestPath);
  if (!fs.existsSync(resolvedManifestPath)) {
    addIssue(collection, "SECRET_MANIFEST_MISSING", "Secret manifest file is missing", {
      manifestPath: resolvedManifestPath,
    });
    return;
  }

  let secretManifest;
  try {
    secretManifest = JSON.parse(fs.readFileSync(resolvedManifestPath, "utf8"));
  } catch (error) {
    addIssue(collection, "SECRET_MANIFEST_INVALID", "Secret manifest JSON could not be parsed", {
      manifestPath: resolvedManifestPath,
      reason: error && error.message ? error.message : String(error),
    });
    return;
  }

  const schemaValidation = validateSecretSchema(secretManifest);
  if (!schemaValidation.valid) {
    addIssue(collection, "SECRET_MANIFEST_INVALID", "Secret manifest schema validation failed", {
      errors: schemaValidation.errors,
    });
    return;
  }

  let actualHash = "";
  try {
    const canonical = getCanonicalSecretManifest(secretManifest);
    actualHash = computeSecretManifestHash(canonical);
  } catch (error) {
    addIssue(collection, "SECRET_MANIFEST_INVALID", "Secret manifest canonicalization failed", {
      reason: error && error.message ? error.message : String(error),
    });
    return;
  }

  if (expectedManifestHash && expectedManifestHash !== actualHash) {
    addIssue(collection, "SECRET_MANIFEST_MISMATCH", "Secret manifest hash does not match expected hash", {
      expectedHash: expectedManifestHash,
      actualHash,
    });
  }

  let authority = null;
  try {
    authority = createSecretAuthority({
      production: isProduction,
      nodeId: "preflight",
      manifestPath: resolvedManifestPath,
      expectedHash: expectedManifestHash,
      provider: normalizeString(securityConfig && securityConfig.secretStoreProvider) || "redis",
      secretProvider: securityConfig && securityConfig.secretStoreProviderImpl,
      secretStoreUrl: normalizeString(securityConfig && securityConfig.secretStoreUrl),
      secretStorePrefix: normalizeString(securityConfig && securityConfig.secretStorePrefix),
      secretStoreConnectTimeoutMs: parsePositiveInt(
        securityConfig && securityConfig.secretStoreConnectTimeoutMs,
      ) || 3000,
      fetchTimeoutMs: parsePositiveInt(securityConfig && securityConfig.secretFetchTimeoutMs) || 3000,
      fetchMaxAttempts: parsePositiveInt(securityConfig && securityConfig.secretFetchMaxAttempts) || 2,
      allowEnvFallbackNonProd: securityConfig && securityConfig.allowEnvSecretFallbackNonProd === true,
      allowProductionPathOverride: false,
    });
    await authority.initialize();
  } catch (error) {
    addIssue(
      collection,
      error && typeof error.code === "string" ? error.code : "SECRET_AUTHORITY_UNINITIALIZED",
      "Secret authority initialization failed",
      {
        reason: error && error.message ? error.message : String(error),
      },
    );
  } finally {
    if (authority && typeof authority.close === "function") {
      try {
        await authority.close();
      } catch {}
    }
  }
}

function validatePhase24WorkloadIntegrity(executionConfig, errors, warnings, isProduction, mode) {
  if (mode !== "container") {
    return;
  }

  const defaultManifestPath = resolveDefaultWorkloadManifestPath();
  const configuredManifestPath = normalizeString(executionConfig.workloadManifestPath || process.env.WORKLOAD_MANIFEST_PATH);
  const expectedManifestHash = normalizeString(
    executionConfig.workloadManifestExpectedHash || process.env.WORKLOAD_MANIFEST_EXPECTED_HASH,
  ).toLowerCase();
  const manifestPath = isProduction
    ? configuredManifestPath || defaultManifestPath
    : configuredManifestPath
    ? configuredManifestPath
    : defaultManifestPath;

  const collection = isProduction ? errors : warnings;

  if (isProduction) {
    if (configuredManifestPath && resolvePath(configuredManifestPath) !== resolvePath(defaultManifestPath)) {
      addIssue(
        errors,
        "WORKLOAD_MANIFEST_PATH_OVERRIDE_FORBIDDEN",
        "Workload manifest path override is forbidden in production",
        {
          configuredPath: resolvePath(configuredManifestPath),
          requiredPath: resolvePath(defaultManifestPath),
        },
      );
    }
    if (!expectedManifestHash) {
      addIssue(errors, "WORKLOAD_MANIFEST_MISMATCH", "execution.workloadManifestExpectedHash is required in production", {});
    }
  }

  if (!manifestPath) {
    addIssue(collection, "WORKLOAD_MANIFEST_MISSING", "execution.workloadManifestPath is required for workload governance", {});
    return;
  }

  const resolvedManifestPath = resolvePath(manifestPath);
  if (!fs.existsSync(resolvedManifestPath)) {
    addIssue(collection, "WORKLOAD_MANIFEST_MISSING", "Workload manifest file is missing", {
      manifestPath: resolvedManifestPath,
    });
    return;
  }

  if (isProduction) {
    try {
      const stat = fs.lstatSync(resolvedManifestPath);
      if (typeof stat.isSymbolicLink === "function" && stat.isSymbolicLink()) {
        addIssue(errors, "WORKLOAD_MANIFEST_PATH_OVERRIDE_FORBIDDEN", "Workload manifest must not be symlinked in production", {
          manifestPath: resolvedManifestPath,
        });
      }
      try {
        fs.accessSync(resolvedManifestPath, fs.constants.W_OK);
        addIssue(errors, "WORKLOAD_MANIFEST_WRITABLE_IN_PRODUCTION", "Workload manifest must not be writable in production", {
          manifestPath: resolvedManifestPath,
        });
      } catch {}
    } catch (error) {
      addIssue(collection, "WORKLOAD_MANIFEST_MISSING", "Workload manifest file metadata could not be loaded", {
        manifestPath: resolvedManifestPath,
        reason: error && error.message ? error.message : String(error),
      });
      return;
    }
  }

  let workloadManifest;
  try {
    workloadManifest = JSON.parse(fs.readFileSync(resolvedManifestPath, "utf8"));
  } catch (error) {
    addIssue(collection, "WORKLOAD_MANIFEST_SCHEMA_INVALID", "Workload manifest JSON could not be parsed", {
      manifestPath: resolvedManifestPath,
      reason: error && error.message ? error.message : String(error),
    });
    return;
  }

  const schemaValidation = validateWorkloadManifest(workloadManifest);
  if (!schemaValidation.valid) {
    addIssue(collection, "WORKLOAD_MANIFEST_SCHEMA_INVALID", "Workload manifest schema validation failed", {
      errors: schemaValidation.errors,
    });
    return;
  }

  let canonical;
  let actualHash = "";
  let deterministic = false;
  try {
    canonical = getCanonicalWorkloadManifest(workloadManifest);
    actualHash = computeWorkloadManifestHash(canonical);
    deterministic = actualHash === computeWorkloadManifestHash(JSON.parse(JSON.stringify(canonical)));
  } catch (error) {
    addIssue(collection, "WORKLOAD_MANIFEST_SCHEMA_INVALID", "Workload manifest canonicalization failed", {
      reason: error && error.message ? error.message : String(error),
    });
    return;
  }

  if (!deterministic) {
    addIssue(collection, "WORKLOAD_MANIFEST_MISMATCH", "Workload manifest canonical hash is non-deterministic", {
      manifestPath: resolvedManifestPath,
    });
  }

  if (expectedManifestHash && actualHash !== expectedManifestHash) {
    addIssue(collection, "WORKLOAD_MANIFEST_MISMATCH", "Workload manifest hash does not match expected hash", {
      expectedHash: expectedManifestHash,
      actualHash,
    });
  }

  if (isProduction && canonical && Array.isArray(canonical.workloads)) {
    for (const entry of canonical.workloads) {
      if (!entry || typeof entry !== "object") {
        continue;
      }
      const workloadID = normalizeString(entry.workloadID);
      const productionRequired = entry.productionRequired === true;
      if (!productionRequired) {
        continue;
      }

      const digest = normalizeString(entry.containerImageDigest).toLowerCase();
      if (!digest) {
        addIssue(errors, "WORKLOAD_IMAGE_MISMATCH", "Production workload requires digest-pinned container image", {
          workloadID,
        });
        continue;
      }
      if (!/^sha256:[a-f0-9]{64}$/.test(digest)) {
        addIssue(errors, "WORKLOAD_IMAGE_MISMATCH", "Production workload image must use digest pinning", {
          workloadID,
          containerImageDigest: digest,
        });
      }
    }
  }
}

function validatePhase25WorkloadAttestation(executionConfig, errors, warnings, isProduction, mode) {
  if (mode !== "container") {
    return;
  }

  const collection = isProduction ? errors : warnings;
  const defaultReferencePath = resolveDefaultAttestationReferencePath();
  const configuredReferencePath = normalizeString(
    executionConfig.workloadAttestationReferencePath || process.env.WORKLOAD_ATTESTATION_REFERENCE_PATH,
  );
  const configuredExpectedHash = normalizeString(
    executionConfig.workloadAttestationReferenceExpectedHash || process.env.WORKLOAD_ATTESTATION_REFERENCE_EXPECTED_HASH,
  ).toLowerCase();

  if (isProduction) {
    if (configuredReferencePath && resolvePath(configuredReferencePath) !== resolvePath(defaultReferencePath)) {
      addIssue(
        errors,
        "WORKLOAD_ATTESTATION_REFERENCE_PATH_OVERRIDE_FORBIDDEN",
        "Attestation reference path override is forbidden in production",
        {
          configuredPath: resolvePath(configuredReferencePath),
          requiredPath: resolvePath(defaultReferencePath),
        },
      );
    }
    if (configuredExpectedHash) {
      addIssue(
        errors,
        "WORKLOAD_ATTESTATION_REFERENCE_PATH_OVERRIDE_FORBIDDEN",
        "Attestation expected hash override is forbidden in production",
        {},
      );
    }
  }

  let loaded;
  try {
    loaded = loadAttestationReferenceFromDisk({
      referencePath: configuredReferencePath || undefined,
      expectedHash: configuredExpectedHash || undefined,
      production: isProduction,
      allowProductionPathOverride: false,
    });
  } catch (error) {
    addIssue(
      collection,
      error && typeof error.code === "string" ? error.code : "WORKLOAD_ATTESTATION_NOT_TRUSTED",
      "Attestation reference validation failed",
      {
        reason: error && error.message ? error.message : String(error),
      },
    );
    return;
  }

  try {
    const hashA = computeAttestationReferenceHash(loaded.reference);
    const hashB = computeAttestationReferenceHash(JSON.parse(JSON.stringify(loaded.reference)));
    if (hashA !== hashB) {
      addIssue(
        collection,
        "WORKLOAD_ATTESTATION_REFERENCE_MISMATCH",
        "Attestation reference canonical hash is non-deterministic",
        {
          referencePath: loaded.referencePath,
        },
      );
    }
  } catch (error) {
    addIssue(
      collection,
      "WORKLOAD_ATTESTATION_REFERENCE_SCHEMA_INVALID",
      "Attestation reference canonicalization failed",
      {
        reason: error && error.message ? error.message : String(error),
      },
    );
  }

  const ttlMs = Number(loaded.reference && loaded.reference.evidenceTtlMs);
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
    addIssue(
      collection,
      "WORKLOAD_ATTESTATION_REFERENCE_SCHEMA_INVALID",
      "Attestation evidence TTL must be configured",
      {
        evidenceTtlMs: ttlMs,
      },
    );
  } else if (isProduction && ttlMs !== 120000) {
    addIssue(
      collection,
      "WORKLOAD_ATTESTATION_REFERENCE_MISMATCH",
      "Attestation evidence TTL must be 120000ms in production",
      {
        evidenceTtlMs: ttlMs,
      },
    );
  }
}

function validatePhase26Provenance(executionConfig, errors, warnings, isProduction, mode) {
  if (mode !== "container") {
    return;
  }

  const collection = isProduction ? errors : warnings;
  const defaultProvenancePath = resolveDefaultBuildProvenancePath();
  const defaultHashPath = resolveDefaultBuildProvenanceHashPath();
  const defaultPublicKeyPath = resolveDefaultBuildProvenancePublicKeyPath();
  const defaultDependencyLockPath = resolveDefaultDependencyLockPath();

  const configuredProvenancePath = normalizeString(
    executionConfig.buildProvenancePath || process.env.WORKLOAD_PROVENANCE_PATH,
  );
  const configuredHashPath = normalizeString(
    executionConfig.buildProvenanceHashPath || process.env.WORKLOAD_PROVENANCE_HASH_PATH,
  );
  const configuredPublicKeyPath = normalizeString(
    executionConfig.buildProvenancePublicKeyPath || process.env.WORKLOAD_PROVENANCE_PUBLIC_KEY_PATH,
  );
  const configuredExpectedHash = normalizeString(
    executionConfig.buildProvenanceExpectedHash || process.env.WORKLOAD_PROVENANCE_EXPECTED_HASH,
  ).toLowerCase();
  const inlinePublicKeyOverride = normalizeString(process.env.WORKLOAD_PROVENANCE_PUBLIC_KEY);

  if (isProduction) {
    if (configuredProvenancePath && resolvePath(configuredProvenancePath) !== resolvePath(defaultProvenancePath)) {
      addIssue(
        errors,
        "WORKLOAD_PROVENANCE_PATH_OVERRIDE_FORBIDDEN",
        "Build provenance path override is forbidden in production",
        {
          configuredPath: resolvePath(configuredProvenancePath),
          requiredPath: resolvePath(defaultProvenancePath),
        },
      );
    }
    if (configuredHashPath && resolvePath(configuredHashPath) !== resolvePath(defaultHashPath)) {
      addIssue(
        errors,
        "WORKLOAD_PROVENANCE_HASH_PATH_OVERRIDE_FORBIDDEN",
        "Build provenance hash path override is forbidden in production",
        {
          configuredPath: resolvePath(configuredHashPath),
          requiredPath: resolvePath(defaultHashPath),
        },
      );
    }
    if (configuredPublicKeyPath && resolvePath(configuredPublicKeyPath) !== resolvePath(defaultPublicKeyPath)) {
      addIssue(
        errors,
        "WORKLOAD_PROVENANCE_KEY_PATH_OVERRIDE_FORBIDDEN",
        "Build provenance public key path override is forbidden in production",
        {
          configuredPath: resolvePath(configuredPublicKeyPath),
          requiredPath: resolvePath(defaultPublicKeyPath),
        },
      );
    }
    if (inlinePublicKeyOverride) {
      addIssue(
        errors,
        "WORKLOAD_PROVENANCE_KEY_OVERRIDE_FORBIDDEN",
        "Inline build provenance public key override is forbidden in production",
        {},
      );
    }
  }

  let loaded;
  try {
    loaded = loadBuildProvenanceFromDisk({
      production: isProduction,
      provenancePath: configuredProvenancePath || undefined,
      provenanceHashPath: configuredHashPath || undefined,
      publicKeyPath: configuredPublicKeyPath || undefined,
      expectedProvenanceHash: configuredExpectedHash || undefined,
      dependencyLockPath: defaultDependencyLockPath,
      allowProductionPathOverride: false,
      // Preflight runs outside the runtime container context, so mount mode enforcement
      // is handled by runtime startup checks in execution router.
      productionContainerMode: false,
    });
  } catch (error) {
    addIssue(
      collection,
      error && typeof error.code === "string" ? error.code : "WORKLOAD_PROVENANCE_NOT_TRUSTED",
      "Build provenance validation failed",
      {
        reason: error && error.message ? error.message : String(error),
      },
    );
    return;
  }

  try {
    const hashA = loaded.canonicalPayloadHash;
    const hashB = computeBuildProvenanceHash(JSON.parse(JSON.stringify(loaded.provenance)));
    if (hashA !== hashB) {
      addIssue(
        collection,
        "WORKLOAD_PROVENANCE_HASH_MISMATCH",
        "Build provenance canonical hash is non-deterministic",
        {
          provenancePath: loaded.provenancePath,
        },
      );
    }
  } catch (error) {
    addIssue(
      collection,
      "WORKLOAD_PROVENANCE_SCHEMA_INVALID",
      "Build provenance canonicalization failed",
      {
        reason: error && error.message ? error.message : String(error),
      },
    );
  }

  const digestEntries = Object.entries((loaded.provenance && loaded.provenance.containerImageDigests) || {});
  if (digestEntries.length === 0) {
    addIssue(
      collection,
      "WORKLOAD_PROVENANCE_DIGEST_MISMATCH",
      "Build provenance must define at least one digest-pinned workload",
      {},
    );
  }

  for (const [workloadID, digest] of digestEntries) {
    const normalizedDigest = normalizeString(digest).toLowerCase();
    if (!/^sha256:[a-f0-9]{64}$/.test(normalizedDigest)) {
      addIssue(
        collection,
        "WORKLOAD_PROVENANCE_DIGEST_MISMATCH",
        "Build provenance container digest must be immutable sha256 format",
        {
          workloadID,
          digest,
        },
      );
    }
  }
}

function validatePhase27OffensiveDomain(executionConfig, errors, warnings, isProduction, mode) {
  if (mode !== "container") {
    return;
  }

  const collection = isProduction ? errors : warnings;
  const defaultManifestPath = resolveDefaultOffensiveManifestPath();
  const defaultHashPath = resolveDefaultOffensiveManifestHashPath();
  const defaultSignaturePath = resolveDefaultOffensiveManifestSignaturePath();
  const defaultPublicKeyPath = resolveDefaultOffensiveManifestPublicKeyPath();
  const defaultWorkloadManifestPath = resolveDefaultWorkloadManifestPath();
  const defaultProvenancePath = resolveDefaultBuildProvenancePath();
  const defaultProvenanceHashPath = resolveDefaultBuildProvenanceHashPath();
  const defaultProvenancePublicKeyPath = resolveDefaultBuildProvenancePublicKeyPath();
  const defaultDependencyLockPath = resolveDefaultDependencyLockPath();

  const configuredManifestPath = normalizeString(process.env.OFFENSIVE_MANIFEST_PATH);
  const configuredHashPath = normalizeString(process.env.OFFENSIVE_MANIFEST_HASH_PATH);
  const configuredSignaturePath = normalizeString(process.env.OFFENSIVE_MANIFEST_SIGNATURE_PATH);
  const configuredPublicKeyPath = normalizeString(process.env.OFFENSIVE_MANIFEST_PUBLIC_KEY_PATH);
  const configuredExpectedHash = normalizeString(process.env.OFFENSIVE_MANIFEST_EXPECTED_HASH).toLowerCase();

  if (isProduction) {
    if (configuredManifestPath && resolvePath(configuredManifestPath) !== resolvePath(defaultManifestPath)) {
      addIssue(errors, "OFFENSIVE_MANIFEST_PATH_OVERRIDE_FORBIDDEN", "Offensive manifest path override is forbidden in production", {
        configuredPath: resolvePath(configuredManifestPath),
        requiredPath: resolvePath(defaultManifestPath),
      });
    }
    if (configuredHashPath && resolvePath(configuredHashPath) !== resolvePath(defaultHashPath)) {
      addIssue(errors, "OFFENSIVE_MANIFEST_HASH_PATH_OVERRIDE_FORBIDDEN", "Offensive manifest hash path override is forbidden in production", {
        configuredPath: resolvePath(configuredHashPath),
        requiredPath: resolvePath(defaultHashPath),
      });
    }
    if (configuredSignaturePath && resolvePath(configuredSignaturePath) !== resolvePath(defaultSignaturePath)) {
      addIssue(
        errors,
        "OFFENSIVE_MANIFEST_SIGNATURE_PATH_OVERRIDE_FORBIDDEN",
        "Offensive manifest signature path override is forbidden in production",
        {
          configuredPath: resolvePath(configuredSignaturePath),
          requiredPath: resolvePath(defaultSignaturePath),
        },
      );
    }
    if (configuredPublicKeyPath && resolvePath(configuredPublicKeyPath) !== resolvePath(defaultPublicKeyPath)) {
      addIssue(
        errors,
        "OFFENSIVE_MANIFEST_PUBLIC_KEY_PATH_OVERRIDE_FORBIDDEN",
        "Offensive manifest public key path override is forbidden in production",
        {
          configuredPath: resolvePath(configuredPublicKeyPath),
          requiredPath: resolvePath(defaultPublicKeyPath),
        },
      );
    }
  }

  let loadedOffensive;
  try {
    loadedOffensive = loadOffensiveManifestFromDisk({
      production: false,
      manifestPath: configuredManifestPath || undefined,
      hashPath: configuredHashPath || undefined,
      signaturePath: configuredSignaturePath || undefined,
      publicKeyPath: configuredPublicKeyPath || undefined,
      expectedManifestHash: configuredExpectedHash || undefined,
      allowProductionPathOverride: false,
      productionContainerMode: false,
    });
  } catch (error) {
    addIssue(
      collection,
      error && typeof error.code === "string" ? error.code : "OFFENSIVE_DOMAIN_NOT_TRUSTED",
      "Offensive manifest verification failed",
      {
        reason: error && error.message ? error.message : String(error),
      },
    );
    return;
  }

  const expectedToolSet = new Set(["nmap", "sqlmap", "nikto", "ffuf"]);
  const toolNames = Array.isArray(loadedOffensive.manifest.tools)
    ? loadedOffensive.manifest.tools.map((tool) => normalizeString(tool.toolName).toLowerCase()).filter(Boolean)
    : [];
  const actualToolSet = new Set(toolNames);
  if (
    toolNames.length !== expectedToolSet.size ||
    actualToolSet.size !== expectedToolSet.size ||
    Array.from(expectedToolSet).some((tool) => !actualToolSet.has(tool))
  ) {
    addIssue(collection, "OFFENSIVE_DOMAIN_NOT_TRUSTED", "Offensive tool registry is not static", {
      expectedTools: Array.from(expectedToolSet).sort((a, b) => a.localeCompare(b)),
      actualTools: Array.from(actualToolSet).sort((a, b) => a.localeCompare(b)),
    });
  }

  for (const tool of loadedOffensive.manifest.tools || []) {
    const digest = normalizeString(tool.containerImageDigest).toLowerCase();
    if (!/^sha256:[a-f0-9]{64}$/.test(digest)) {
      addIssue(collection, "WORKLOAD_PROVENANCE_DIGEST_MISMATCH", "Offensive tool digest must be immutable sha256", {
        toolName: normalizeString(tool.toolName),
        containerImageDigest: digest,
      });
    }

    const profile = tool.isolationProfile && typeof tool.isolationProfile === "object" ? tool.isolationProfile : {};
    const dropCaps = Array.isArray(profile.dropCapabilities) ? profile.dropCapabilities : [];
    const writableVolumes = Array.isArray(profile.writableVolumes) ? profile.writableVolumes : [];
    if (
      profile.privileged !== false ||
      profile.hostPID !== false ||
      profile.hostNetwork !== false ||
      profile.readOnlyRootFilesystem !== true ||
      profile.tty !== false ||
      profile.stdin !== false ||
      dropCaps.length !== 1 ||
      dropCaps[0] !== "ALL" ||
      writableVolumes.length !== 1 ||
      writableVolumes[0] !== "scratch"
    ) {
      addIssue(collection, "WORKLOAD_ISOLATION_INVALID", "Offensive isolation profile is invalid", {
        toolName: normalizeString(tool.toolName),
      });
    }

    const constraints = tool.executionConstraints && typeof tool.executionConstraints === "object" ? tool.executionConstraints : {};
    if (constraints.nonInteractive !== true) {
      addIssue(collection, "OFFENSIVE_ARGUMENTS_INVALID", "Offensive workload must enforce non-interactive mode", {
        toolName: normalizeString(tool.toolName),
      });
    }
  }

  const sqlmapEntry = (loadedOffensive.manifest.tools || []).find(
    (tool) => normalizeString(tool.toolName).toLowerCase() === "sqlmap",
  );
  if (sqlmapEntry) {
    const forced = new Set((sqlmapEntry.forcedFlags || []).map((entry) => normalizeString(entry).toLowerCase()));
    const denied = new Set((sqlmapEntry.deniedFlags || []).map((entry) => normalizeString(entry).toLowerCase()));
    const requiredDenied = ["--os-shell", "--os-pwn", "--file-write", "--file-read", "--udf-inject", "--tamper"];
    if (!forced.has("--batch")) {
      addIssue(collection, "OFFENSIVE_ARGUMENTS_INVALID", "SQLMap must force --batch in offensive mode", {});
    }
    for (const deniedFlag of requiredDenied) {
      if (!denied.has(deniedFlag)) {
        addIssue(collection, "OFFENSIVE_ARGUMENTS_INVALID", "SQLMap denylist is incomplete", {
          missingFlag: deniedFlag,
        });
      }
    }
  }

  let workloadManifest;
  try {
    const workloadManifestPath = normalizeString(executionConfig.workloadManifestPath || defaultWorkloadManifestPath);
    workloadManifest = getCanonicalWorkloadManifest(JSON.parse(fs.readFileSync(resolvePath(workloadManifestPath), "utf8")));
  } catch (error) {
    addIssue(collection, "WORKLOAD_MANIFEST_SCHEMA_INVALID", "Failed to load workload manifest for offensive binding check", {
      reason: error && error.message ? error.message : String(error),
    });
    return;
  }

  if (normalizeString(workloadManifest.offensiveManifestHash).toLowerCase() !== loadedOffensive.canonicalPayloadHash) {
    addIssue(collection, "WORKLOAD_MANIFEST_MISMATCH", "Workload manifest offensive hash must match offensive manifest", {
      expectedOffensiveManifestHash: loadedOffensive.canonicalPayloadHash,
      actualOffensiveManifestHash: normalizeString(workloadManifest.offensiveManifestHash).toLowerCase(),
    });
  }

  let loadedProvenance;
  try {
    loadedProvenance = loadBuildProvenanceFromDisk({
      production: isProduction,
      provenancePath: normalizeString(executionConfig.buildProvenancePath) || defaultProvenancePath,
      provenanceHashPath: normalizeString(executionConfig.buildProvenanceHashPath) || defaultProvenanceHashPath,
      publicKeyPath: normalizeString(executionConfig.buildProvenancePublicKeyPath) || defaultProvenancePublicKeyPath,
      expectedProvenanceHash: normalizeString(executionConfig.buildProvenanceExpectedHash).toLowerCase() || undefined,
      dependencyLockPath: defaultDependencyLockPath,
      allowProductionPathOverride: false,
      productionContainerMode: false,
    });
  } catch (error) {
    addIssue(
      collection,
      error && typeof error.code === "string" ? error.code : "WORKLOAD_PROVENANCE_NOT_TRUSTED",
      "Failed to load build provenance for offensive binding check",
      {
        reason: error && error.message ? error.message : String(error),
      },
    );
    return;
  }

  const provenanceOffensiveHash = normalizeString(loadedProvenance.provenance.offensiveManifestHash).toLowerCase();
  if (provenanceOffensiveHash !== loadedOffensive.canonicalPayloadHash) {
    addIssue(collection, "WORKLOAD_PROVENANCE_LOCK_MISMATCH", "Build provenance offensive hash must match offensive manifest", {
      expectedOffensiveManifestHash: loadedOffensive.canonicalPayloadHash,
      actualOffensiveManifestHash: provenanceOffensiveHash,
    });
  }

  for (const tool of loadedOffensive.manifest.tools || []) {
    const key = normalizeString(tool.workloadID || tool.toolName).toLowerCase();
    const provenanceDigest = normalizeString(loadedProvenance.provenance.containerImageDigests[key]).toLowerCase();
    const expectedDigest = normalizeString(tool.containerImageDigest).toLowerCase();
    if (!provenanceDigest || provenanceDigest !== expectedDigest) {
      addIssue(collection, "WORKLOAD_PROVENANCE_DIGEST_MISMATCH", "Offensive tool digest must match provenance", {
        toolName: normalizeString(tool.toolName),
        workloadID: key,
        expectedDigest,
        actualDigest: provenanceDigest,
      });
    }
  }
}

function resolveExecutionToolImageReference(executionConfig, slug, toolConfig) {
  const direct = normalizeString(toolConfig && toolConfig.image);
  if (direct) {
    return direct;
  }
  const policyImage = normalizeString(
    executionConfig &&
      executionConfig.imagePolicies &&
      executionConfig.imagePolicies[slug] &&
      executionConfig.imagePolicies[slug].image,
  );
  if (policyImage) {
    return policyImage;
  }
  const fallback = resolveCatalogImageReference(slug, {
    images: executionConfig && executionConfig.images,
  });
  if (fallback) {
    return fallback;
  }

  return normalizeString(executionConfig && executionConfig.image);
}

function resolveSignatureFlag(executionConfig, slug, toolConfig) {
  if (toolConfig && Object.prototype.hasOwnProperty.call(toolConfig, "signatureVerified")) {
    return toolConfig.signatureVerified;
  }
  if (
    executionConfig &&
    executionConfig.imagePolicies &&
    executionConfig.imagePolicies[slug] &&
    Object.prototype.hasOwnProperty.call(executionConfig.imagePolicies[slug], "signatureVerified")
  ) {
    return executionConfig.imagePolicies[slug].signatureVerified;
  }
  if (executionConfig && Object.prototype.hasOwnProperty.call(executionConfig, "signatureVerified")) {
    return executionConfig.signatureVerified;
  }
  return undefined;
}

function resolveRequireSignatureVerification(executionConfig, slug, toolConfig, isProduction) {
  if (toolConfig && Object.prototype.hasOwnProperty.call(toolConfig, "requireSignatureVerification")) {
    return toolConfig.requireSignatureVerification === true;
  }
  if (
    executionConfig &&
    executionConfig.imagePolicies &&
    executionConfig.imagePolicies[slug] &&
    Object.prototype.hasOwnProperty.call(executionConfig.imagePolicies[slug], "requireSignatureVerification")
  ) {
    return executionConfig.imagePolicies[slug].requireSignatureVerification === true;
  }
  if (executionConfig && Object.prototype.hasOwnProperty.call(executionConfig, "requireSignatureVerification")) {
    return executionConfig.requireSignatureVerification === true;
  }
  return isProduction;
}

function validateExecutionGuardrails(
  {
    executionMode,
    executionModeSource,
    executionBackend,
    executionBackendSource,
    executionConfig,
    containerRuntimeEnabled,
    containerRuntimeEnabledSource,
    knownToolSlugs,
    isProduction,
  },
  errors,
  warnings,
) {
  const mode = normalizeMode(executionMode);
  const supportedModes = new Set(["host", "container"]);

  if (mode && !supportedModes.has(mode)) {
    addIssue(errors, "EXECUTION_CONTAINER_REQUIRED_PROD", "execution.executionMode must be either 'host' or 'container'", {
      executionMode: mode,
      executionModeSource,
    });
    return {
      mode,
      executionToolCount: 0,
      validatedTools: [],
    };
  }

  if (!SUPPORTED_BACKENDS.includes(executionBackend)) {
    addIssue(errors, "EXECUTION_CONTAINER_REQUIRED_PROD", "execution backend must be one of mock,docker,containerd", {
      executionBackend,
      executionBackendSource,
    });
    return {
      mode,
      executionToolCount: 0,
      validatedTools: [],
    };
  }

  if (isProduction && !mode) {
    addIssue(
      errors,
      "EXECUTION_CONTAINER_REQUIRED_PROD",
      "Production mode requires explicit execution.executionMode to be set",
      { executionModeSource },
    );
    return {
      mode,
      executionToolCount: 0,
      validatedTools: [],
    };
  }

  if (mode === "host") {
    if (isProduction) {
      addIssue(warnings, "HOST_EXECUTION_TRANSITIONAL_PROD", "Host execution mode is transitional and not production-hardened", {});
    }
    return {
      mode,
      executionToolCount: 0,
      validatedTools: [],
    };
  }

  if (mode !== "container") {
    return {
      mode,
      executionToolCount: 0,
      validatedTools: [],
    };
  }

  if (isProduction && containerRuntimeEnabled !== true) {
    addIssue(
      errors,
      "CONTAINER_RUNTIME_DISABLED",
      "Container mode requires execution.containerRuntimeEnabled=true in production",
      { containerRuntimeEnabledSource },
    );
  }

  const tools = executionConfig && executionConfig.tools && typeof executionConfig.tools === "object" ? executionConfig.tools : {};
  const slugs = Object.keys(tools).map((item) => normalizeString(item).toLowerCase()).filter(Boolean);
  const uniqueSlugs = Array.from(new Set(slugs)).sort((a, b) => a.localeCompare(b));

  if (isProduction && uniqueSlugs.length === 0) {
    addIssue(
      errors,
      "EXECUTION_CONTAINER_REQUIRED_PROD",
      "Container execution mode requires at least one execution.tools entry in production",
      {},
    );
  }

  const validatedTools = [];

  for (const slug of uniqueSlugs) {
    if (!knownToolSlugs.has(slug)) {
      addIssue(errors, "EXECUTION_TOOL_UNREGISTERED", "execution.tools contains an unregistered tool slug", {
        toolSlug: slug,
      });
    }

    const toolConfig = tools[slug] && typeof tools[slug] === "object" ? tools[slug] : {};
    const sandboxConfig =
      (toolConfig && typeof toolConfig.sandbox === "object" && toolConfig.sandbox) ||
      (executionConfig.sandboxPolicies && executionConfig.sandboxPolicies[slug]) ||
      executionConfig.sandboxPolicy ||
      null;

    if (!sandboxConfig || typeof sandboxConfig !== "object") {
      addIssue(errors, "SANDBOX_POLICY_MISSING", "Sandbox policy is required for container execution tool", { toolSlug: slug });
    } else {
      const sandboxValidation = validateSandboxConfig(sandboxConfig);
      if (!sandboxValidation.valid) {
        addIssue(errors, "SANDBOX_POLICY_MISSING", "Sandbox policy is invalid for container execution tool", {
          toolSlug: slug,
          errors: sandboxValidation.errors,
        });
      }
    }

    const resourcePolicies = {
      ...(executionConfig.resourcePolicies && typeof executionConfig.resourcePolicies === "object" ? executionConfig.resourcePolicies : {}),
    };
    if (toolConfig && typeof toolConfig.resourceLimits === "object") {
      resourcePolicies[slug] = toolConfig.resourceLimits;
    }

    try {
      resolveResourceLimits(slug, {
        policies: resourcePolicies,
        allowDefault: !isProduction,
      });
    } catch (error) {
      addIssue(
        errors,
        error && typeof error.code === "string" ? error.code : "RESOURCE_POLICY_UNDEFINED",
        "Resource policy is undefined or invalid for container execution tool",
        {
          toolSlug: slug,
          reason: error && error.message ? error.message : String(error),
        },
      );
    }

    const egressPolicies = {
      ...(executionConfig.egressPolicies && typeof executionConfig.egressPolicies === "object" ? executionConfig.egressPolicies : {}),
    };
    if (toolConfig && typeof toolConfig.egress === "object") {
      egressPolicies[slug] = toolConfig.egress;
    }

    const egressValidation = validateEgressPolicy(slug, egressPolicies, {
      allowDefault: !isProduction,
    });
    if (!egressValidation.valid) {
      addIssue(errors, "EGRESS_POLICY_UNDEFINED", "Egress policy is undefined or invalid for container execution tool", {
        toolSlug: slug,
        errors: egressValidation.errors,
      });
    }

    const imageRef = resolveExecutionToolImageReference(executionConfig, slug, toolConfig);
    const imagePolicy = executionConfig.imagePolicies && executionConfig.imagePolicies[slug];
    const requireSignatureVerification = resolveRequireSignatureVerification(executionConfig, slug, toolConfig, isProduction);
    const imageValidation = validateImageReference(imageRef, {
      production: isProduction,
      allowedRegistries:
        (imagePolicy && Array.isArray(imagePolicy.allowedRegistries) && imagePolicy.allowedRegistries) ||
        (executionConfig.imagePolicy &&
          Array.isArray(executionConfig.imagePolicy.allowedRegistries) &&
          executionConfig.imagePolicy.allowedRegistries) ||
        executionConfig.allowedImageRegistries,
      requireDigestPinning: true,
      requireSignatureVerification,
      signatureVerified: resolveSignatureFlag(executionConfig, slug, toolConfig),
    });
    if (!imageValidation.valid) {
      addIssue(errors, "IMAGE_POLICY_VIOLATION", "Image policy validation failed for container execution tool", {
        toolSlug: slug,
        errors: imageValidation.errors,
      });
    }

    validatedTools.push(slug);
  }

  return {
    mode,
    executionToolCount: uniqueSlugs.length,
    validatedTools,
  };
}

function addIssue(collection, code, message, details = {}) {
  collection.push({
    code,
    message,
    details,
  });
}

function validateDebugFlags(options, errors, isProduction) {
  if (!isProduction) {
    return;
  }

  const debugCandidates = {
    optionsDebug: options && options.debug,
    DEBUG: process.env.DEBUG,
    NODE_DEBUG: process.env.NODE_DEBUG,
    SUPERVISOR_DEBUG: process.env.SUPERVISOR_DEBUG,
    CLUSTER_DEBUG: process.env.CLUSTER_DEBUG,
  };

  const enabledFlags = Object.entries(debugCandidates)
    .filter(([, value]) => isTruthyFlag(value))
    .map(([name]) => name);

  if (enabledFlags.length > 0) {
    addIssue(errors, "DEBUG_FLAGS_NOT_ALLOWED_PROD", "Debug flags are enabled in production mode", {
      enabledFlags,
    });
  }
}

function validateTls(tlsConfig, errors, warnings) {
  if (tlsConfig.httpEnabled && !tlsConfig.tlsEnabled) {
    addIssue(errors, "TLS_REQUIRED_FOR_HTTP", "HTTP ingress requires TLS to be enabled", {});
    return;
  }

  if (!tlsConfig.tlsEnabled) {
    return;
  }

  if (!tlsConfig.certPath || !tlsConfig.keyPath) {
    addIssue(errors, "TLS_CONFIG_INCOMPLETE", "TLS certPath and keyPath are required when TLS is enabled", {});
    return;
  }

  const certPath = resolvePath(tlsConfig.certPath);
  const keyPath = resolvePath(tlsConfig.keyPath);

  if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
    addIssue(errors, "TLS_FILES_MISSING", "TLS cert/key files are missing", {
      certPath,
      keyPath,
    });
    return;
  }

  try {
    const certPem = fs.readFileSync(certPath, "utf8");
    const cert = new crypto.X509Certificate(certPem);
    const notAfterMs = Date.parse(cert.validTo);

    if (!Number.isFinite(notAfterMs)) {
      addIssue(errors, "TLS_CERT_INVALID", "Unable to parse TLS certificate validity", {
        certPath,
      });
      return;
    }

    const now = Date.now();
    const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000;

    if (notAfterMs <= now) {
      addIssue(errors, "TLS_CERT_EXPIRED", "TLS certificate is expired", {
        certPath,
        validTo: cert.validTo,
      });
      return;
    }

    if (notAfterMs - now <= thirtyDaysMs) {
      addIssue(warnings, "TLS_CERT_EXPIRING_SOON", "TLS certificate expires within 30 days", {
        certPath,
        validTo: cert.validTo,
      });
    }
  } catch (error) {
    addIssue(errors, "TLS_CERT_INVALID", "Failed to parse TLS certificate", {
      certPath,
      error: error && error.message ? error.message : String(error),
    });
  }

  if (tlsConfig.mtlsEnabled) {
    if (!tlsConfig.caPath) {
      addIssue(errors, "MTLS_CA_REQUIRED", "mTLS is enabled but MTLS_CA_PATH is missing", {});
      return;
    }

    const caPath = resolvePath(tlsConfig.caPath);
    if (!fs.existsSync(caPath)) {
      addIssue(errors, "MTLS_CA_MISSING", "mTLS CA bundle path does not exist", {
        caPath,
      });
    }
  }
}

function buildStatePath(template, nodeId) {
  const safeNodeId = normalizeString(nodeId) || "unknown";
  const pathTemplate = normalizeString(template);
  if (pathTemplate.includes("{nodeId}")) {
    return resolvePath(pathTemplate.replaceAll("{nodeId}", safeNodeId));
  }
  return resolvePath(pathTemplate);
}

function validateStatePathIsolation({ clusterEnabled, expectedNodeCount, statePathTemplate, nodeId, nodeIds }, errors) {
  if (!clusterEnabled) {
    return;
  }

  if (!nodeId) {
    addIssue(errors, "NODE_ID_REQUIRED", "Cluster mode requires a nodeId", {});
    return;
  }

  const resolvedLocalPath = buildStatePath(statePathTemplate, nodeId);
  const requiresIsolation = Number.isFinite(expectedNodeCount) && expectedNodeCount > 1;

  if (requiresIsolation && !statePathTemplate.includes("{nodeId}")) {
    addIssue(errors, "STATE_PATH_NOT_NODE_ISOLATED", "Cluster state path must be node-isolated for multi-node topology", {
      statePathTemplate,
      resolvedLocalPath,
      nodeId,
      expectedNodeCount,
    });
  }

  if (Array.isArray(nodeIds) && nodeIds.length > 0) {
    const resolved = nodeIds
      .map((candidate) => normalizeString(candidate))
      .filter(Boolean)
      .map((candidate) => ({
        nodeId: candidate,
        path: buildStatePath(statePathTemplate, candidate),
      }));

    const seen = new Map();
    for (const entry of resolved) {
      const existing = seen.get(entry.path);
      if (existing && existing !== entry.nodeId) {
        addIssue(errors, "STATE_PATH_COLLISION", "Cluster state path collides across node identities", {
          path: entry.path,
          firstNodeId: existing,
          secondNodeId: entry.nodeId,
        });
        break;
      }
      seen.set(entry.path, entry.nodeId);
    }
  }
}

function validateClusterGuardrails({
  clusterEnabled,
  federationEnabled,
  partitionContainmentEnabled,
  expectedNodeCount,
  controlPlanePhase,
  clusterCapabilities,
  isProduction,
  clusterConfig,
}, errors, warnings) {
  if (!clusterEnabled) {
    return;
  }

  if (!federationEnabled) {
    addIssue(errors, "CLUSTER_REQUIRES_FEDERATION", "cluster.enabled=true requires federation.enabled=true", {});
  }

  if (!clusterConfig.shardCount || !clusterConfig.heartbeatIntervalMs || !clusterConfig.leaderTimeoutMs) {
    addIssue(errors, "CLUSTER_CONFIG_INVARIANT_MISSING", "Cluster shardCount, heartbeatIntervalMs, and leaderTimeoutMs are required", {
      clusterConfig,
    });
  }

  if (isProduction) {
    if (!Number.isFinite(expectedNodeCount)) {
      addIssue(
        errors,
        "TOPOLOGY_EXPECTED_NODE_COUNT_REQUIRED_PROD",
        "topology.expectedNodeCount is required in production mode",
        {},
      );
    } else {
      if (expectedNodeCount < 3) {
        addIssue(errors, "CLUSTER_MIN_NODE_COUNT_REQUIRED", "Production cluster mode requires at least 3 expected nodes", {
          expectedNodeCount,
        });
      }
      if (expectedNodeCount === 1) {
        addIssue(errors, "CLUSTER_SINGLE_NODE_NOT_ALLOWED_PROD", "Single-node cluster is not allowed in production", {
          expectedNodeCount,
        });
      }
    }
  } else if (!Number.isFinite(expectedNodeCount)) {
    addIssue(warnings, "TOPOLOGY_EXPECTED_NODE_COUNT_MISSING", "topology.expectedNodeCount was not provided", {});
  }

  if (isProduction && !partitionContainmentEnabled) {
    addIssue(
      errors,
      "CLUSTER_PARTITION_CONTAINMENT_REQUIRED",
      "Production cluster mode requires partition containment to be enabled",
      {},
    );
    return;
  }

  if (isProduction && partitionContainmentEnabled) {
    const capabilityFlag = parseBoolean(clusterCapabilities && clusterCapabilities.partitionContainment, false);
    const phaseBasedCapability = Number.isFinite(controlPlanePhase) ? controlPlanePhase >= 16 : false;

    if (!capabilityFlag && !phaseBasedCapability) {
      addIssue(
        errors,
        "CLUSTER_PARTITION_CONTAINMENT_UNVERIFIED",
        "Partition containment flag is set but capability evidence is missing",
        {
          controlPlanePhase: Number.isFinite(controlPlanePhase) ? controlPlanePhase : null,
          partitionContainmentCapability: capabilityFlag,
        },
      );
    }
  }
}

function parsePrometheusMetricNames(rawText) {
  const names = new Set();
  const lines = String(rawText).split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    const split = trimmed.split(/\s+/, 2);
    const left = split[0] || "";
    const metricName = left.split("{")[0].trim();
    if (metricName) {
      names.add(metricName);
    }
  }
  return names;
}

function extractMetricNames(payload) {
  if (!payload) {
    return new Set();
  }

  if (typeof payload === "string") {
    return parsePrometheusMetricNames(payload);
  }

  if (Array.isArray(payload)) {
    const names = new Set();
    for (const item of payload) {
      if (item && typeof item === "object" && typeof item.name === "string") {
        names.add(item.name);
      }
    }
    return names;
  }

  if (payload && typeof payload === "object" && Array.isArray(payload.metrics)) {
    return extractMetricNames(payload.metrics);
  }

  return new Set();
}

async function maybeFetchMetricsPayload(liveCheck) {
  if (!liveCheck || typeof liveCheck !== "object") {
    return null;
  }

  if (liveCheck.metricsPayload) {
    return liveCheck.metricsPayload;
  }

  const endpoint = normalizeString(liveCheck.metricsEndpoint || liveCheck.metricsUrl);
  if (!endpoint) {
    return null;
  }

  const timeoutMs = parsePositiveInt(liveCheck.timeoutMs) || 3000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(endpoint, {
      method: "GET",
      headers: {
        Accept: "application/json,text/plain,*/*",
      },
      signal: controller.signal,
    });

    const contentType = normalizeString(response.headers.get("content-type"));
    if (contentType.includes("application/json")) {
      return await response.json();
    }
    return await response.text();
  } finally {
    clearTimeout(timer);
  }
}

async function validateContainmentMetrics(liveCheck, errors, warnings) {
  const payload = await maybeFetchMetricsPayload(liveCheck);
  if (!payload) {
    return;
  }

  let names;
  try {
    names = extractMetricNames(payload);
  } catch (error) {
    addIssue(warnings, "LIVE_METRICS_PARSE_FAILED", "Unable to parse live metrics payload for containment verification", {
      error: error && error.message ? error.message : String(error),
    });
    return;
  }

  const missing = PARTITION_CONTAINMENT_METRICS.filter((name) => !names.has(name));
  if (missing.length > 0) {
    addIssue(
      errors,
      "CLUSTER_PARTITION_CONTAINMENT_UNVERIFIED",
      "Containment verification metrics are missing from provided live metrics payload",
      { missingMetrics: missing },
    );
  }
}

function validateVersionTargets({ isProduction, localVersion, versionTargets }, errors) {
  if (!isProduction) {
    return;
  }

  if (!localVersion) {
    addIssue(errors, "LOCAL_SOFTWARE_VERSION_REQUIRED", "Local software version could not be resolved", {});
    return;
  }

  if (!Array.isArray(versionTargets) || versionTargets.length === 0) {
    addIssue(
      errors,
      "VERSION_GUARD_TARGETS_REQUIRED_PROD",
      "Production mode requires deployment.versionTargets for compatibility preflight",
      {},
    );
    return;
  }

  const versionGuard = createVersionGuard();

  for (const targetVersion of versionTargets) {
    const result = versionGuard.evaluateCompatibility(localVersion, targetVersion);
    if (!result.compatible) {
      addIssue(
        errors,
        "VERSION_COMPATIBILITY_VIOLATION",
        "Local version is incompatible with one or more planned rollout target versions",
        {
          localVersion,
          targetVersion,
          reason: result.reason,
        },
      );
    }
  }
}

async function runPreflightValidation(options = {}) {
  const errors = [];
  const warnings = [];
  const manifest = getManifest(options);

  const cliEnv = normalizeString(options.__cliEnv || "");
  const productionMode = resolveProductionMode(options, cliEnv);

  const clusterEnabled = resolveClusterEnabled(options);
  const federationEnabled = resolveFederationEnabled(options);
  const partitionContainmentEnabled = resolvePartitionContainmentEnabled(options);

  const expectedNodeCountResult = resolveExpectedNodeCount(options, manifest);
  const expectedNodeCount = expectedNodeCountResult.value;

  const controlPlanePhaseResult = resolveControlPlanePhase(options, manifest);
  const controlPlanePhase = controlPlanePhaseResult.value;

  const versionTargetsResult = resolveVersionTargets(options, manifest);
  const softwareVersionResult = resolveSoftwareVersion(options);
  const clusterCapabilities = resolveClusterCapabilities(options, manifest);
  const executionModeResult = resolveExecutionMode(options, manifest);
  const executionBackendResult = resolveExecutionBackend(options, manifest);
  const containerRuntimeEnabledResult = resolveExecutionContainerRuntimeEnabled(options, manifest);
  const executionConfig = resolveExecutionConfig(options, manifest);
  const securityConfig = resolveSecurityConfig(options, manifest);
  const observabilityConfig = resolveObservabilityConfig(options, manifest);
  const knownToolSlugs = resolveAuthoritativeToolSlugs(options);

  const nodeId = resolveNodeId(options);
  const statePathTemplate = resolveClusterStatePathTemplate(options);
  const clusterConfig = resolveClusterConfig(options);
  const tlsConfig = resolveTlsConfig(options);

  validateClusterGuardrails(
    {
      clusterEnabled,
      federationEnabled,
      partitionContainmentEnabled,
      expectedNodeCount,
      controlPlanePhase,
      clusterCapabilities,
      isProduction: productionMode.isProduction,
      clusterConfig,
    },
    errors,
    warnings,
  );

  validateStatePathIsolation(
    {
      clusterEnabled,
      expectedNodeCount,
      statePathTemplate,
      nodeId,
      nodeIds: options && options.topology && options.topology.nodeIds,
    },
    errors,
  );

  validateTls(tlsConfig, errors, warnings);
  validateVersionTargets(
    {
      isProduction: productionMode.isProduction,
      localVersion: softwareVersionResult.value,
      versionTargets: versionTargetsResult.values,
    },
    errors,
  );

  validateDebugFlags(options, errors, productionMode.isProduction);

  if (productionMode.isProduction && partitionContainmentEnabled) {
    await validateContainmentMetrics(options.liveCheck, errors, warnings);
  }

  const executionValidation = validateExecutionGuardrails(
    {
      executionMode: executionModeResult.value,
      executionModeSource: executionModeResult.source,
      executionBackend: executionBackendResult.value,
      executionBackendSource: executionBackendResult.source,
      executionConfig,
      containerRuntimeEnabled: containerRuntimeEnabledResult.value,
      containerRuntimeEnabledSource: containerRuntimeEnabledResult.source,
      knownToolSlugs,
      isProduction: productionMode.isProduction,
    },
    errors,
    warnings,
  );
  validatePhase21ExecutionConfig(
    executionConfig,
    errors,
    warnings,
    productionMode.isProduction,
    executionValidation.mode,
  );
  validatePhase22PolicyGovernance(
    executionConfig,
    errors,
    warnings,
    productionMode.isProduction,
    executionValidation.mode,
  );
  await validatePhase23SecretGovernance(
    executionConfig,
    securityConfig,
    errors,
    warnings,
    productionMode.isProduction,
    executionValidation.mode,
  );
  validatePhase24WorkloadIntegrity(
    executionConfig,
    errors,
    warnings,
    productionMode.isProduction,
    executionValidation.mode,
  );
  validatePhase25WorkloadAttestation(
    executionConfig,
    errors,
    warnings,
    productionMode.isProduction,
    executionValidation.mode,
  );
  validatePhase26Provenance(
    executionConfig,
    errors,
    warnings,
    productionMode.isProduction,
    executionValidation.mode,
  );
  validatePhase27OffensiveDomain(
    executionConfig,
    errors,
    warnings,
    productionMode.isProduction,
    executionValidation.mode,
  );
  validatePhase21SecurityConfig(securityConfig, errors, productionMode.isProduction, executionValidation.mode);
  validatePhase21ObservabilityConfig(observabilityConfig, errors, warnings, productionMode.isProduction);

  const result = {
    ready_for_production: errors.length === 0,
    warnings,
    errors,
    diagnostics: {
      mode: productionMode.mode,
      modeSource: productionMode.source,
      clusterEnabled,
      federationEnabled,
      partitionContainmentEnabled,
      expectedNodeCount,
      expectedNodeCountSource: expectedNodeCountResult.source,
      controlPlanePhase,
      controlPlanePhaseSource: controlPlanePhaseResult.source,
      versionTargetsSource: versionTargetsResult.source,
      localVersionSource: softwareVersionResult.source,
      statePathTemplate,
      nodeId,
      executionMode: executionModeResult.value || "unset",
      executionModeSource: executionModeResult.source,
      executionBackend: executionBackendResult.value || "unset",
      executionBackendSource: executionBackendResult.source,
      containerRuntimeEnabled: containerRuntimeEnabledResult.value === true,
      containerRuntimeEnabledSource: containerRuntimeEnabledResult.source,
      executionToolCount: executionValidation.executionToolCount,
      validatedExecutionTools: executionValidation.validatedTools,
      knownExecutionTools: Array.from(knownToolSlugs).sort((a, b) => a.localeCompare(b)),
      executionConfigVersion: normalizeString(executionConfig.configVersion),
      expectedExecutionConfigVersion: normalizeString(executionConfig.expectedExecutionConfigVersion),
      executionPolicyManifestPath: normalizeString(executionConfig.policyManifestPath),
      executionPolicySignaturePath: normalizeString(executionConfig.policySignaturePath),
      executionPolicyPublicKeyPath: normalizeString(executionConfig.policyPublicKeyPath),
      executionPolicyExpectedHash: normalizeString(executionConfig.policyExpectedHash).toLowerCase(),
      secretManifestPath: normalizeString(executionConfig.secretManifestPath),
      secretManifestExpectedHash: normalizeString(executionConfig.secretManifestExpectedHash).toLowerCase(),
      workloadManifestPath: normalizeString(executionConfig.workloadManifestPath),
      workloadManifestExpectedHash: normalizeString(executionConfig.workloadManifestExpectedHash).toLowerCase(),
      workloadAttestationReferencePath: normalizeString(executionConfig.workloadAttestationReferencePath),
      workloadAttestationReferenceExpectedHash: normalizeString(executionConfig.workloadAttestationReferenceExpectedHash).toLowerCase(),
      buildProvenancePath: normalizeString(executionConfig.buildProvenancePath),
      buildProvenanceHashPath: normalizeString(executionConfig.buildProvenanceHashPath),
      buildProvenancePublicKeyPath: normalizeString(executionConfig.buildProvenancePublicKeyPath),
      buildProvenanceExpectedHash: normalizeString(executionConfig.buildProvenanceExpectedHash).toLowerCase(),
      secretStoreProvider: normalizeString(securityConfig.secretStoreProvider),
      secretStoreUrlConfigured: normalizeString(securityConfig.secretStoreUrl).length > 0,
      observabilityThresholdScope: normalizeString(observabilityConfig.thresholdScope),
    },
  };

  if (!parseBoolean(options.includeDiagnostics, false)) {
    delete result.diagnostics;
  }

  return result;
}

function parseCliArgs(argv) {
  const args = Array.isArray(argv) ? argv.slice(2) : [];
  const parsed = {
    __cliEnv: "",
    includeDiagnostics: true,
  };

  for (let index = 0; index < args.length; index += 1) {
    const token = args[index];
    if (token === "--env") {
      parsed.__cliEnv = normalizeString(args[index + 1]);
      index += 1;
      continue;
    }
    if (token === "--config") {
      parsed.__configPath = normalizeString(args[index + 1]);
      index += 1;
      continue;
    }
    if (token === "--metrics-endpoint") {
      parsed.liveCheck = parsed.liveCheck || {};
      parsed.liveCheck.metricsEndpoint = normalizeString(args[index + 1]);
      index += 1;
      continue;
    }
    if (token === "--no-diagnostics") {
      parsed.includeDiagnostics = false;
      continue;
    }
    if (token === "--expected-node-count") {
      parsed.topology = parsed.topology || {};
      parsed.topology.expectedNodeCount = parsePositiveInt(args[index + 1]);
      index += 1;
      continue;
    }
    if (token === "--version-target") {
      parsed.deployment = parsed.deployment || {};
      if (!Array.isArray(parsed.deployment.versionTargets)) {
        parsed.deployment.versionTargets = [];
      }
      const value = normalizeString(args[index + 1]);
      if (value) {
        parsed.deployment.versionTargets.push(value);
      }
      index += 1;
      continue;
    }
    if (token === "--execution-mode") {
      parsed.execution = parsed.execution || {};
      parsed.execution.executionMode = normalizeMode(args[index + 1]);
      index += 1;
      continue;
    }
    if (token === "--execution-backend") {
      parsed.execution = parsed.execution || {};
      parsed.execution.backend = normalizeMode(args[index + 1]);
      index += 1;
      continue;
    }
    if (token === "--container-runtime-enabled") {
      parsed.execution = parsed.execution || {};
      parsed.execution.containerRuntimeEnabled = parseBoolean(args[index + 1], false);
      index += 1;
      continue;
    }
  }

  return parsed;
}

function loadConfigFromPath(configPath) {
  const resolved = resolvePath(configPath);
  const raw = fs.readFileSync(resolved, "utf8");
  return JSON.parse(raw);
}

if (require.main === module) {
  (async () => {
    const cliOptions = parseCliArgs(process.argv);

    let fileOptions = {};
    if (cliOptions.__configPath) {
      fileOptions = loadConfigFromPath(cliOptions.__configPath);
    }

    const merged = {
      ...fileOptions,
      ...cliOptions,
      topology: {
        ...(fileOptions.topology || {}),
        ...(cliOptions.topology || {}),
      },
      deployment: {
        ...(fileOptions.deployment || {}),
        ...(cliOptions.deployment || {}),
      },
      execution: {
        ...(fileOptions.execution || {}),
        ...(cliOptions.execution || {}),
        tools: {
          ...((fileOptions.execution && fileOptions.execution.tools) || {}),
          ...((cliOptions.execution && cliOptions.execution.tools) || {}),
        },
        resourcePolicies: {
          ...((fileOptions.execution && fileOptions.execution.resourcePolicies) || {}),
          ...((cliOptions.execution && cliOptions.execution.resourcePolicies) || {}),
        },
        sandboxPolicies: {
          ...((fileOptions.execution && fileOptions.execution.sandboxPolicies) || {}),
          ...((cliOptions.execution && cliOptions.execution.sandboxPolicies) || {}),
        },
        egressPolicies: {
          ...((fileOptions.execution && fileOptions.execution.egressPolicies) || {}),
          ...((cliOptions.execution && cliOptions.execution.egressPolicies) || {}),
        },
        imagePolicies: {
          ...((fileOptions.execution && fileOptions.execution.imagePolicies) || {}),
          ...((cliOptions.execution && cliOptions.execution.imagePolicies) || {}),
        },
        images: {
          ...((fileOptions.execution && fileOptions.execution.images) || {}),
          ...((cliOptions.execution && cliOptions.execution.images) || {}),
        },
      },
      liveCheck: {
        ...(fileOptions.liveCheck || {}),
        ...(cliOptions.liveCheck || {}),
      },
    };

    const result = await runPreflightValidation(merged);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    process.exit(result.errors.length === 0 ? 0 : 1);
  })().catch((error) => {
    const output = {
      ready_for_production: false,
      warnings: [],
      errors: [
        {
          code: "PREFLIGHT_RUNTIME_ERROR",
          message: error && error.message ? error.message : String(error),
          details: {},
        },
      ],
    };
    process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
    process.exit(1);
  });
}

module.exports = {
  runPreflightValidation,
};
