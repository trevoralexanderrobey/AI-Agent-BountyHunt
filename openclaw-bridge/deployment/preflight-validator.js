const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const { createVersionGuard } = require("./version-guard.js");

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
