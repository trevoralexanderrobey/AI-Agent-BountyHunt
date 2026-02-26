const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

function parseBoolean(value, fallback = false) {
  if (typeof value === "boolean") {
    return value;
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

function parsePositiveInt(value, fallback = 0) {
  const parsed = Number.parseInt(String(value ?? "").trim(), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
}

function normalizeString(value) {
  return typeof value === "string" ? value.trim() : "";
}

function stableStringify(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }

  const keys = Object.keys(value).sort((left, right) => left.localeCompare(right));
  const entries = keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`);
  return `{${entries.join(",")}}`;
}

function makeBootstrapError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function resolvePackageVersion() {
  const packagePath = path.resolve(__dirname, "..", "package.json");
  try {
    const raw = fs.readFileSync(packagePath, "utf8");
    const parsed = JSON.parse(raw);
    const version = normalizeString(parsed && parsed.version);
    return version;
  } catch {
    return "";
  }
}

function normalizeTlsConfig(rawTls) {
  const tls = rawTls && typeof rawTls === "object" ? rawTls : {};
  return {
    enabled: parseBoolean(tls.enabled, parseBoolean(process.env.TLS_ENABLED, false)),
    certPath: normalizeString(tls.certPath || process.env.TLS_CERT_PATH),
    keyPath: normalizeString(tls.keyPath || process.env.TLS_KEY_PATH),
    caPath: normalizeString(tls.caPath || process.env.MTLS_CA_PATH),
    mtlsEnabled: parseBoolean(tls.mtlsEnabled, parseBoolean(process.env.MTLS_ENABLED, false)),
    reloadMode: normalizeString(tls.reloadMode) || "hot",
  };
}

function normalizeTokenRotation(rawTokenRotation) {
  const tokenRotation = rawTokenRotation && typeof rawTokenRotation === "object" ? rawTokenRotation : {};
  return {
    enabled: parseBoolean(tokenRotation.enabled, false),
    acceptPreviousToken: parseBoolean(tokenRotation.acceptPreviousToken, true),
    graceWindowMs: parsePositiveInt(tokenRotation.graceWindowMs, 0),
  };
}

function resolveSoftwareVersion(rawSoftwareVersion) {
  const explicitVersion = normalizeString(rawSoftwareVersion);
  if (explicitVersion) {
    return explicitVersion;
  }

  const envVersion = normalizeString(process.env.SUPERVISOR_SOFTWARE_VERSION);
  if (envVersion) {
    return envVersion;
  }

  const packageVersion = resolvePackageVersion();
  if (packageVersion) {
    return packageVersion;
  }

  throw makeBootstrapError("BOOTSTRAP_SOFTWARE_VERSION_REQUIRED", "Unable to resolve software version");
}

function createBootstrapManager(options = {}) {
  const clusterEnabled = Boolean(options.clusterEnabled);
  const federationEnabled = Boolean(options.federationEnabled);
  const nodeId = normalizeString(options.nodeId);
  const clusterConfig = options.clusterConfig && typeof options.clusterConfig === "object" ? options.clusterConfig : {};
  const shardCount = parsePositiveInt(clusterConfig.shardCount, 0);
  const leaderTimeoutMs = parsePositiveInt(clusterConfig.leaderTimeoutMs, 0);
  const heartbeatIntervalMs = parsePositiveInt(clusterConfig.heartbeatIntervalMs, 0);
  const softwareVersion = resolveSoftwareVersion(options.softwareVersion);
  const httpEnabled = parseBoolean(options.httpEnabled, false);
  const tls = normalizeTlsConfig(options.tls);
  const tokenRotation = normalizeTokenRotation(options.tokenRotation);

  const configFingerprintPayload = {
    clusterEnabled,
    federationEnabled,
    clusterConfig: {
      shardCount,
      leaderTimeoutMs,
      heartbeatIntervalMs,
    },
    httpEnabled,
    tls: {
      enabled: tls.enabled,
      mtlsEnabled: tls.mtlsEnabled,
      reloadMode: tls.reloadMode,
    },
    tokenRotation,
  };

  const configHash =
    normalizeString(options.configHash) ||
    crypto.createHash("sha256").update(stableStringify(configFingerprintPayload), "utf8").digest("hex");

  const criticalConfig = Object.freeze({
    shardCount,
    leaderTimeoutMs,
    heartbeatIntervalMs,
  });

  const nodePublication = Object.freeze({
    nodeId,
    softwareVersion,
    configHash,
    shardCount,
    leaderTimeoutMs,
    heartbeatIntervalMs,
  });

  function validateStartup() {
    if (clusterEnabled && !federationEnabled) {
      throw makeBootstrapError("BOOTSTRAP_CLUSTER_REQUIRES_FEDERATION", "cluster.enabled requires federation.enabled=true");
    }

    if (clusterEnabled && !nodeId) {
      throw makeBootstrapError("BOOTSTRAP_NODE_ID_REQUIRED", "cluster.nodeId is required when cluster.enabled=true");
    }

    if (clusterEnabled && (!shardCount || !leaderTimeoutMs || !heartbeatIntervalMs)) {
      throw makeBootstrapError(
        "BOOTSTRAP_CLUSTER_CONFIG_REQUIRED",
        "cluster shardCount, leaderTimeoutMs, and heartbeatIntervalMs are required",
      );
    }

    if (httpEnabled) {
      if (!tls.enabled) {
        throw makeBootstrapError("BOOTSTRAP_TLS_REQUIRED", "TLS must be enabled when HTTP server is enabled");
      }
      if (!tls.certPath || !tls.keyPath) {
        throw makeBootstrapError("BOOTSTRAP_TLS_CONFIG_REQUIRED", "TLS certPath and keyPath are required when HTTP server is enabled");
      }
    }

    if (tls.enabled && tls.reloadMode !== "hot") {
      throw makeBootstrapError("BOOTSTRAP_TLS_HOT_RELOAD_REQUIRED", "TLS reloadMode must be 'hot'");
    }

    if (tokenRotation.enabled) {
      if (!tokenRotation.acceptPreviousToken) {
        throw makeBootstrapError(
          "BOOTSTRAP_TOKEN_DUAL_WINDOW_REQUIRED",
          "token rotation requires acceptPreviousToken=true",
        );
      }
      if (!tokenRotation.graceWindowMs) {
        throw makeBootstrapError(
          "BOOTSTRAP_TOKEN_GRACE_WINDOW_REQUIRED",
          "token rotation requires a positive graceWindowMs",
        );
      }
    }

    return {
      ok: true,
    };
  }

  function assertCriticalConfigUnchanged(nextConfig = {}) {
    const nextShardCount = parsePositiveInt(nextConfig.shardCount, 0);
    const nextLeaderTimeoutMs = parsePositiveInt(nextConfig.leaderTimeoutMs, 0);
    const nextHeartbeatIntervalMs = parsePositiveInt(nextConfig.heartbeatIntervalMs, 0);

    if (
      nextShardCount !== criticalConfig.shardCount ||
      nextLeaderTimeoutMs !== criticalConfig.leaderTimeoutMs ||
      nextHeartbeatIntervalMs !== criticalConfig.heartbeatIntervalMs
    ) {
      throw makeBootstrapError(
        "CRITICAL_CONFIG_CHANGE_REQUIRES_RESTART",
        "shardCount, leaderTimeoutMs, and heartbeatIntervalMs require full cluster restart",
      );
    }

    return {
      ok: true,
    };
  }

  function getNodePublication() {
    return nodePublication;
  }

  function getCriticalConfig() {
    return criticalConfig;
  }

  return {
    validateStartup,
    getNodePublication,
    getCriticalConfig,
    assertCriticalConfigUnchanged,
  };
}

module.exports = {
  createBootstrapManager,
};
