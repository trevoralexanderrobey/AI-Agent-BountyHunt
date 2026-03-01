const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

let redisModule = null;
try {
  redisModule = require("redis");
} catch {
  redisModule = null;
}

const {
  validateSecretSchema,
  computeSecretManifestHash,
  getCanonicalSecretManifest,
  loadSecretManifestFromDisk,
} = require("./secret-manifest.js");

const DEFAULT_SECRET_MANIFEST_PATH = path.resolve(__dirname, "secret-manifest.json");

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

function parsePositiveInteger(value, fallback) {
  const parsed = Number.parseInt(String(value ?? "").trim(), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
}

function isPlainObject(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
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
  const error = new Error(String(message || "Secret authority failure"));
  error.code = String(code || "SECRET_AUTHORITY_ERROR");
  error.details = details;
  return error;
}

function hashPrincipal(principalId) {
  return crypto.createHash("sha256").update(normalizeString(principalId) || "anonymous", "utf8").digest("hex").slice(0, 16);
}

function hashSecretName(secretName) {
  return crypto.createHash("sha256").update(normalizeString(secretName).toLowerCase(), "utf8").digest("hex").slice(0, 16);
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

function withTimeout(promise, timeoutMs, timeoutCode, timeoutMessage) {
  const timeout = parsePositiveInteger(timeoutMs, 3000);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(makeFailure(timeoutCode, timeoutMessage, { timeoutMs: timeout }));
    }, timeout);
    if (typeof timer.unref === "function") {
      timer.unref();
    }

    Promise.resolve(promise)
      .then((value) => {
        clearTimeout(timer);
        resolve(value);
      })
      .catch((error) => {
        clearTimeout(timer);
        reject(error);
      });
  });
}

function resolveDefaultSecretManifestPath() {
  return DEFAULT_SECRET_MANIFEST_PATH;
}

function resolveManifestPath(options = {}, production = false) {
  const configured =
    normalizeString(options.manifestPath) || normalizeString(process.env.SECRET_MANIFEST_PATH) || "";
  if (!production) {
    return configured || resolveDefaultSecretManifestPath();
  }
  if (configured && path.resolve(configured) !== resolveDefaultSecretManifestPath() && options.allowProductionPathOverride !== true) {
    throw makeFailure(
      "SECRET_MANIFEST_PATH_OVERRIDE_FORBIDDEN",
      "Secret manifest path override is forbidden in production",
      {
        configuredPath: path.resolve(configured),
        requiredPath: resolveDefaultSecretManifestPath(),
      },
    );
  }
  return configured ? path.resolve(configured) : resolveDefaultSecretManifestPath();
}

function normalizeSecretName(secretName) {
  return normalizeString(secretName);
}

function secretNameToEnvKey(secretName) {
  const raw = normalizeSecretName(secretName);
  if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(raw)) {
    return raw;
  }
  const suffix = raw
    .toUpperCase()
    .replace(/[^A-Z0-9_]/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_+|_+$/g, "");
  return `OPENCLAW_SECRET_${suffix || "UNNAMED"}`;
}

function normalizeAllowedPrincipals(value) {
  if (value === "*") {
    return "*";
  }
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => normalizeString(item)).filter(Boolean);
}

function principalAllowed(allowedPrincipals, principalId) {
  if (allowedPrincipals === "*") {
    return true;
  }
  const normalizedPrincipal = normalizeString(principalId);
  return Array.isArray(allowedPrincipals) && allowedPrincipals.includes(normalizedPrincipal);
}

function toolAllowed(allowedTools, toolSlug) {
  const normalizedTool = normalizeString(toolSlug).toLowerCase();
  return Array.isArray(allowedTools) && allowedTools.some((item) => normalizeString(item).toLowerCase() === normalizedTool);
}

function createRedisSecretProvider(options = {}) {
  const redisUrl = normalizeString(options.redisUrl || process.env.SECRET_STORE_URL);
  const redisPrefix = normalizeString(options.redisPrefix || process.env.SECRET_STORE_PREFIX) || "openclaw:secrets";
  const connectTimeoutMs = parsePositiveInteger(
    options.connectTimeoutMs || process.env.SECRET_STORE_CONNECT_TIMEOUT_MS,
    3000,
  );

  if (!redisUrl) {
    return null;
  }
  if (!redisModule || typeof redisModule.createClient !== "function") {
    throw makeFailure("SECRET_STORE_UNREACHABLE", "redis module is unavailable for configured secret store", {
      provider: "redis",
    });
  }

  let client = null;
  let connected = false;

  async function ensureConnected() {
    if (!client) {
      client = redisModule.createClient({
        url: redisUrl,
        socket: {
          reconnectStrategy: false,
          connectTimeout: connectTimeoutMs,
        },
      });
    }
    if (!connected && typeof client.connect === "function") {
      await withTimeout(
        client.connect(),
        connectTimeoutMs,
        "SECRET_STORE_UNREACHABLE",
        "Secret store connectivity timed out",
      );
      connected = true;
    }
    return client;
  }

  return {
    async ping() {
      const resolved = await ensureConnected();
      const response = await withTimeout(
        resolved.ping(),
        connectTimeoutMs,
        "SECRET_STORE_UNREACHABLE",
        "Secret store ping timed out",
      );
      return normalizeString(response).toUpperCase() === "PONG";
    },
    async fetchSecret(input = {}) {
      const resolved = await ensureConnected();
      const secretName = normalizeSecretName(input.secretName);
      const secretVersion = Number(input.secretVersion);
      const key = `${redisPrefix}:${secretName}:v${secretVersion}`;
      const value = await withTimeout(
        resolved.get(key),
        connectTimeoutMs,
        "SECRET_FETCH_TIMEOUT",
        "Secret fetch timed out",
      );
      if (!normalizeString(value)) {
        return {
          found: false,
          value: "",
        };
      }
      return {
        found: true,
        value: String(value),
      };
    },
    async close() {
      if (client && typeof client.quit === "function") {
        try {
          await client.quit();
        } catch {}
      }
      client = null;
      connected = false;
    },
  };
}

function resolveSecretProvider(options = {}) {
  if (options.secretProvider && typeof options.secretProvider.fetchSecret === "function") {
    return options.secretProvider;
  }

  const providerType = normalizeString(options.provider || process.env.SECRET_STORE_PROVIDER || "redis").toLowerCase();
  if (providerType === "redis") {
    return createRedisSecretProvider(options);
  }
  if (providerType === "none") {
    return null;
  }
  throw makeFailure("SECRET_STORE_PROVIDER_INVALID", `Unsupported secret store provider '${providerType}'`, {
    provider: providerType,
  });
}

function normalizeFetchResult(raw) {
  if (typeof raw === "string") {
    const value = raw;
    return {
      found: value.length > 0,
      value,
    };
  }
  if (!raw || typeof raw !== "object") {
    return {
      found: false,
      value: "",
    };
  }
  const value = typeof raw.value === "string" ? raw.value : String(raw.value ?? "");
  const found = Object.prototype.hasOwnProperty.call(raw, "found") ? raw.found === true : value.length > 0;
  return {
    found,
    value,
  };
}

function createSecretAuthority(options = {}) {
  const production = parseBoolean(options.production, normalizeString(process.env.NODE_ENV).toLowerCase() === "production");
  const nodeId = normalizeString(options.nodeId || process.env.SUPERVISOR_NODE_ID) || "node-unknown";
  const metrics = createSafeMetrics(options.metrics);
  const auditLogger = createSafeAuditLogger(options.auditLogger || options.logger);

  const allowEnvFallbackNonProd = parseBoolean(
    options.allowEnvFallbackNonProd,
    parseBoolean(process.env.SECRET_FETCH_ALLOW_ENV_FALLBACK_NONPROD, false),
  );
  const fetchTimeoutMs = parsePositiveInteger(options.fetchTimeoutMs || process.env.SECRET_FETCH_TIMEOUT_MS, 3000);
  const fetchMaxAttempts = parsePositiveInteger(options.fetchMaxAttempts || process.env.SECRET_FETCH_MAX_ATTEMPTS, 2);

  const provider = resolveSecretProvider({
    ...options,
    redisUrl: options.secretStoreUrl || options.redisUrl || process.env.SECRET_STORE_URL,
    redisPrefix: options.secretStorePrefix || options.redisPrefix || process.env.SECRET_STORE_PREFIX,
    connectTimeoutMs:
      options.secretStoreConnectTimeoutMs ||
      options.connectTimeoutMs ||
      process.env.SECRET_STORE_CONNECT_TIMEOUT_MS,
  });

  let initialized = false;
  let manifestPath = "";
  let manifestHash = "";
  let manifestCanonical = null;
  let manifestByName = new Map();
  let lastPeerSummary = {
    ok: true,
    status: "not_evaluated",
    criticalMismatches: [],
    warnings: [],
    timestamp: Date.now(),
  };
  const executionSecrets = new Map();

  function assertInitialized() {
    if (!initialized) {
      throw makeFailure("SECRET_AUTHORITY_UNINITIALIZED", "Secret authority is not initialized", {
        nodeId,
      });
    }
  }

  function getExpectedManifestHash() {
    return normalizeString(options.expectedHash || process.env.SECRET_MANIFEST_EXPECTED_HASH).toLowerCase();
  }

  async function initialize() {
    const priorManifestHash = manifestHash;
    manifestPath = resolveManifestPath(options, production);
    let rawManifest;
    try {
      rawManifest = loadSecretManifestFromDisk({ manifestPath });
    } catch (error) {
      throw makeFailure("SECRET_MANIFEST_MISSING", "Secret manifest file is missing or unreadable", {
        manifestPath,
        reason: error && error.message ? error.message : String(error),
      });
    }

    const validation = validateSecretSchema(rawManifest);
    if (!validation.valid) {
      throw makeFailure("SECRET_MANIFEST_INVALID", "Secret manifest validation failed", {
        manifestPath,
        errors: validation.errors,
      });
    }

    const canonical = getCanonicalSecretManifest(rawManifest);
    manifestHash = computeSecretManifestHash(canonical);
    const expectedHash = getExpectedManifestHash();
    if (expectedHash && expectedHash !== manifestHash) {
      throw makeFailure("SECRET_MANIFEST_MISMATCH", "Secret manifest hash mismatch", {
        expectedHash,
        actualHash: manifestHash,
      });
    }

    manifestCanonical = deepFreeze(canonical);
    manifestByName = new Map(
      manifestCanonical.secrets.map((entry) => [normalizeSecretName(entry.secretName).toLowerCase(), entry]),
    );

    const hasProductionRequiredSecrets = manifestCanonical.secrets.some((entry) => entry.productionRequired === true);
    const mustVerifyStore = production && hasProductionRequiredSecrets;

    if (mustVerifyStore) {
      if (!provider || typeof provider.fetchSecret !== "function") {
        throw makeFailure("SECRET_STORE_UNREACHABLE", "External secret store provider is required in production", {
          provider: "missing",
        });
      }
      if (typeof provider.ping === "function") {
        const pingOk = await withTimeout(
          provider.ping(),
          fetchTimeoutMs,
          "SECRET_STORE_UNREACHABLE",
          "Secret store ping timed out",
        ).catch((error) => {
          throw makeFailure("SECRET_STORE_UNREACHABLE", "Secret store is unreachable", {
            reason: error && error.message ? error.message : String(error),
          });
        });
        if (pingOk !== true) {
          throw makeFailure("SECRET_STORE_UNREACHABLE", "Secret store ping failed", {
            provider: "external",
          });
        }
      }
    }

    initialized = true;
    metrics.gauge("secret.manifest.hash", 1, {
      node_id: nodeId,
      secret_manifest_hash: manifestHash,
    });
    if (priorManifestHash && priorManifestHash !== manifestHash) {
      metrics.increment("secret.rotation", {
        node_id: nodeId,
      });
      auditLogger.log({
        event: "secret_rotation",
        principal_id: "system",
        slug: "",
        request_id: "",
        status: "success",
        details: {
          node_id: nodeId,
          previous_manifest_hash: priorManifestHash,
          secret_manifest_hash: manifestHash,
        },
      });
    }

    return getActiveMetadata();
  }

  function getScopedSecretEntries(input = {}) {
    const toolSlug = normalizeString(input.toolSlug).toLowerCase();
    const principalId = normalizeString(input.principalId);
    const requested = Array.isArray(input.requestedSecretNames)
      ? input.requestedSecretNames.map((item) => normalizeSecretName(item)).filter(Boolean)
      : [];

    const scoped = manifestCanonical.secrets
      .filter((entry) => toolAllowed(entry.allowedTools, toolSlug))
      .filter((entry) => principalAllowed(normalizeAllowedPrincipals(entry.allowedPrincipals), principalId))
      .sort((a, b) => normalizeSecretName(a.secretName).localeCompare(normalizeSecretName(b.secretName)));

    if (requested.length === 0) {
      return scoped;
    }

    const byName = new Map(scoped.map((entry) => [normalizeSecretName(entry.secretName), entry]));
    for (const requestedName of requested) {
      if (!byName.has(requestedName)) {
        metrics.increment("secret.scope.violation", {
          node_id: nodeId,
          tool: toolSlug || "unknown",
          principal_hash: hashPrincipal(principalId),
        });
        auditLogger.log({
          event: "secret_scope_rejection",
          principal_id: principalId || "anonymous",
          slug: toolSlug || "",
          request_id: normalizeString(input.executionId),
          status: "failure",
          details: {
            node_id: nodeId,
            secret_name_hash: hashSecretName(requestedName),
          },
        });
        throw makeFailure("SECRET_SCOPE_VIOLATION", "Secret scope violation detected", {
          requestedSecretName: requestedName,
          toolSlug,
          principalHash: hashPrincipal(principalId),
        });
      }
    }

    return requested.map((name) => byName.get(name)).filter(Boolean);
  }

  async function fetchSecretValue(entry, input) {
    const executionId = normalizeString(input.executionId);
    const toolSlug = normalizeString(input.toolSlug).toLowerCase();
    const principalId = normalizeString(input.principalId);
    const secretName = normalizeSecretName(entry.secretName);

    let attempt = 0;
    let lastError = null;
    while (attempt < fetchMaxAttempts) {
      attempt += 1;
      try {
        if (provider && typeof provider.fetchSecret === "function") {
          const raw = await withTimeout(
            provider.fetchSecret({
              secretName,
              secretVersion: entry.secretVersion,
              executionId,
              toolSlug,
              principalId,
              timeoutMs: fetchTimeoutMs,
            }),
            fetchTimeoutMs,
            "SECRET_FETCH_TIMEOUT",
            "Secret fetch timed out",
          );
          const normalized = normalizeFetchResult(raw);
          if (normalized.found && normalizeString(normalized.value)) {
            auditLogger.log({
              event: "secret_fetch",
              principal_id: principalId || "anonymous",
              slug: toolSlug,
              request_id: executionId,
              status: "success",
              details: {
                node_id: nodeId,
                secret_name_hash: hashSecretName(secretName),
                secret_version: entry.secretVersion,
                source: "external_store",
              },
            });
            return {
              found: true,
              value: normalized.value,
              source: "external_store",
            };
          }
        }
        return {
          found: false,
          value: "",
          source: "external_store",
        };
      } catch (error) {
        lastError = error;
        if (attempt >= fetchMaxAttempts) {
          metrics.increment("secret.fetch.failure", {
            node_id: nodeId,
            tool: toolSlug || "unknown",
            principal_hash: hashPrincipal(principalId),
          });
          throw makeFailure("SECRET_FETCH_FAILURE", "Secret fetch failed", {
            secretNameHash: hashSecretName(secretName),
            attempt,
            reason: error && error.message ? error.message : String(error),
          });
        }
      }
    }

    if (lastError) {
      throw lastError;
    }
    return {
      found: false,
      value: "",
      source: "external_store",
    };
  }

  function resolveEnvFallbackValue(entry) {
    if (production || !allowEnvFallbackNonProd) {
      return {
        found: false,
        value: "",
      };
    }

    const envKey = secretNameToEnvKey(entry.secretName);
    const fallbackValue = process.env[envKey];
    if (typeof fallbackValue === "string" && fallbackValue.length > 0) {
      metrics.increment("secret.fetch.fallback.nonprod", {
        node_id: nodeId,
        secret_name_hash: hashSecretName(entry.secretName),
      });
      return {
        found: true,
        value: fallbackValue,
      };
    }

    return {
      found: false,
      value: "",
    };
  }

  async function getExecutionSecrets(input = {}) {
    assertInitialized();
    const executionId = normalizeString(input.executionId);
    const toolSlug = normalizeString(input.toolSlug).toLowerCase();
    const principalId = normalizeString(input.principalId);
    if (!executionId) {
      throw makeFailure("SECRET_AUTHORITY_INVALID_INPUT", "executionId is required", {});
    }
    if (!toolSlug) {
      throw makeFailure("SECRET_AUTHORITY_INVALID_INPUT", "toolSlug is required", {});
    }
    if (!principalId) {
      throw makeFailure("SECRET_AUTHORITY_INVALID_INPUT", "principalId is required", {});
    }

    if (executionSecrets.has(executionId)) {
      releaseExecutionSecrets(executionId);
    }

    const scopedEntries = getScopedSecretEntries(input);
    const env = {};
    const buffers = [];
    const secretNameHashes = [];

    for (const entry of scopedEntries) {
      const fetchResult = await fetchSecretValue(entry, {
        executionId,
        toolSlug,
        principalId,
      });

      let resolved = fetchResult;
      if (!resolved.found) {
        const fallback = resolveEnvFallbackValue(entry);
        if (fallback.found) {
          resolved = {
            found: true,
            value: fallback.value,
            source: "env_fallback_nonprod",
          };
        }
      }

      if (!resolved.found) {
        if (production && entry.productionRequired === true) {
          throw makeFailure("REQUIRED_SECRET_UNAVAILABLE", "Required production secret is unavailable", {
            secret_name_hash: hashSecretName(entry.secretName),
            tool_slug: toolSlug,
            principal_hash: hashPrincipal(principalId),
          });
        }
        continue;
      }

      const envKey = secretNameToEnvKey(entry.secretName);
      const value = String(resolved.value);
      const buffer = Buffer.from(value, "utf8");
      env[envKey] = buffer.toString("utf8");
      buffers.push(buffer);
      secretNameHashes.push(hashSecretName(entry.secretName));
    }

    executionSecrets.set(executionId, {
      executionId,
      createdAt: Date.now(),
      buffers,
      secretNameHashes: secretNameHashes.slice().sort((a, b) => a.localeCompare(b)),
    });

    metrics.increment("secret.injection", {
      node_id: nodeId,
      tool: toolSlug || "unknown",
      principal_hash: hashPrincipal(principalId),
      secret_count: String(buffers.length),
    });
    auditLogger.log({
      event: "secret_injection",
      principal_id: principalId,
      slug: toolSlug,
      request_id: executionId,
      status: "success",
      details: {
        node_id: nodeId,
        secret_count: buffers.length,
        secret_name_hashes: secretNameHashes.slice().sort((a, b) => a.localeCompare(b)),
      },
    });

    return {
      env,
      executionSecretRef: {
        executionId,
      },
    };
  }

  function releaseExecutionSecrets(input) {
    const executionId =
      typeof input === "string"
        ? normalizeString(input)
        : normalizeString(input && input.executionId);
    if (!executionId) {
      return {
        ok: true,
        released: false,
      };
    }

    const state = executionSecrets.get(executionId);
    if (!state) {
      return {
        ok: true,
        released: false,
      };
    }

    if (Array.isArray(state.buffers)) {
      for (const buffer of state.buffers) {
        try {
          if (Buffer.isBuffer(buffer)) {
            buffer.fill(0);
          }
        } catch {}
      }
    }

    state.buffers = [];
    state.secretNameHashes = [];
    executionSecrets.delete(executionId);
    return {
      ok: true,
      released: true,
    };
  }

  function evaluatePeerSecretPosture(peers = []) {
    const now = Date.now();
    const criticalMismatches = [];
    const warnings = [];

    if (!initialized || !manifestHash) {
      const missingLocal = {
        classification: "MISSING_SECRET_MANIFEST",
        peerId: "local",
      };
      if (production) {
        criticalMismatches.push(missingLocal);
      } else {
        warnings.push(missingLocal);
      }
      lastPeerSummary = {
        ok: criticalMismatches.length === 0,
        status: criticalMismatches.length === 0 ? "aligned" : "mismatch",
        criticalMismatches,
        warnings,
        timestamp: now,
      };
      return lastPeerSummary;
    }

    const healthyPeers = Array.isArray(peers)
      ? peers.filter((peer) => normalizeString(peer && peer.status).toUpperCase() === "UP")
      : [];

    for (const peer of healthyPeers) {
      const peerId = normalizeString(peer.peerId) || "unknown-peer";
      const peerHash =
        normalizeString(peer.secretManifestHash || peer.secret_manifest_hash).toLowerCase();

      if (!/^[a-f0-9]{64}$/.test(peerHash)) {
        const entry = {
          classification: "MISSING_SECRET_MANIFEST",
          peerId,
        };
        if (production) {
          criticalMismatches.push(entry);
        } else {
          warnings.push(entry);
        }
        continue;
      }

      if (peerHash !== manifestHash) {
        metrics.increment("secret.manifest.hash.mismatch", {
          node_id: nodeId,
          peer_id: peerId,
        });
        const entry = {
          classification: "SECRET_MANIFEST_MISMATCH",
          peerId,
          localSecretManifestHash: manifestHash,
          peerSecretManifestHash: peerHash,
        };
        if (production) {
          criticalMismatches.push(entry);
        } else {
          warnings.push(entry);
        }
      }
    }

    lastPeerSummary = {
      ok: criticalMismatches.length === 0,
      status: criticalMismatches.length === 0 ? "aligned" : "mismatch",
      criticalMismatches,
      warnings,
      timestamp: now,
    };

    return lastPeerSummary;
  }

  function getActiveMetadata() {
    if (!initialized) {
      return {
        nodeId,
        secretManifestHash: "",
        secretManifestPath: manifestPath || "",
        secretManifestLoaded: false,
      };
    }

    return {
      nodeId,
      secretManifestHash: manifestHash,
      secretManifestPath: manifestPath,
      secretManifestLoaded: true,
      secretCount: Array.isArray(manifestCanonical && manifestCanonical.secrets)
        ? manifestCanonical.secrets.length
        : 0,
    };
  }

  async function close() {
    for (const executionId of Array.from(executionSecrets.keys())) {
      releaseExecutionSecrets(executionId);
    }
    if (provider && typeof provider.close === "function") {
      try {
        await provider.close();
      } catch {}
    }
  }

  return {
    initialize,
    getExecutionSecrets,
    releaseExecutionSecrets,
    evaluatePeerSecretPosture,
    getActiveMetadata,
    close,
  };
}

module.exports = {
  createSecretAuthority,
  resolveDefaultSecretManifestPath,
  createRedisSecretProvider,
};
