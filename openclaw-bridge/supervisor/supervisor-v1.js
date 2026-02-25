const crypto = require("node:crypto");
const http = require("node:http");

const { createMetrics } = require("../observability/metrics.js");
const { createAuthGuard } = require("../security/auth.js");
const { createAuditLogger } = require("../security/audit-logger.js");
const { createRateLimiter } = require("../security/rate-limit.js");
const { CONTROL_PLANE_STATE_VERSION } = require("../state/persistent-store.js");
const { createStateManager } = require("../state/state-manager.js");
const { createSpawnerV2 } = require("../spawner/spawner-v2.js");
const { createPeerRegistry, STATUS_DOWN, STATUS_UP } = require("../federation/peer-registry.js");
const { createRemoteExecutionClient } = require("../federation/remote-client.js");
const { createPeerHeartbeat } = require("../federation/heartbeat.js");
const { createClusterManager } = require("../cluster/cluster-manager.js");
const { createCircuitBreaker } = require("./circuit-breaker.js");
const { RequestQueue } = require("./request-queue.js");
const { registerBatch1Tools } = require("../tools/adapters/index.js");
const { registerBatch2Tools } = require("../tools/adapters/batch-2-index.js");
const { registerBatch3Tools } = require("../tools/adapters/batch-3-index.js");
const { createToolRegistry } = require("../tools/tool-registry.js");
const { createToolValidator } = require("../tools/tool-validator.js");

const SKILL_CONFIG = Object.freeze({
  nmap: Object.freeze({
    maxInstances: 5,
    idleTTLms: 60000,
  }),
});

const ALLOWED_METHODS = Object.freeze([
  "run",
  "health",
  "read_output_chunk",
  "search_output",
  "semantic_summary",
  "anomaly_summary",
  "anomaly_diff",
  "tag_baseline",
  "list_baselines",
  "diff_against_baseline",
]);

const METHOD_SET = new Set(ALLOWED_METHODS);
const DEFAULT_REQUEST_TIMEOUT_MS = 60000;
const DEFAULT_RETRY_POLICY = Object.freeze({
  retries: 3,
  delayMs: 1000,
  backoffFactor: 2,
});
const NON_IDEMPOTENT_METHODS = new Set(["run", "tag_baseline"]);

function createNoopMetrics() {
  return {
    increment: () => {},
    observe: () => {},
    gauge: () => {},
    snapshot: () => ({ counters: [], histograms: [], gauges: [] }),
    reset: () => {},
  };
}

function createSafeMetrics(rawMetrics) {
  const noop = createNoopMetrics();
  const source = rawMetrics && typeof rawMetrics === "object" ? rawMetrics : noop;

  return {
    increment: (...args) => {
      try {
        if (typeof source.increment === "function") {
          source.increment(...args);
        }
      } catch {}
    },
    observe: (...args) => {
      try {
        if (typeof source.observe === "function") {
          source.observe(...args);
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
    snapshot: () => {
      try {
        if (typeof source.snapshot === "function") {
          return source.snapshot();
        }
      } catch {}
      return { counters: [], histograms: [], gauges: [] };
    },
    reset: () => {
      try {
        if (typeof source.reset === "function") {
          source.reset();
        }
      } catch {}
    },
  };
}

class Mutex {
  constructor() {
    this.locked = false;
    this.waiters = [];
  }

  acquire() {
    if (!this.locked) {
      this.locked = true;
      return Promise.resolve(this.release.bind(this));
    }

    return new Promise((resolve) => {
      this.waiters.push(resolve);
    }).then(() => this.release.bind(this));
  }

  release() {
    const next = this.waiters.shift();
    if (next) {
      next();
      return;
    }
    this.locked = false;
  }
}

function createSupervisorV1(options = {}) {
  const spawnerFactory = typeof options.spawnerFactory === "function" ? options.spawnerFactory : createSpawnerV2;
  const federationOptions = options.federation && typeof options.federation === "object" ? options.federation : {};
  const federationEnabled = Boolean(federationOptions.enabled);
  const clusterOptions = options.cluster && typeof options.cluster === "object" ? options.cluster : {};
  const clusterEnabled = Boolean(clusterOptions.enabled);
  const clusterNodeIdCandidate =
    typeof clusterOptions.nodeId === "string" && clusterOptions.nodeId.trim()
      ? clusterOptions.nodeId.trim()
      : typeof process.env.SUPERVISOR_NODE_ID === "string" && process.env.SUPERVISOR_NODE_ID.trim()
      ? process.env.SUPERVISOR_NODE_ID.trim()
      : "";
  const clusterShardCount = parsePositiveInt(clusterOptions.shardCount, 16);
  const clusterHeartbeatIntervalMs = parsePositiveInt(clusterOptions.heartbeatIntervalMs, 5000);
  const clusterLeaderTimeoutMs = parsePositiveInt(clusterOptions.leaderTimeoutMs, 15000);

  if (clusterEnabled && !federationEnabled) {
    throw new Error("cluster.enabled requires federation.enabled=true");
  }
  if (clusterEnabled && !clusterNodeIdCandidate) {
    throw new Error("cluster.nodeId is required when cluster.enabled=true");
  }

  const requestTimeoutMs = parsePositiveInt(options.requestTimeoutMs, DEFAULT_REQUEST_TIMEOUT_MS);
  const idempotencyEnabled = Boolean(options.idempotency && options.idempotency.enabled);
  const idempotencyTtlMs = parsePositiveInt(options.idempotency && options.idempotency.ttlMs, 300000);
  const idempotencyMaxEntries = parsePositiveInt(options.idempotency && options.idempotency.maxEntries, 1000);
  const queueEnabled = Boolean(options.queue && options.queue.enabled);
  const queueMaxLength = parsePositiveInt(options.queue && options.queue.maxLength, 100);
  const queuePollIntervalMs = parsePositiveInt(options.queue && options.queue.pollIntervalMs, 250);
  const stateOptions = options.state && typeof options.state === "object" ? options.state : {};
  const stateEnabled = stateOptions.enabled !== false;
  const stateQueueItemTtlMs = parsePositiveInt(stateOptions.queueItemTtlMs, 300000);
  const stateDebounceMs = parsePositiveInt(stateOptions.debounceMs, 1000);
  const stateStorePath = typeof stateOptions.path === "string" && stateOptions.path.trim() ? stateOptions.path.trim() : undefined;
  const circuitBreaker = createCircuitBreaker({
    enabled: Boolean(options.circuitBreaker && options.circuitBreaker.enabled),
    failureThreshold:
      options.circuitBreaker && typeof options.circuitBreaker.failureThreshold !== "undefined"
        ? options.circuitBreaker.failureThreshold
        : undefined,
    successThreshold:
      options.circuitBreaker && typeof options.circuitBreaker.successThreshold !== "undefined"
        ? options.circuitBreaker.successThreshold
        : undefined,
    timeout: options.circuitBreaker && typeof options.circuitBreaker.timeout !== "undefined" ? options.circuitBreaker.timeout : undefined,
  });
  const baseMetrics = options.metrics && typeof options.metrics === "object" ? options.metrics : createMetrics();
  const metrics = createSafeMetrics(baseMetrics);
  const authGuard = createAuthGuard({
    enabled: Boolean(options.auth && options.auth.enabled),
    mode: options.auth && typeof options.auth.mode === "string" ? options.auth.mode : "bearer",
    bearerToken: options.auth && typeof options.auth.bearerToken === "string" ? options.auth.bearerToken : "",
  });
  const rateLimiter = createRateLimiter({
    enabled: Boolean(options.rateLimit && options.rateLimit.enabled),
    rps: options.rateLimit && typeof options.rateLimit.rps !== "undefined" ? options.rateLimit.rps : undefined,
    burst: options.rateLimit && typeof options.rateLimit.burst !== "undefined" ? options.rateLimit.burst : undefined,
  });
  const auditLogger = createAuditLogger({
    enabled: options.auditLog && typeof options.auditLog.enabled !== "undefined" ? options.auditLog.enabled : true,
    path: options.auditLog && typeof options.auditLog.path === "string" ? options.auditLog.path : undefined,
    rotationPolicy:
      options.auditLog && options.auditLog.rotationPolicy && typeof options.auditLog.rotationPolicy === "object"
        ? options.auditLog.rotationPolicy
        : undefined,
  });
  const externalToolRegistry = options.toolRegistry && typeof options.toolRegistry.get === "function" ? options.toolRegistry : null;
  const toolRegistry = externalToolRegistry || createToolRegistry({ strict: false });
  registerBatch1Tools(toolRegistry);
  registerBatch2Tools(toolRegistry);
  registerBatch3Tools(toolRegistry);
  registerConfiguredToolAdapters(toolRegistry, options.toolAdapters);
  if (!externalToolRegistry && typeof toolRegistry.seal === "function") {
    toolRegistry.seal();
  }
  const toolValidator = createToolValidator(toolRegistry);
  const federationPeerRegistry = federationEnabled
    ? (() => {
        const candidate = federationOptions.peerRegistry;
        if (
          candidate &&
          typeof candidate.registerPeer === "function" &&
          typeof candidate.removePeer === "function" &&
          typeof candidate.listPeers === "function" &&
          typeof candidate.getHealthyPeersForSlug === "function" &&
          typeof candidate.updatePeerHealth === "function"
        ) {
          return candidate;
        }
        return createPeerRegistry({
          onChange: () => {
            scheduleStatePersist("peer_registry_change");
          },
        });
      })()
    : null;
  const federationRemoteClient = federationEnabled
    ? (() => {
        const candidate = federationOptions.remoteClient;
        if (candidate && typeof candidate.executeRemote === "function") {
          return candidate;
        }
        return createRemoteExecutionClient({
          timeoutMs: parsePositiveInt(federationOptions.timeoutMs, 30000),
        });
      })()
    : null;
  const federationHeartbeat = federationEnabled
    ? (() => {
        const candidate = federationOptions.heartbeat;
        if (candidate && typeof candidate.start === "function" && typeof candidate.stop === "function" && typeof candidate.runOnce === "function") {
          return candidate;
        }
        return createPeerHeartbeat({
          peerRegistry: federationPeerRegistry,
          intervalMs: parsePositiveInt(federationOptions.heartbeatIntervalMs, 60000),
          timeoutMs: parsePositiveInt(federationOptions.heartbeatTimeoutMs, 5000),
        });
      })()
    : null;

  const clusterManager = clusterEnabled
    ? createClusterManager({
        nodeId: clusterNodeIdCandidate,
        shardCount: clusterShardCount,
        heartbeatIntervalMs: clusterHeartbeatIntervalMs,
        leaderTimeoutMs: clusterLeaderTimeoutMs,
        peerRegistry: federationPeerRegistry,
        heartbeat: federationHeartbeat,
        metrics,
        localCapabilities: Object.keys(SKILL_CONFIG).map((slug) => String(slug || "").trim().toLowerCase()),
      })
    : null;

  if (federationEnabled && Array.isArray(federationOptions.peers)) {
    for (const peer of federationOptions.peers) {
      if (!peer || typeof peer !== "object") {
        continue;
      }
      const peerId = typeof peer.peerId === "string" ? peer.peerId : "";
      federationPeerRegistry.registerPeer(peerId, {
        url: peer.url,
        authToken: peer.authToken,
        status: peer.status,
        capabilities: peer.capabilities,
        lastLatencyMs: peer.lastLatencyMs,
        lastHeartbeat: peer.lastHeartbeat,
      });
    }
  }

  const spawner = spawnerFactory({ metrics });
  const pools = new Map();
  const instanceMetaById = new Map();
  const instanceTokenById = new Map();
  const pendingSpawnsBySlug = new Map();
  const reapReservationsBySlug = new Map();
  const idempotencyStore = new Map();
  const requestQueue = new RequestQueue(queueMaxLength);
  const slugLocks = new Map();
  const aggregateCounts = {
    total: 0,
    ready: 0,
    busy: 0,
    pending: 0,
  };

  let initialized = false;
  let isShuttingDown = false;
  let queueTimer = null;
  let queueProcessorActive = false;
  let statePersistenceInitialized = false;
  let suspendStatePersistence = false;
  const stateManager = stateEnabled
    ? createStateManager({
        version: CONTROL_PLANE_STATE_VERSION,
        path: stateStorePath,
        debounceMs: stateDebounceMs,
        buildState: buildPersistentStatePayload,
        applyState: restorePersistentState,
        onError: (error) => {
          const code = error && typeof error.code === "string" ? error.code : "STATE_PERSISTENCE_ERROR";
          const message = error && typeof error.message === "string" ? error.message : "State persistence failure";
          metrics.increment("supervisor.state.persistence.error", { code });
          safeAudit({
            event: "state_persistence_error",
            principal_id: "system",
            slug: "",
            request_id: "",
            status: "failure",
            details: {
              code,
              message,
            },
          });
        },
      })
    : null;

  function parsePositiveInt(value, fallback) {
    const parsed = Number.parseInt(String(value ?? "").trim(), 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      return fallback;
    }
    return parsed;
  }

  function parseNonNegativeInt(value, fallback) {
    const parsed = Number.parseInt(String(value ?? "").trim(), 10);
    if (!Number.isFinite(parsed) || parsed < 0) {
      return fallback;
    }
    return parsed;
  }

  function registerConfiguredToolAdapters(registry, toolAdapters) {
    if (!registry || typeof registry.register !== "function" || !toolAdapters) {
      return;
    }

    const registerOne = (slug, adapter, enabled = true) => {
      if (!slug || !adapter) {
        return;
      }
      registry.register(slug, adapter, { enabled });
    };

    if (Array.isArray(toolAdapters)) {
      for (const item of toolAdapters) {
        if (!item || typeof item !== "object") {
          continue;
        }
        registerOne(item.slug, item.adapter, item.enabled !== false);
      }
      return;
    }

    if (toolAdapters && typeof toolAdapters === "object") {
      for (const slug of Object.keys(toolAdapters)) {
        const entry = toolAdapters[slug];
        if (!entry) {
          continue;
        }
        if (entry && typeof entry === "object" && entry.adapter) {
          registerOne(slug, entry.adapter, entry.enabled !== false);
        } else {
          registerOne(slug, entry, true);
        }
      }
    }
  }

  function makeFailure(code, message, details) {
    const error = new Error(String(message || "Unexpected error"));
    error.code = String(code || "SUPERVISOR_ERROR");
    if (typeof details !== "undefined") {
      error.details = details;
    }
    return error;
  }

  function safeAudit(event) {
    try {
      auditLogger.log(event);
    } catch {}
  }

  function scheduleStatePersist(reason = "update") {
    if (!stateManager || !statePersistenceInitialized || suspendStatePersistence) {
      return;
    }
    stateManager.schedulePersist(reason);
  }

  function sanitizeRetryPolicyForPersistence(policy) {
    if (!policy || typeof policy !== "object") {
      return null;
    }
    return {
      retries: parseNonNegativeInt(policy.retries, 0),
      delayMs: parsePositiveInt(policy.delayMs, DEFAULT_RETRY_POLICY.delayMs),
      backoffFactor: Number.isFinite(Number(policy.backoffFactor)) && Number(policy.backoffFactor) > 0 ? Number(policy.backoffFactor) : DEFAULT_RETRY_POLICY.backoffFactor,
    };
  }

  function sanitizeQueueContextForPersistence(context) {
    if (!context || typeof context !== "object") {
      return {
        __queueRetryExecution: true,
      };
    }

    const persisted = {
      __queueRetryExecution: true,
    };

    if (typeof context.requestId === "string" && context.requestId.trim()) {
      persisted.requestId = context.requestId.trim().slice(0, 128);
    }
    if (typeof context.principalId === "string" && context.principalId.trim()) {
      persisted.principalId = context.principalId.trim();
    }
    if (typeof context.idempotencyKey === "string" && context.idempotencyKey.trim()) {
      persisted.idempotencyKey = context.idempotencyKey.trim().slice(0, 128);
    }

    const retryPolicy = sanitizeRetryPolicyForPersistence(context.retryPolicy);
    if (retryPolicy) {
      persisted.retryPolicy = retryPolicy;
    }

    return persisted;
  }

  function sanitizeQueueContextForRecovery(context) {
    const recovered = sanitizeQueueContextForPersistence(context);
    if (!recovered.principalId) {
      recovered.principalId = "anonymous";
    }
    return recovered;
  }

  function buildPersistentStatePayload() {
    const idempotencyEntries = Array.from(idempotencyStore.entries())
      .map(([key, entry]) => ({
        key,
        createdAt: entry && Number.isFinite(Number(entry.createdAt)) ? Number(entry.createdAt) : 0,
        paramsHash: entry && typeof entry.paramsHash === "string" ? entry.paramsHash : "",
        result: entry ? cloneForIdempotency(entry.result) : null,
        error: entry ? cloneForIdempotency(entry.error) : null,
      }))
      .sort((a, b) => {
        if (a.createdAt !== b.createdAt) {
          return a.createdAt - b.createdAt;
        }
        return String(a.key || "").localeCompare(String(b.key || ""));
      });

    const queueItems = requestQueue.toArray().map((item) => ({
      slug: item && typeof item.slug === "string" ? item.slug : "",
      method: item && typeof item.method === "string" ? item.method : "",
      params: item ? cloneForIdempotency(item.params) : {},
      requestContext: sanitizeQueueContextForPersistence(item && item.requestContext),
      nextExecutionTime: item && Number.isFinite(Number(item.nextExecutionTime)) ? Number(item.nextExecutionTime) : Date.now(),
      enqueuedAt: item && Number.isFinite(Number(item.enqueuedAt)) ? Number(item.enqueuedAt) : Date.now(),
    }));

    const circuitBreakerState =
      circuitBreaker && typeof circuitBreaker.exportState === "function" ? circuitBreaker.exportState() : [];
    const peerRegistryMetadata =
      federationPeerRegistry && typeof federationPeerRegistry.exportMetadata === "function" ? federationPeerRegistry.exportMetadata() : [];

    return {
      idempotencyStore: idempotencyEntries,
      requestQueue: {
        maxLength: queueMaxLength,
        items: queueItems,
      },
      circuitBreakerState,
      peerRegistryMetadata,
    };
  }

  async function restorePersistentState(rawPayload) {
    if (!rawPayload || typeof rawPayload !== "object") {
      return;
    }

    const now = Date.now();

    if (idempotencyEnabled) {
      idempotencyStore.clear();
      const idempotencyEntries = Array.isArray(rawPayload.idempotencyStore) ? rawPayload.idempotencyStore : [];
      idempotencyEntries
        .filter((item) => item && typeof item === "object")
        .sort((a, b) => {
          const createdAtA = Number.isFinite(Number(a.createdAt)) ? Number(a.createdAt) : 0;
          const createdAtB = Number.isFinite(Number(b.createdAt)) ? Number(b.createdAt) : 0;
          if (createdAtA !== createdAtB) {
            return createdAtA - createdAtB;
          }
          return String(a.key || "").localeCompare(String(b.key || ""));
        })
        .forEach((item) => {
          const key = typeof item.key === "string" ? item.key : "";
          const paramsHash = typeof item.paramsHash === "string" ? item.paramsHash : "";
          const createdAt = Number.isFinite(Number(item.createdAt)) ? Math.max(0, Number(item.createdAt)) : 0;
          if (!key || !paramsHash) {
            return;
          }
          if (now - createdAt > idempotencyTtlMs) {
            return;
          }
          idempotencyStore.set(key, {
            createdAt,
            paramsHash,
            result: Object.prototype.hasOwnProperty.call(item, "result") ? cloneForIdempotency(item.result) : null,
            error: Object.prototype.hasOwnProperty.call(item, "error") ? cloneForIdempotency(item.error) : null,
          });
        });
      pruneIdempotencyStore(now);
    }

    if (queueEnabled) {
      const queueItems = Array.isArray(rawPayload.requestQueue && rawPayload.requestQueue.items)
        ? rawPayload.requestQueue.items
        : [];
      const recoveredQueue = [];
      for (const item of queueItems) {
        if (!item || typeof item !== "object") {
          continue;
        }
        const slug = typeof item.slug === "string" ? item.slug : "";
        const method = typeof item.method === "string" ? item.method : "";
        if (!slug || !method) {
          continue;
        }
        if (item.inFlight === true || (item.requestContext && item.requestContext.__inFlightExecution === true)) {
          continue;
        }

        const enqueuedAt = Number.isFinite(Number(item.enqueuedAt)) ? Math.max(0, Number(item.enqueuedAt)) : now;
        const nextExecutionTime = Number.isFinite(Number(item.nextExecutionTime)) ? Math.max(0, Number(item.nextExecutionTime)) : now;
        const queueAge = now - Math.max(enqueuedAt, nextExecutionTime);
        if (queueAge > stateQueueItemTtlMs) {
          continue;
        }

        recoveredQueue.push({
          slug,
          method,
          params: cloneForIdempotency(item.params),
          requestContext: sanitizeQueueContextForRecovery(item.requestContext),
          nextExecutionTime: Math.max(now, nextExecutionTime),
          enqueuedAt,
        });
      }
      requestQueue.fromArray(recoveredQueue);
      publishQueueGauge();
    }

    if (circuitBreaker && typeof circuitBreaker.importState === "function") {
      circuitBreaker.importState(rawPayload.circuitBreakerState, {
        resetHalfOpenToOpen: true,
      });

      const circuitSlugs = new Set(Object.keys(SKILL_CONFIG));
      if (Array.isArray(rawPayload.circuitBreakerState)) {
        for (const item of rawPayload.circuitBreakerState) {
          if (!item || typeof item !== "object" || typeof item.slug !== "string") {
            continue;
          }
          const slug = item.slug.trim().toLowerCase();
          if (slug) {
            circuitSlugs.add(slug);
          }
        }
      }
      for (const slug of Array.from(circuitSlugs).sort((a, b) => a.localeCompare(b))) {
        publishCircuitGauges(slug, circuitBreaker.getSnapshot(slug));
      }
    }

    if (federationEnabled && federationPeerRegistry && typeof federationPeerRegistry.importMetadata === "function") {
      federationPeerRegistry.importMetadata(rawPayload.peerRegistryMetadata);
    }
  }

  function isSpawnerError(value) {
    return Boolean(value && typeof value === "object" && value.ok === false && value.error && typeof value.error.code === "string");
  }

  function getSlugMutex(slug) {
    let mutex = slugLocks.get(slug);
    if (!mutex) {
      mutex = new Mutex();
      slugLocks.set(slug, mutex);
    }
    return mutex;
  }

  async function withSlugLock(slug, fn) {
    const mutex = getSlugMutex(slug);
    const release = await mutex.acquire();
    try {
      return await fn();
    } finally {
      release();
    }
  }

  function normalizeSlug(rawSlug) {
    return typeof rawSlug === "string" ? rawSlug.trim().toLowerCase() : "";
  }

  function normalizeMethod(rawMethod) {
    return typeof rawMethod === "string" ? rawMethod.trim() : "";
  }

  function resolveRequestId(requestContext) {
    const explicit = requestContext && typeof requestContext.requestId === "string" ? requestContext.requestId.trim() : "";
    if (explicit && explicit.length <= 128) {
      return explicit;
    }
    if (typeof crypto.randomUUID === "function") {
      return crypto.randomUUID();
    }
    return crypto.randomBytes(16).toString("hex");
  }

  function resolvePrincipalId(requestContext) {
    const explicit = requestContext && typeof requestContext.principalId === "string" ? requestContext.principalId.trim() : "";
    return explicit || "anonymous";
  }

  function normalizeIdempotencyKey(requestContext) {
    if (!requestContext || typeof requestContext !== "object" || typeof requestContext.idempotencyKey !== "string") {
      return "";
    }
    const key = requestContext.idempotencyKey.trim();
    if (!key || key.length > 128) {
      return "";
    }
    return key;
  }

  function normalizeRetryPolicy(requestContext) {
    if (!requestContext || typeof requestContext !== "object" || !requestContext.retryPolicy || typeof requestContext.retryPolicy !== "object") {
      return null;
    }
    const source = requestContext.retryPolicy;
    const retries = parseNonNegativeInt(source.retries, DEFAULT_RETRY_POLICY.retries);
    const delayMs = parsePositiveInt(source.delayMs, DEFAULT_RETRY_POLICY.delayMs);
    const rawBackoff = Number(source.backoffFactor);
    const backoffFactor = Number.isFinite(rawBackoff) && rawBackoff > 0 ? rawBackoff : DEFAULT_RETRY_POLICY.backoffFactor;
    return {
      retries,
      delayMs,
      backoffFactor,
    };
  }

  function isRetryEligibleMethod(method) {
    return NON_IDEMPOTENT_METHODS.has(method);
  }

  function stableStringify(value) {
    const seen = new WeakSet();
    const encoded = JSON.stringify(value, (key, input) => {
      if (typeof input === "bigint") {
        return input.toString();
      }
      if (input && typeof input === "object") {
        if (seen.has(input)) {
          return "[Circular]";
        }
        seen.add(input);
        if (Array.isArray(input)) {
          return input;
        }
        const ordered = {};
        for (const childKey of Object.keys(input).sort()) {
          ordered[childKey] = input[childKey];
        }
        return ordered;
      }
      return input;
    });
    return typeof encoded === "string" ? encoded : String(encoded);
  }

  function cloneForIdempotency(value) {
    try {
      if (typeof globalThis.structuredClone === "function") {
        return globalThis.structuredClone(value);
      }
    } catch {}
    try {
      return JSON.parse(JSON.stringify(value));
    } catch {
      return value;
    }
  }

  function makeIdempotencyStoreKey(principalId, slug, method, paramsHash, idempotencyKey) {
    const keyMaterial = stableStringify({
      principalId,
      slug,
      method,
      paramsHash,
      idempotencyKey,
    });
    const digest = crypto.createHash("sha256").update(keyMaterial, "utf8").digest("hex");
    return `idem:v2:${digest}`;
  }

  function pruneIdempotencyStore(now) {
    if (!idempotencyEnabled) {
      return;
    }
    let changed = false;

    while (idempotencyStore.size > 0) {
      const oldestKey = idempotencyStore.keys().next().value;
      if (typeof oldestKey === "undefined") {
        break;
      }
      const oldestEntry = idempotencyStore.get(oldestKey);
      if (!oldestEntry || now - oldestEntry.createdAt > idempotencyTtlMs) {
        idempotencyStore.delete(oldestKey);
        changed = true;
        continue;
      }
      break;
    }

    while (idempotencyStore.size > idempotencyMaxEntries) {
      const oldestKey = idempotencyStore.keys().next().value;
      if (typeof oldestKey === "undefined") {
        break;
      }
      idempotencyStore.delete(oldestKey);
      changed = true;
    }

    if (changed) {
      scheduleStatePersist("idempotency_prune");
    }
  }

  function readIdempotencyReplay(storeKey, paramsHash, now) {
    if (!idempotencyEnabled || !storeKey) {
      return null;
    }
    const entry = idempotencyStore.get(storeKey);
    if (!entry) {
      return null;
    }
    if (now - entry.createdAt > idempotencyTtlMs) {
      idempotencyStore.delete(storeKey);
      scheduleStatePersist("idempotency_expired");
      return null;
    }
    if (entry.paramsHash !== paramsHash) {
      return null;
    }

    if (entry.error !== null) {
      return {
        kind: "runtime_error",
        payload: cloneForIdempotency(entry.error),
      };
    }

    return {
      kind: "result",
      payload: cloneForIdempotency(entry.result),
    };
  }

  function storeIdempotencyOutcome(storeKey, paramsHash, outcomeKind, payload) {
    if (!idempotencyEnabled || !storeKey) {
      return;
    }
    const now = Date.now();
    pruneIdempotencyStore(now);

    if (idempotencyStore.has(storeKey)) {
      idempotencyStore.delete(storeKey);
    }

    idempotencyStore.set(storeKey, {
      createdAt: now,
      paramsHash,
      result: outcomeKind === "result" ? cloneForIdempotency(payload) : null,
      error: outcomeKind === "runtime_error" ? cloneForIdempotency(payload) : null,
    });

    pruneIdempotencyStore(now);
    scheduleStatePersist("idempotency_store");
  }

  function publishQueueGauge() {
    metrics.gauge("supervisor.queue.length", requestQueue.length);
  }

  function circuitStateMetricValue(state) {
    if (state === "OPEN") {
      return 0;
    }
    if (state === "HALF_OPEN") {
      return 1;
    }
    return 2;
  }

  function publishCircuitGauges(slug, snapshot) {
    if (!circuitBreaker.enabled || !snapshot) {
      return;
    }
    metrics.gauge("supervisor.circuit_breaker.state", circuitStateMetricValue(snapshot.state), { slug });
    metrics.gauge("supervisor.skill.health", snapshot.healthScore, { slug });
  }

  function applyCircuitTransitionMetrics(slug, transition, context = {}) {
    if (!circuitBreaker.enabled || !transition || !transition.transitioned) {
      return;
    }

    scheduleStatePersist("circuit_transition");
    publishCircuitGauges(slug, transition.snapshot);
    if (transition.to === "OPEN") {
      metrics.increment("supervisor.circuit_breaker.trips", { slug });
      safeAudit({
        event: "circuit_trip",
        principal_id: typeof context.principalId === "string" ? context.principalId : "system",
        slug,
        request_id: typeof context.requestId === "string" ? context.requestId : "",
        status: "failure",
        details: {
          from: transition.from,
          to: transition.to,
          failureCount: transition.snapshot.failureCount,
        },
      });
      return;
    }
    if (transition.to === "CLOSED") {
      metrics.increment("supervisor.circuit_breaker.recoveries", { slug });
      safeAudit({
        event: "circuit_recovery",
        principal_id: typeof context.principalId === "string" ? context.principalId : "system",
        slug,
        request_id: typeof context.requestId === "string" ? context.requestId : "",
        status: "success",
        details: {
          from: transition.from,
          to: transition.to,
          successCount: transition.snapshot.successCount,
        },
      });
    }
  }

  function buildCircuitOpenDetails(slug) {
    const snapshot = circuitBreaker.getSnapshot(slug);
    const nextRetryAt = snapshot.state === "OPEN" ? snapshot.lastTransitionAt + circuitBreaker.constants.timeoutMs : Date.now();
    return {
      slug,
      state: snapshot.state,
      failureCount: snapshot.failureCount,
      nextRetryAt,
    };
  }

  function buildRetryContext(baseContext, principalId, nextRetryPolicy) {
    return {
      ...baseContext,
      principalId,
      retryPolicy: nextRetryPolicy,
      __queueRetryExecution: true,
    };
  }

  function enqueueRetryRequest({ slug, method, params, requestContext, principalId, retryPolicy, requestId }) {
    if (!queueEnabled || !retryPolicy || retryPolicy.retries <= 0 || !isRetryEligibleMethod(method)) {
      return { queued: false, reason: "not_eligible" };
    }

    if (requestQueue.length >= queueMaxLength) {
      metrics.increment("supervisor.capacity.rejection.due.to.queue", { slug, method, request_id: requestId });
      metrics.increment("supervisor.retry.failure", { slug, reason: "queue_full", request_id: requestId });
      return { queued: false, reason: "queue_full" };
    }

    const remainingRetries = retryPolicy.retries - 1;
    const nextRetryPolicy = {
      retries: Math.max(remainingRetries, 0),
      delayMs: Math.max(1, Math.floor(retryPolicy.delayMs * retryPolicy.backoffFactor)),
      backoffFactor: retryPolicy.backoffFactor,
    };
    const now = Date.now();
    const queued = requestQueue.enqueue({
      slug,
      method,
      params,
      requestContext: buildRetryContext(requestContext, principalId, nextRetryPolicy),
      nextExecutionTime: now + retryPolicy.delayMs,
      enqueuedAt: now,
    });

    if (!queued) {
      metrics.increment("supervisor.capacity.rejection.due.to.queue", { slug, method, request_id: requestId });
      metrics.increment("supervisor.retry.failure", { slug, reason: "queue_full", request_id: requestId });
      return { queued: false, reason: "queue_full" };
    }

    metrics.increment("supervisor.retries.count", { slug, method, request_id: requestId });
    publishQueueGauge();
    scheduleStatePersist("queue_enqueue");

    return {
      queued: true,
      remainingRetries,
    };
  }

  function attachRequestId(error, requestId) {
    if (!error || typeof error !== "object" || !requestId) {
      return error;
    }
    error.request_id = requestId;
    if (!error.details || typeof error.details !== "object") {
      error.details = {};
    }
    error.details.request_id = requestId;
    return error;
  }

  function getConfig(slug) {
    return SKILL_CONFIG[slug] || null;
  }

  function initializeCircuitMetrics() {
    if (!circuitBreaker.enabled) {
      return;
    }
    const slugs = Object.keys(SKILL_CONFIG).sort();
    for (const slug of slugs) {
      publishCircuitGauges(slug, circuitBreaker.getSnapshot(slug));
    }
  }

  function getOrCreatePool(slug) {
    let pool = pools.get(slug);
    if (!pool) {
      pool = { instances: new Map() };
      pools.set(slug, pool);
    }
    return pool;
  }

  function getExistingPool(slug) {
    return pools.get(slug) || null;
  }

  function getPendingSpawns(slug) {
    return pendingSpawnsBySlug.get(slug) || 0;
  }

  function isQueueRetryExecution(requestContext) {
    return Boolean(requestContext && requestContext.__queueRetryExecution === true);
  }

  function isLocalCapacityExhausted(slug) {
    const config = getConfig(slug);
    if (!config) {
      return false;
    }
    const pool = getExistingPool(slug);
    const instanceCount = pool ? pool.instances.size : 0;
    const pending = getPendingSpawns(slug);
    return instanceCount + pending >= config.maxInstances;
  }

  function resolveRemoteExecutionPayload(remoteResponse) {
    if (!remoteResponse || typeof remoteResponse !== "object") {
      return { ok: false };
    }

    if (Object.prototype.hasOwnProperty.call(remoteResponse, "result")) {
      return {
        ok: true,
        payload: remoteResponse.result,
      };
    }

    if (remoteResponse.ok === true && remoteResponse.data && typeof remoteResponse.data === "object" && Object.prototype.hasOwnProperty.call(remoteResponse.data, "result")) {
      return {
        ok: true,
        payload: remoteResponse.data.result,
      };
    }

    if (remoteResponse.ok === false && remoteResponse.error && typeof remoteResponse.error === "object") {
      return {
        ok: true,
        payload: {
          ok: false,
          error: remoteResponse.error,
        },
      };
    }

    return { ok: false };
  }

  function isRemoteTimeoutFailure(remoteResult) {
    if (!remoteResult || remoteResult.ok !== false || !remoteResult.error) {
      return false;
    }
    const code = typeof remoteResult.error.code === "string" ? remoteResult.error.code : "";
    if (code !== "REMOTE_TRANSPORT_ERROR") {
      return false;
    }
    const message =
      remoteResult.error.details && typeof remoteResult.error.details.message === "string"
        ? remoteResult.error.details.message
        : typeof remoteResult.error.message === "string"
        ? remoteResult.error.message
        : "";
    return /timeout/i.test(message);
  }

  function getRemoteStatusCode(remoteResult) {
    if (!remoteResult || remoteResult.ok !== false || !remoteResult.error || !remoteResult.error.details) {
      return 0;
    }
    const statusCode = Number(remoteResult.error.details.statusCode);
    if (!Number.isFinite(statusCode)) {
      return 0;
    }
    return Math.floor(statusCode);
  }

  function getRemoteLatencyMs(remoteResult) {
    if (remoteResult && remoteResult.ok === true && Number.isFinite(Number(remoteResult.latencyMs))) {
      return Number(remoteResult.latencyMs);
    }
    if (remoteResult && remoteResult.ok === false && remoteResult.error && remoteResult.error.details && Number.isFinite(Number(remoteResult.error.details.latencyMs))) {
      return Number(remoteResult.error.details.latencyMs);
    }
    return 0;
  }

  function buildFederationRemotePayload({ slug, method, params, requestId, idempotencyKey, retryPolicy, principalId }) {
    const remotePayload = {
      slug,
      method,
      params,
      request_id: requestId,
      principalId,
    };

    if (idempotencyKey) {
      remotePayload.idempotencyKey = idempotencyKey;
    }
    if (retryPolicy) {
      remotePayload.retryPolicy = retryPolicy;
    }

    return remotePayload;
  }

  async function executeRemotePeerAttempt({
    peer,
    slug,
    method,
    params,
    requestId,
    idempotencyKey,
    retryPolicy,
    principalId,
    auditPhase = "federation_success",
  }) {
    const remotePayload = buildFederationRemotePayload({
      slug,
      method,
      params,
      requestId,
      idempotencyKey,
      retryPolicy,
      principalId,
    });

    const remoteResult = await federationRemoteClient.executeRemote(peer, remotePayload);
    const latencyMs = getRemoteLatencyMs(remoteResult);
    if (latencyMs > 0) {
      metrics.observe("supervisor.federation.latency_ms", latencyMs, { slug });
      federationPeerRegistry.updatePeerHealth(peer.peerId, {
        lastLatencyMs: latencyMs,
        lastHeartbeat: Date.now(),
      });
      scheduleStatePersist("peer_registry_health");
    }

    if (remoteResult && remoteResult.ok === true) {
      const resolved = resolveRemoteExecutionPayload(remoteResult.response);
      if (!resolved.ok) {
        metrics.increment("supervisor.federation.failure", { slug, reason: "invalid_remote_response" });
        return {
          success: false,
          invalidResponse: true,
          timeoutFailure: false,
          statusCode: 0,
        };
      }

      federationPeerRegistry.updatePeerHealth(peer.peerId, {
        status: STATUS_UP,
        lastHeartbeat: Date.now(),
      });
      scheduleStatePersist("peer_registry_up");

      if (remoteResult.replayed === true || remoteResult.idempotentReplay === true) {
        metrics.increment("supervisor.federation.idempotent_replay", { slug });
        metrics.increment("supervisor.federation.duplicate_prevented", { slug });
      }

      metrics.increment("supervisor.federation.success", { slug });
      safeAudit({
        event: "execute",
        principal_id: principalId,
        slug,
        request_id: requestId,
        status: "success",
        details: {
          phase: auditPhase,
          method,
          peerId: peer.peerId,
        },
      });

      return {
        success: true,
        payload: resolved.payload,
        timeoutFailure: false,
        statusCode: Number.isFinite(Number(remoteResult.statusCode)) ? Number(remoteResult.statusCode) : 0,
      };
    }

    const statusCode = getRemoteStatusCode(remoteResult);
    const timeoutFailure = isRemoteTimeoutFailure(remoteResult);
    const reasonCode =
      remoteResult && remoteResult.error && typeof remoteResult.error.code === "string" ? remoteResult.error.code : "remote_error";

    if (timeoutFailure) {
      federationPeerRegistry.updatePeerHealth(peer.peerId, {
        status: STATUS_DOWN,
        lastHeartbeat: Date.now(),
      });
      scheduleStatePersist("peer_registry_down");
      metrics.increment("supervisor.federation.peer_down", { slug });
      metrics.increment("supervisor.federation.failure", { slug, reason: "timeout" });
      return {
        success: false,
        timeoutFailure: true,
        statusCode,
        reasonCode,
      };
    }

    if (statusCode === 429 || statusCode === 503) {
      metrics.increment("supervisor.federation.failure", { slug, reason: String(statusCode) });
    } else {
      metrics.increment("supervisor.federation.failure", { slug, reason: reasonCode });
    }

    return {
      success: false,
      timeoutFailure: false,
      statusCode,
      reasonCode,
    };
  }

  async function attemptFederatedExecution({ slug, method, params, requestId, idempotencyKey, retryPolicy, principalId }) {
    if (!federationEnabled || !federationPeerRegistry || !federationRemoteClient) {
      return { attempted: false, success: false };
    }

    const peers = federationPeerRegistry.getHealthyPeersForSlug(slug);
    if (!Array.isArray(peers) || peers.length === 0) {
      return { attempted: false, success: false };
    }

    metrics.increment("supervisor.federation.attempt", { slug });
    let attempted = false;

    for (const peer of peers) {
      attempted = true;
      const attempt = await executeRemotePeerAttempt({
        peer,
        slug,
        method,
        params,
        requestId,
        idempotencyKey,
        retryPolicy,
        principalId,
        auditPhase: "federation_success",
      });

      if (attempt && attempt.success) {
        return {
          attempted: true,
          success: true,
          payload: attempt.payload,
        };
      }

      const timeoutFailure = Boolean(attempt && attempt.timeoutFailure);
      const statusCode = Number.isFinite(Number(attempt && attempt.statusCode)) ? Number(attempt.statusCode) : 0;

      if (timeoutFailure) {
        if (!idempotencyKey) {
          return {
            attempted: true,
            success: false,
            timeoutBlockedFailover: true,
          };
        }
        continue;
      }

      if (statusCode === 429 || statusCode === 503) {
        continue;
      }
    }

    return {
      attempted,
      success: false,
    };
  }

  async function attemptClusterShardExecution({
    slug,
    method,
    params,
    requestId,
    idempotencyKey,
    retryPolicy,
    principalId,
    snapshot,
  }) {
    if (!clusterEnabled || !clusterManager || !federationEnabled || !federationRemoteClient) {
      return {
        attempted: false,
        success: false,
        localOwner: true,
      };
    }

    const excludedNodeIds = new Set();
    let recordedFederationAttempt = false;

    while (true) {
      const selection = clusterManager.resolveOwnerForSlug(slug, {
        snapshot,
        excludeNodeIds: Array.from(excludedNodeIds),
      });
      const ownerNodeId = selection && typeof selection.ownerNodeId === "string" ? selection.ownerNodeId : "";
      const ownerIsLocal = Boolean(selection && selection.ownerIsLocal);

      if (!ownerNodeId) {
        return {
          attempted: recordedFederationAttempt,
          success: false,
          localOwner: false,
          noOwner: true,
          shardId: selection ? selection.shardId : null,
        };
      }

      if (ownerIsLocal) {
        return {
          attempted: recordedFederationAttempt,
          success: false,
          localOwner: true,
          ownerNodeId,
          shardId: selection.shardId,
        };
      }

      const peer = clusterManager.getPeerForNode(ownerNodeId);
      if (!peer) {
        excludedNodeIds.add(ownerNodeId);
        if (!idempotencyKey) {
          return {
            attempted: recordedFederationAttempt,
            success: false,
            localOwner: false,
            ownerNodeId,
            missingPeer: true,
            shardId: selection.shardId,
            timeoutBlockedFailover: true,
          };
        }
        continue;
      }

      if (!recordedFederationAttempt) {
        metrics.increment("supervisor.federation.attempt", { slug });
        recordedFederationAttempt = true;
      }

      const attempt = await executeRemotePeerAttempt({
        peer,
        slug,
        method,
        params,
        requestId,
        idempotencyKey,
        retryPolicy,
        principalId,
        auditPhase: "cluster_shard_forward_success",
      });

      if (attempt && attempt.success) {
        return {
          attempted: true,
          success: true,
          payload: attempt.payload,
          ownerNodeId,
          shardId: selection.shardId,
          localOwner: false,
        };
      }

      if (attempt && attempt.timeoutFailure) {
        clusterManager.markNodeDown(ownerNodeId, Date.now());
        scheduleStatePersist("peer_registry_down");
        excludedNodeIds.add(ownerNodeId);
        if (!idempotencyKey) {
          return {
            attempted: true,
            success: false,
            timeoutBlockedFailover: true,
            ownerNodeId,
            shardId: selection.shardId,
            localOwner: false,
          };
        }
        continue;
      }

      return {
        attempted: true,
        success: false,
        localOwner: false,
        ownerNodeId,
        shardId: selection.shardId,
      };
    }
  }

  function hasQueueDispatchCapacity(slug) {
    const config = getConfig(slug);
    if (!config) {
      return false;
    }

    const pool = getExistingPool(slug);
    if (!pool || pool.instances.size === 0) {
      return true;
    }

    for (const instance of pool.instances.values()) {
      if (instance.state === "READY") {
        return true;
      }
    }

    return pool.instances.size + getPendingSpawns(slug) < config.maxInstances;
  }

  function publishGaugeSnapshot() {
    metrics.gauge("supervisor.instances.total", aggregateCounts.total);
    metrics.gauge("supervisor.instances.ready", aggregateCounts.ready);
    metrics.gauge("supervisor.instances.busy", aggregateCounts.busy);
    metrics.gauge("supervisor.pending_spawns", aggregateCounts.pending);
  }

  async function processQueue() {
    if (!queueEnabled || isShuttingDown || queueProcessorActive) {
      return;
    }
    queueProcessorActive = true;
    try {
      const queued = requestQueue.peek();
      if (!queued) {
        return;
      }

      const now = Date.now();
      if (now < queued.nextExecutionTime) {
        return;
      }

      if (!hasQueueDispatchCapacity(queued.slug)) {
        metrics.increment("supervisor.capacity.rejection.due.to.queue", { slug: queued.slug, method: queued.method });
        return;
      }

      const dequeued = requestQueue.dequeue();
      publishQueueGauge();
      scheduleStatePersist("queue_dequeue");
      if (!dequeued) {
        return;
      }

      metrics.observe("supervisor.queue.execution.delay.histogram", Math.max(0, now - dequeued.enqueuedAt), {
        slug: dequeued.slug,
        method: dequeued.method,
      });

      try {
        await execute(dequeued.slug, dequeued.method, dequeued.params, dequeued.requestContext);
      } catch {}
    } finally {
      queueProcessorActive = false;
    }
  }

  function startQueueProcessor() {
    if (!queueEnabled || queueTimer) {
      return;
    }
    queueTimer = setInterval(() => {
      processQueue().catch(() => {});
    }, queuePollIntervalMs);
    if (queueTimer && typeof queueTimer.unref === "function") {
      queueTimer.unref();
    }
  }

  function stopQueueProcessor() {
    if (!queueTimer) {
      return;
    }
    clearInterval(queueTimer);
    queueTimer = null;
  }

  function setPendingSpawns(slug, count) {
    const current = pendingSpawnsBySlug.get(slug) || 0;
    const safe = Math.max(0, Number.parseInt(String(count), 10) || 0);
    if (safe === 0) {
      pendingSpawnsBySlug.delete(slug);
    } else {
      pendingSpawnsBySlug.set(slug, safe);
    }
    aggregateCounts.pending += safe - current;
    publishGaugeSnapshot();
  }

  function getOrCreateReservationSet(slug) {
    let set = reapReservationsBySlug.get(slug);
    if (!set) {
      set = new Set();
      reapReservationsBySlug.set(slug, set);
    }
    return set;
  }

  function clearReservation(slug, containerId) {
    const set = reapReservationsBySlug.get(slug);
    if (!set) {
      return;
    }
    set.delete(containerId);
    if (set.size === 0) {
      reapReservationsBySlug.delete(slug);
    }
  }

  function applyInstanceStateDelta(state, delta) {
    if (state === "READY") {
      aggregateCounts.ready += delta;
    } else if (state === "BUSY") {
      aggregateCounts.busy += delta;
    }
  }

  function addInstanceLocked(slug, containerId, state, lastUsedAt) {
    const pool = getOrCreatePool(slug);
    pool.instances.set(containerId, {
      state,
      lastUsedAt,
    });
    aggregateCounts.total += 1;
    applyInstanceStateDelta(state, 1);
    publishGaugeSnapshot();
  }

  function setInstanceStateLocked(slug, containerId, nextState) {
    const pool = getExistingPool(slug);
    if (!pool) {
      return false;
    }
    const entry = pool.instances.get(containerId);
    if (!entry) {
      return false;
    }

    if (entry.state !== nextState) {
      applyInstanceStateDelta(entry.state, -1);
      entry.state = nextState;
      applyInstanceStateDelta(entry.state, 1);
      publishGaugeSnapshot();
    }
    return true;
  }

  function removeInstanceLocked(slug, containerId) {
    const pool = getExistingPool(slug);
    if (pool) {
      const existing = pool.instances.get(containerId);
      if (existing) {
        aggregateCounts.total -= 1;
        applyInstanceStateDelta(existing.state, -1);
      }
      pool.instances.delete(containerId);
      if (pool.instances.size === 0) {
        pools.delete(slug);
      }
    }
    instanceMetaById.delete(containerId);
    instanceTokenById.delete(containerId);
    clearReservation(slug, containerId);
    publishGaugeSnapshot();
  }

  function pickReadyInstanceLocked(slug) {
    const pool = getExistingPool(slug);
    if (!pool) {
      return null;
    }

    const reservations = reapReservationsBySlug.get(slug);
    const candidates = Array.from(pool.instances.entries())
      .filter(([containerId, instance]) => instance.state === "READY" && !(reservations && reservations.has(containerId)))
      .sort((a, b) => {
        if (a[1].lastUsedAt !== b[1].lastUsedAt) {
          return a[1].lastUsedAt - b[1].lastUsedAt;
        }
        return a[0].localeCompare(b[0]);
      });

    if (candidates.length === 0) {
      return null;
    }

    return {
      containerId: candidates[0][0],
      instance: candidates[0][1],
    };
  }

  function ensureSkillAndMethod(slug, method) {
    if (!getConfig(slug)) {
      throw makeFailure("INVALID_SLUG", `Unsupported skill slug '${slug || ""}'`);
    }

    if (!METHOD_SET.has(method)) {
      throw makeFailure("INVALID_METHOD", `Unsupported method '${method || ""}'`);
    }
  }

  async function ensureInitialized() {
    if (initialized) {
      return;
    }

    const result = await spawner.initialize();
    if (isSpawnerError(result)) {
      throw makeFailure("SPAWN_FAILED", "Spawner initialization failed", {
        code: result.error.code,
        message: result.error.message,
      });
    }

    initialized = true;
  }

  function buildRuntimeStyleErrorFromJsonRpc(jsonRpcError) {
    const code = Object.prototype.hasOwnProperty.call(jsonRpcError || {}, "code") ? String(jsonRpcError.code) : "RPC_ERROR";
    const message = jsonRpcError && typeof jsonRpcError.message === "string" ? jsonRpcError.message : "RPC error";
    const payload = {
      ok: false,
      error: {
        code,
        message,
      },
    };

    if (jsonRpcError && Object.prototype.hasOwnProperty.call(jsonRpcError, "data")) {
      payload.error.details = jsonRpcError.data;
    }

    return payload;
  }

  function isValidJsonRpcEnvelope(value) {
    return Boolean(
      value &&
        typeof value === "object" &&
        value.jsonrpc === "2.0" &&
        Object.prototype.hasOwnProperty.call(value, "id") &&
        (Object.prototype.hasOwnProperty.call(value, "result") || Object.prototype.hasOwnProperty.call(value, "error")),
    );
  }

  async function callInstanceJsonRpc(meta, token, method, params, requestId) {
    const url = new URL(meta.networkAddress);
    const payload = JSON.stringify({
      jsonrpc: "2.0",
      method,
      params,
      id: requestId,
    });

    return new Promise((resolve) => {
      let done = false;
      const finish = (value) => {
        if (done) {
          return;
        }
        done = true;
        resolve(value);
      };

      const req = http.request(
        {
          protocol: url.protocol,
          hostname: url.hostname,
          port: url.port,
          path: `${url.pathname}${url.search}`,
          method: "POST",
          timeout: requestTimeoutMs,
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
            "Content-Length": Buffer.byteLength(payload, "utf8"),
          },
        },
        (res) => {
          let body = "";
          res.setEncoding("utf8");
          res.on("data", (chunk) => {
            body += chunk;
          });
          res.on("end", () => {
            if (res.statusCode !== 200) {
              finish({
                kind: "transport_failure",
                reason: "http_status",
                statusCode: res.statusCode,
              });
              return;
            }

            let parsed;
            try {
              parsed = JSON.parse(body);
            } catch {
              finish({
                kind: "transport_failure",
                reason: "invalid_json",
              });
              return;
            }

            if (!isValidJsonRpcEnvelope(parsed)) {
              finish({
                kind: "transport_failure",
                reason: "invalid_jsonrpc",
              });
              return;
            }

            if (Object.prototype.hasOwnProperty.call(parsed, "error")) {
              finish({
                kind: "jsonrpc_error",
                error: parsed.error,
              });
              return;
            }

            finish({
              kind: "result",
              result: parsed.result,
            });
          });
        },
      );

      req.on("timeout", () => {
        req.destroy();
        finish({
          kind: "transport_failure",
          reason: "timeout",
        });
      });

      req.on("error", () => {
        finish({
          kind: "transport_failure",
          reason: "connection_error",
        });
      });

      req.end(payload);
    });
  }

  async function handleInstanceTransportFailure(slug, containerId, reasonPayload, requestId, principalId) {
    const failureReason = reasonPayload && reasonPayload.reason ? reasonPayload.reason : "transport_failure";
    metrics.increment("supervisor.instance.failed", { slug, reason: failureReason, request_id: requestId });
    metrics.increment("supervisor.executions.error", { slug, reason: failureReason, request_id: requestId });

    await withSlugLock(slug, async () => {
      removeInstanceLocked(slug, containerId);
    });

    const terminateResult = await spawner.terminateSkill(containerId, {
      requestId,
      principalId,
    });
    const details = {
      containerId,
      reason: reasonPayload && reasonPayload.reason ? reasonPayload.reason : "transport_failure",
      request_id: requestId,
    };

    if (reasonPayload && Object.prototype.hasOwnProperty.call(reasonPayload, "statusCode")) {
      details.statusCode = reasonPayload.statusCode;
    }

    if (isSpawnerError(terminateResult)) {
      safeAudit({
        event: "terminate",
        principal_id: principalId,
        slug,
        request_id: requestId,
        status: "failure",
        details: {
          code: terminateResult.error.code,
          message: terminateResult.error.message,
        },
      });
      details.terminateError = {
        code: terminateResult.error.code,
        message: terminateResult.error.message,
      };
    } else {
      safeAudit({
        event: "terminate",
        principal_id: principalId,
        slug,
        request_id: requestId,
        status: "success",
        details: {
          source: "failure_cleanup",
        },
      });
      metrics.increment("supervisor.instance.terminated", { slug, source: "failure_cleanup" });
    }

    throw attachRequestId(makeFailure("INSTANCE_FAILED", "Instance execution failed", details), requestId);
  }

  async function initialize() {
    await ensureInitialized();
    if (stateManager && !statePersistenceInitialized) {
      const loadResult = await stateManager.initialize();
      statePersistenceInitialized = true;
      if (loadResult && loadResult.loaded) {
        scheduleStatePersist("startup_recovery");
      }
    }

    if (clusterEnabled && clusterManager) {
      await clusterManager.start();
    } else if (federationEnabled && federationHeartbeat && typeof federationHeartbeat.runOnce === "function") {
      try {
        await federationHeartbeat.runOnce();
      } catch {}
    }

    initializeCircuitMetrics();
    startQueueProcessor();
    if (!clusterEnabled && federationEnabled && federationHeartbeat && typeof federationHeartbeat.start === "function") {
      federationHeartbeat.start();
    }
    publishQueueGauge();
    return {
      ok: true,
      initialized: true,
    };
  }

  async function execute(rawSlug, rawMethod, rawParams, requestContext = {}) {
    const context = requestContext && typeof requestContext === "object" ? requestContext : {};
    const requestId = resolveRequestId(context);
    const principalId = resolvePrincipalId(context);
    const idempotencyKey = normalizeIdempotencyKey(context);
    const retryPolicy = normalizeRetryPolicy(context);
    const slug = normalizeSlug(rawSlug);
    const method = normalizeMethod(rawMethod);
    const params = typeof rawParams === "undefined" ? {} : rawParams;
    const queueRetryExecution = isQueueRetryExecution(context);
    let idempotencyStoreKey = "";
    let idempotencyParamsHash = "";
    let circuitLeaseAcquired = false;
    let executionStartedAt = 0;
    let shouldObserveExecution = false;
    let clusterRoutingSnapshot = null;

    try {
      authGuard.validate(context, requestId);
      rateLimiter.check(principalId, requestId);
      safeAudit({
        event: "execute",
        principal_id: principalId,
        slug,
        request_id: requestId,
        status: "success",
        details: {
          phase: "entry",
          method,
        },
      });

      if (isShuttingDown) {
        throw makeFailure("SUPERVISOR_SHUTTING_DOWN", "Supervisor is shutting down");
      }

      await ensureInitialized();
      startQueueProcessor();

      if (isShuttingDown) {
        throw makeFailure("SUPERVISOR_SHUTTING_DOWN", "Supervisor is shutting down");
      }

      const skillConfig = getConfig(slug);
      const toolAdapter = toolRegistry.get(slug);
      if (!skillConfig && !toolAdapter) {
        throw makeFailure("INVALID_TOOL_REQUEST", `Tool '${slug || ""}' is not registered`);
      }

      if (idempotencyEnabled && idempotencyKey) {
        idempotencyParamsHash = stableStringify(params);
        idempotencyStoreKey = makeIdempotencyStoreKey(principalId, slug, method, idempotencyParamsHash, idempotencyKey);
        const replay = readIdempotencyReplay(idempotencyStoreKey, idempotencyParamsHash, Date.now());
        if (replay) {
          if (replay.kind === "runtime_error") {
            metrics.increment("supervisor.executions.error", { slug, reason: "idempotency_replay", request_id: requestId });
          } else {
            metrics.increment("supervisor.executions.success", { slug, method });
          }
          return replay.payload;
        }
      }

      if (toolAdapter) {
        executionStartedAt = Date.now();
        shouldObserveExecution = true;
        metrics.increment("supervisor.executions.total", { slug, method });

        if (method !== "run") {
          metrics.increment("supervisor.executions.error", { slug, reason: "invalid_tool_method", request_id: requestId });
          throw makeFailure("INVALID_TOOL_REQUEST", "Tool adapters only support method 'run'", {
            slug,
            method,
          });
        }

        const validation = await toolValidator.validateExecutionRequest(slug, params);
        if (!validation.valid || !validation.adapter) {
          metrics.increment("supervisor.executions.error", { slug, reason: "invalid_tool_request", request_id: requestId });
          throw makeFailure("INVALID_TOOL_REQUEST", "Tool request validation failed", {
            slug,
            errors: validation.errors || [],
          });
        }

        metrics.increment("tool.executions.total", { slug });
        const toolStartedAt = Date.now();
        const toolResult = await validation.adapter.execute({
          params,
          timeout: requestTimeoutMs,
          requestId,
        });
        const toolDuration = Math.max(
          0,
          toolResult &&
            toolResult.metadata &&
            Number.isFinite(Number(toolResult.metadata.executionTimeMs))
            ? Number(toolResult.metadata.executionTimeMs)
            : Date.now() - toolStartedAt,
        );
        const outputBytes = Math.max(
          0,
          toolResult &&
            toolResult.metadata &&
            Number.isFinite(Number(toolResult.metadata.outputBytes))
            ? Number(toolResult.metadata.outputBytes)
            : (() => {
                try {
                  return Buffer.byteLength(JSON.stringify(toolResult && toolResult.result ? toolResult.result : {}), "utf8");
                } catch {
                  return 0;
                }
              })(),
        );
        metrics.observe("tool.execution.duration_ms", toolDuration, { slug });
        metrics.observe("tool.output_size_bytes", outputBytes, { slug });

        if (toolResult && toolResult.ok === true) {
          metrics.increment("tool.executions.success", { slug });
          metrics.increment("supervisor.executions.success", { slug, method });
          storeIdempotencyOutcome(idempotencyStoreKey, idempotencyParamsHash, "result", toolResult);
          safeAudit({
            event: "execute",
            principal_id: principalId,
            slug,
            request_id: requestId,
            status: "success",
            details: {
              phase: "tool_result",
              method,
            },
          });
          return toolResult;
        }

        const toolErrorResult =
          toolResult && toolResult.ok === false
            ? toolResult
            : {
                ok: false,
                error: {
                  code: "TOOL_EXECUTION_ERROR",
                  message: "Tool execution failed",
                },
                metadata: {
                  executionTimeMs: toolDuration,
                  outputBytes,
                  requestId,
                },
              };
        metrics.increment("tool.executions.error", { slug });
        metrics.increment("supervisor.executions.error", { slug, reason: "tool_execution_error", request_id: requestId });
        storeIdempotencyOutcome(idempotencyStoreKey, idempotencyParamsHash, "runtime_error", toolErrorResult);
        safeAudit({
          event: "execute",
          principal_id: principalId,
          slug,
          request_id: requestId,
          status: "failure",
          details: {
            phase: "tool_execution_error",
            method,
            code: toolErrorResult.error && toolErrorResult.error.code ? toolErrorResult.error.code : "TOOL_EXECUTION_ERROR",
          },
        });
        return toolErrorResult;
      }

      ensureSkillAndMethod(slug, method);

      if (clusterEnabled && clusterManager) {
        clusterRoutingSnapshot = clusterManager.getSnapshot();
        const clusterResult = await attemptClusterShardExecution({
          slug,
          method,
          params,
          requestId,
          idempotencyKey,
          retryPolicy,
          principalId,
          snapshot: clusterRoutingSnapshot,
        });

        if (clusterResult && clusterResult.success) {
          const clusterPayload = clusterResult.payload;
          const clusterRuntimeError =
            Boolean(clusterPayload && typeof clusterPayload === "object") &&
            clusterPayload.ok === false &&
            Boolean(clusterPayload.error && typeof clusterPayload.error === "object");
          storeIdempotencyOutcome(
            idempotencyStoreKey,
            idempotencyParamsHash,
            clusterRuntimeError ? "runtime_error" : "result",
            clusterPayload,
          );
          return clusterPayload;
        }

        if (clusterResult && clusterResult.localOwner !== true) {
          throw makeFailure("SUPERVISOR_CAPACITY_EXCEEDED", `Skill '${slug}' is at capacity`, {
            slug,
            maxInstances: getConfig(slug).maxInstances,
            shardId: Object.prototype.hasOwnProperty.call(clusterResult, "shardId") ? clusterResult.shardId : null,
            ownerNodeId: clusterResult.ownerNodeId || null,
          });
        }
      }

      if (circuitBreaker.enabled) {
        const gate = circuitBreaker.checkBeforeRequest(slug);
        applyCircuitTransitionMetrics(slug, gate, { requestId, principalId });
        if (!gate.allowed) {
          const snapshot = gate.snapshot || circuitBreaker.getSnapshot(slug);
          const nextRetryAt =
            snapshot.state === "OPEN" ? snapshot.lastTransitionAt + circuitBreaker.constants.timeoutMs : Date.now();
          const reason = snapshot.state === "OPEN" ? "circuit_open" : "circuit_half_open_busy";
          metrics.increment("supervisor.executions.error", { slug, reason, request_id: requestId });
          throw makeFailure(
            "CIRCUIT_BREAKER_OPEN",
            snapshot.state === "OPEN" ? "Skill circuit breaker is open" : "Skill circuit breaker is half-open",
            {
              slug,
              state: snapshot.state,
              failureCount: snapshot.failureCount,
              nextRetryAt,
            },
          );
        }
        circuitLeaseAcquired = gate.leaseAcquired;
      }

      if (!clusterEnabled && federationEnabled && !queueRetryExecution && !circuitLeaseAcquired && isLocalCapacityExhausted(slug)) {
        const federationResult = await attemptFederatedExecution({
          slug,
          method,
          params,
          requestId,
          idempotencyKey,
          retryPolicy,
          principalId,
        });

        if (federationResult && federationResult.success) {
          const federatedPayload = federationResult.payload;
          const federatedRuntimeError =
            Boolean(federatedPayload && typeof federatedPayload === "object") &&
            federatedPayload.ok === false &&
            Boolean(federatedPayload.error && typeof federatedPayload.error === "object");
          storeIdempotencyOutcome(
            idempotencyStoreKey,
            idempotencyParamsHash,
            federatedRuntimeError ? "runtime_error" : "result",
            federatedPayload,
          );
          return federatedPayload;
        }

        if (federationResult && federationResult.attempted) {
          throw makeFailure("SUPERVISOR_CAPACITY_EXCEEDED", `Skill '${slug}' is at capacity`, {
            slug,
            maxInstances: getConfig(slug).maxInstances,
          });
        }
      }

      executionStartedAt = Date.now();
      shouldObserveExecution = true;
      metrics.increment("supervisor.executions.total", { slug, method });

      let acquiredContainerId = null;
      let shouldSpawn = false;

      try {
        await withSlugLock(slug, async () => {
          if (isShuttingDown) {
            throw makeFailure("SUPERVISOR_SHUTTING_DOWN", "Supervisor is shutting down");
          }

          const ready = pickReadyInstanceLocked(slug);
          if (ready) {
            setInstanceStateLocked(slug, ready.containerId, "BUSY");
            acquiredContainerId = ready.containerId;
            return;
          }

          const pool = getOrCreatePool(slug);
          const config = getConfig(slug);
          const pending = getPendingSpawns(slug);
          if (pool.instances.size + pending >= config.maxInstances) {
            throw makeFailure("SUPERVISOR_CAPACITY_EXCEEDED", `Skill '${slug}' is at capacity`, {
              slug,
              maxInstances: config.maxInstances,
            });
          }

          metrics.increment("supervisor.spawn.attempt", { slug });
          setPendingSpawns(slug, pending + 1);
          shouldSpawn = true;
        });
      } catch (error) {
        if (error && error.code === "SUPERVISOR_CAPACITY_EXCEEDED") {
          metrics.increment("supervisor.executions.capacity_rejected", { slug, request_id: requestId });
          metrics.increment("supervisor.executions.error", { slug, reason: "capacity_rejected", request_id: requestId });
        }
        throw error;
      }

      if (shouldSpawn) {
        const spawnStartedAt = Date.now();
        safeAudit({
          event: "spawn",
          principal_id: principalId,
          slug,
          request_id: requestId,
          status: "success",
          details: {
            phase: "attempt",
          },
        });
        const spawnResult = await spawner.spawnSkill(slug, {
          requestId,
          principalId,
        });
        metrics.observe("supervisor.spawn.duration_ms", Date.now() - spawnStartedAt, { slug });

        if (isSpawnerError(spawnResult)) {
          safeAudit({
            event: "spawn",
            principal_id: principalId,
            slug,
            request_id: requestId,
            status: "failure",
            details: {
              code: spawnResult.error.code,
              message: spawnResult.error.message,
            },
          });
          metrics.increment("supervisor.spawn.failure", { slug, request_id: requestId });
          metrics.increment("supervisor.executions.error", { slug, reason: "spawn_failed", request_id: requestId });
          await withSlugLock(slug, async () => {
            setPendingSpawns(slug, getPendingSpawns(slug) - 1);
          });
          throw makeFailure("SPAWN_FAILED", `Failed to spawn instance for '${slug}'`, {
            slug,
            code: spawnResult.error.code,
            message: spawnResult.error.message,
          });
        }

        if (!spawnResult || typeof spawnResult.containerId !== "string" || typeof spawnResult.networkAddress !== "string" || typeof spawnResult.token !== "string") {
          safeAudit({
            event: "spawn",
            principal_id: principalId,
            slug,
            request_id: requestId,
            status: "failure",
            details: {
              code: "INVALID_SPAWN_PAYLOAD",
            },
          });
          metrics.increment("supervisor.spawn.failure", { slug, request_id: requestId });
          metrics.increment("supervisor.executions.error", { slug, reason: "invalid_spawn_payload", request_id: requestId });
          await withSlugLock(slug, async () => {
            setPendingSpawns(slug, getPendingSpawns(slug) - 1);
          });
          throw makeFailure("SPAWN_FAILED", `Spawner returned invalid instance payload for '${slug}'`, { slug });
        }

        metrics.increment("supervisor.spawn.success", { slug });
        safeAudit({
          event: "spawn",
          principal_id: principalId,
          slug,
          request_id: requestId,
          status: "success",
          details: {
            phase: "success",
          },
        });
        let shutdownAfterSpawn = false;

        await withSlugLock(slug, async () => {
          setPendingSpawns(slug, getPendingSpawns(slug) - 1);

          if (isShuttingDown) {
            shutdownAfterSpawn = true;
            return;
          }

          addInstanceLocked(slug, spawnResult.containerId, "BUSY", Date.now());

          instanceMetaById.set(spawnResult.containerId, {
            slug,
            name: spawnResult.name,
            networkAddress: spawnResult.networkAddress,
          });
          instanceTokenById.set(spawnResult.containerId, spawnResult.token);

          acquiredContainerId = spawnResult.containerId;
        });

        if (shutdownAfterSpawn) {
          const terminateResult = await spawner.terminateSkill(spawnResult.containerId, {
            requestId,
            principalId,
          });
          if (!isSpawnerError(terminateResult)) {
            safeAudit({
              event: "terminate",
              principal_id: principalId,
              slug,
              request_id: requestId,
              status: "success",
              details: {
                source: "shutdown_after_spawn",
              },
            });
            metrics.increment("supervisor.instance.terminated", { slug, source: "shutdown_after_spawn" });
          } else {
            safeAudit({
              event: "terminate",
              principal_id: principalId,
              slug,
              request_id: requestId,
              status: "failure",
              details: {
                source: "shutdown_after_spawn",
                code: terminateResult.error.code,
                message: terminateResult.error.message,
              },
            });
          }
          metrics.increment("supervisor.executions.error", { slug, reason: "shutting_down", request_id: requestId });
          throw makeFailure("SUPERVISOR_SHUTTING_DOWN", "Supervisor is shutting down");
        }
      }

      if (!acquiredContainerId) {
        metrics.increment("supervisor.executions.error", { slug, reason: "instance_unavailable", request_id: requestId });
        throw makeFailure("INSTANCE_FAILED", "Unable to acquire an instance");
      }

      const meta = instanceMetaById.get(acquiredContainerId);
      const token = instanceTokenById.get(acquiredContainerId);

      if (!meta || !token) {
        if (circuitBreaker.enabled) {
          const transition = circuitBreaker.recordFailure(slug);
          scheduleStatePersist("circuit_failure");
          applyCircuitTransitionMetrics(slug, transition, { requestId, principalId });
        }
        await handleInstanceTransportFailure(slug, acquiredContainerId, {
          reason: "missing_instance_metadata",
        }, requestId, principalId);
      }

      const rpcResult = await callInstanceJsonRpc(meta, token, method, params, requestId);

      if (rpcResult.kind === "result") {
        await withSlugLock(slug, async () => {
          const pool = getExistingPool(slug);
          if (!pool) {
            return;
          }
          const entry = pool.instances.get(acquiredContainerId);
          if (!entry) {
            return;
          }
          setInstanceStateLocked(slug, acquiredContainerId, "READY");
          entry.lastUsedAt = Date.now();
        });
        if (circuitBreaker.enabled) {
          const transition = circuitBreaker.recordSuccess(slug);
          scheduleStatePersist("circuit_success");
          applyCircuitTransitionMetrics(slug, transition, { requestId, principalId });
        }
        storeIdempotencyOutcome(idempotencyStoreKey, idempotencyParamsHash, "result", rpcResult.result);
        metrics.increment("supervisor.executions.success", { slug, method });
        safeAudit({
          event: "execute",
          principal_id: principalId,
          slug,
          request_id: requestId,
          status: "success",
          details: {
            phase: "result",
            method,
          },
        });
        return rpcResult.result;
      }

      if (rpcResult.kind === "jsonrpc_error") {
        await withSlugLock(slug, async () => {
          const pool = getExistingPool(slug);
          if (!pool) {
            return;
          }
          const entry = pool.instances.get(acquiredContainerId);
          if (!entry) {
            return;
          }
          setInstanceStateLocked(slug, acquiredContainerId, "READY");
          entry.lastUsedAt = Date.now();
        });
        if (circuitBreaker.enabled) {
          const transition = circuitBreaker.recordSuccess(slug);
          scheduleStatePersist("circuit_success");
          applyCircuitTransitionMetrics(slug, transition, { requestId, principalId });
        }
        const runtimeStyleError = buildRuntimeStyleErrorFromJsonRpc(rpcResult.error);
        storeIdempotencyOutcome(idempotencyStoreKey, idempotencyParamsHash, "runtime_error", runtimeStyleError);
        metrics.increment("supervisor.executions.error", { slug, reason: "jsonrpc_error", request_id: requestId });
        safeAudit({
          event: "execute",
          principal_id: principalId,
          slug,
          request_id: requestId,
          status: "failure",
          details: {
            phase: "runtime_error",
            method,
            code: runtimeStyleError.error.code,
          },
        });
        return runtimeStyleError;
      }

      if (circuitBreaker.enabled) {
        const transition = circuitBreaker.recordFailure(slug);
        scheduleStatePersist("circuit_failure");
        applyCircuitTransitionMetrics(slug, transition, { requestId, principalId });
      }
      await handleInstanceTransportFailure(slug, acquiredContainerId, rpcResult, requestId, principalId);
    } catch (error) {
      const normalizedError = attachRequestId(error, requestId);
      const normalizedCode = normalizedError && typeof normalizedError.code === "string" ? normalizedError.code : "INTERNAL_ERROR";
      if (normalizedCode === "UNAUTHORIZED") {
        safeAudit({
          event: "auth_failure",
          principal_id: principalId,
          slug,
          request_id: requestId,
          status: "failure",
          details: {
            method,
          },
        });
      }
      safeAudit({
        event: "execute",
        principal_id: principalId,
        slug,
        request_id: requestId,
        status: "failure",
        details: {
          phase: "exception",
          method,
          code: normalizedCode,
        },
      });
      if (circuitBreaker.enabled && normalizedError && normalizedError.code !== "INSTANCE_FAILED" && circuitLeaseAcquired) {
        circuitBreaker.releaseHalfOpenLease(slug);
      }
      if (
        normalizedError &&
        normalizedError.code === "INSTANCE_FAILED" &&
        retryPolicy &&
        retryPolicy.retries > 0 &&
        isRetryEligibleMethod(method)
      ) {
        if (circuitBreaker.enabled) {
          const snapshot = circuitBreaker.getSnapshot(slug);
          if (snapshot.state === "OPEN") {
            metrics.increment("supervisor.executions.error", { slug, reason: "circuit_open", request_id: requestId });
            throw attachRequestId(makeFailure("CIRCUIT_BREAKER_OPEN", "Skill circuit breaker is open", buildCircuitOpenDetails(slug)), requestId);
          }
        }
        const enqueueResult = enqueueRetryRequest({
          slug,
          method,
          params,
          requestContext: context,
          principalId,
          retryPolicy,
          requestId,
        });
        if (enqueueResult.queued) {
          if (!normalizedError.details || typeof normalizedError.details !== "object") {
            normalizedError.details = {};
          }
          normalizedError.details.retry_enqueued = true;
          normalizedError.details.remaining_retries = enqueueResult.remainingRetries;
          normalizedError.details.queue_length = requestQueue.length;
          throw normalizedError;
        }
        if (enqueueResult.reason === "queue_full") {
          safeAudit({
            event: "queue_overflow",
            principal_id: principalId,
            slug,
            request_id: requestId,
            status: "failure",
            details: {
              method,
              maxLength: queueMaxLength,
            },
          });
          metrics.increment("supervisor.executions.error", { slug, reason: "queue_capacity_rejected", request_id: requestId });
          throw attachRequestId(
            makeFailure("SUPERVISOR_CAPACITY_EXCEEDED", "Retry queue is at capacity", {
              slug,
              maxLength: queueMaxLength,
            }),
            requestId,
          );
        }
      }
      throw normalizedError;
    } finally {
      if (shouldObserveExecution) {
        metrics.observe("supervisor.execution.duration_ms", Date.now() - executionStartedAt, { slug, method });
      }
    }
  }

  async function reapIdle() {
    await ensureInitialized();

    let reaped = 0;
    let failed = 0;

    const slugs = Object.keys(SKILL_CONFIG).sort();

    for (const slug of slugs) {
      const candidates = [];
      await withSlugLock(slug, async () => {
        const pool = getExistingPool(slug);
        if (!pool) {
          return;
        }

        const ttlMs = getConfig(slug).idleTTLms;
        const now = Date.now();
        const reservations = getOrCreateReservationSet(slug);

        const entries = Array.from(pool.instances.entries()).sort((a, b) => a[0].localeCompare(b[0]));
        for (const [containerId, instance] of entries) {
          if (instance.state !== "READY") {
            continue;
          }
          if (reservations.has(containerId)) {
            continue;
          }
          if (now - instance.lastUsedAt <= ttlMs) {
            continue;
          }

          reservations.add(containerId);
          candidates.push(containerId);
        }

        if (reservations.size === 0) {
          reapReservationsBySlug.delete(slug);
        }
      });

      for (const containerId of candidates) {
        const terminateResult = await spawner.terminateSkill(containerId);
        const terminateOk = !isSpawnerError(terminateResult);

        await withSlugLock(slug, async () => {
          clearReservation(slug, containerId);
          if (!terminateOk) {
            return;
          }
          removeInstanceLocked(slug, containerId);
        });

        if (terminateOk) {
          safeAudit({
            event: "terminate",
            principal_id: "system",
            slug,
            request_id: "",
            status: "success",
            details: {
              source: "reap",
            },
          });
          reaped += 1;
          metrics.increment("supervisor.instance.reaped", { slug });
          metrics.increment("supervisor.instance.terminated", { slug, source: "reap" });
        } else {
          safeAudit({
            event: "terminate",
            principal_id: "system",
            slug,
            request_id: "",
            status: "failure",
            details: {
              source: "reap",
              code: terminateResult.error.code,
              message: terminateResult.error.message,
            },
          });
          failed += 1;
        }
      }
    }

    return {
      ok: true,
      reaped,
      failed,
    };
  }

  async function getStatus() {
    const slugs = Object.keys(SKILL_CONFIG).sort();
    const skills = slugs.map((slug) => {
      const config = getConfig(slug);
      const pool = getExistingPool(slug);
      const instances = pool
        ? Array.from(pool.instances.entries())
            .sort((a, b) => a[0].localeCompare(b[0]))
            .map(([containerId, instance]) => ({
              containerId,
              state: instance.state,
              lastUsedAt: instance.lastUsedAt,
            }))
        : [];

      const counts = {
        ready: instances.filter((x) => x.state === "READY").length,
        busy: instances.filter((x) => x.state === "BUSY").length,
        total: instances.length,
      };

      return {
        slug,
        maxInstances: config.maxInstances,
        idleTTLms: config.idleTTLms,
        counts,
        instances,
      };
    });

    return {
      ok: true,
      isShuttingDown,
      skills,
    };
  }

  function getMetrics() {
    return metrics.snapshot();
  }

  async function shutdown() {
    isShuttingDown = true;
    suspendStatePersistence = true;
    stopQueueProcessor();
    if (clusterEnabled && clusterManager && typeof clusterManager.stop === "function") {
      clusterManager.stop();
    }
    if (federationEnabled && federationHeartbeat && typeof federationHeartbeat.stop === "function") {
      federationHeartbeat.stop();
    }
    safeAudit({
      event: "shutdown",
      principal_id: "system",
      slug: "",
      request_id: "",
      status: "success",
      details: {
        phase: "start",
      },
    });

    const terminateTargets = [];
    const allSlugs = Array.from(new Set([...Object.keys(SKILL_CONFIG), ...pools.keys()])).sort();

    for (const slug of allSlugs) {
      await withSlugLock(slug, async () => {
        const pool = getExistingPool(slug);
        if (!pool) {
          setPendingSpawns(slug, 0);
          reapReservationsBySlug.delete(slug);
          return;
        }

        for (const containerId of Array.from(pool.instances.keys())) {
          terminateTargets.push({ slug, containerId });
          removeInstanceLocked(slug, containerId);
        }

        setPendingSpawns(slug, 0);
        reapReservationsBySlug.delete(slug);
      });
    }

    let terminated = 0;
    let failed = 0;
    const errors = [];

    for (const target of terminateTargets) {
      const terminateResult = await spawner.terminateSkill(target.containerId);
      if (isSpawnerError(terminateResult)) {
        safeAudit({
          event: "terminate",
          principal_id: "system",
          slug: target.slug,
          request_id: "",
          status: "failure",
          details: {
            source: "shutdown",
            code: terminateResult.error.code,
            message: terminateResult.error.message,
          },
        });
        failed += 1;
        errors.push({
          containerId: target.containerId,
          code: terminateResult.error.code,
          message: terminateResult.error.message,
        });
      } else {
        safeAudit({
          event: "terminate",
          principal_id: "system",
          slug: target.slug,
          request_id: "",
          status: "success",
          details: {
            source: "shutdown",
          },
        });
        terminated += 1;
        metrics.increment("supervisor.instance.terminated", { slug: target.slug, source: "shutdown" });
      }
    }

    pools.clear();
    instanceMetaById.clear();
    instanceTokenById.clear();
    pendingSpawnsBySlug.clear();
    reapReservationsBySlug.clear();
    slugLocks.clear();
    requestQueue.clear();
    aggregateCounts.total = 0;
    aggregateCounts.ready = 0;
    aggregateCounts.busy = 0;
    aggregateCounts.pending = 0;
    publishGaugeSnapshot();
    publishQueueGauge();
    safeAudit({
      event: "shutdown",
      principal_id: "system",
      slug: "",
      request_id: "",
      status: failed > 0 ? "failure" : "success",
      details: {
        phase: "complete",
        terminated,
        failed,
      },
    });

    if (stateManager) {
      await stateManager.shutdown();
    }

    return {
      ok: true,
      terminated,
      failed,
      errors,
    };
  }

  publishGaugeSnapshot();
  initializeCircuitMetrics();
  publishQueueGauge();

  return {
    initialize,
    execute,
    getStatus,
    getMetrics,
    reapIdle,
    shutdown,
  };
}

module.exports = {
  createSupervisorV1,
  SKILL_CONFIG,
  ALLOWED_METHODS,
};
