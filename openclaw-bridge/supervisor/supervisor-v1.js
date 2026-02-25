const crypto = require("node:crypto");
const http = require("node:http");

const { createMetrics } = require("../observability/metrics.js");
const { createSpawnerV2 } = require("../spawner/spawner-v2.js");

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
  const requestTimeoutMs = parsePositiveInt(options.requestTimeoutMs, DEFAULT_REQUEST_TIMEOUT_MS);
  const baseMetrics = options.metrics && typeof options.metrics === "object" ? options.metrics : createMetrics();
  const metrics = createSafeMetrics(baseMetrics);

  const spawner = spawnerFactory({ metrics });
  const pools = new Map();
  const instanceMetaById = new Map();
  const instanceTokenById = new Map();
  const pendingSpawnsBySlug = new Map();
  const reapReservationsBySlug = new Map();
  const slugLocks = new Map();
  const aggregateCounts = {
    total: 0,
    ready: 0,
    busy: 0,
    pending: 0,
  };

  let initialized = false;
  let isShuttingDown = false;

  function parsePositiveInt(value, fallback) {
    const parsed = Number.parseInt(String(value ?? "").trim(), 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      return fallback;
    }
    return parsed;
  }

  function makeFailure(code, message, details) {
    const error = new Error(String(message || "Unexpected error"));
    error.code = String(code || "SUPERVISOR_ERROR");
    if (typeof details !== "undefined") {
      error.details = details;
    }
    return error;
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

  function getConfig(slug) {
    return SKILL_CONFIG[slug] || null;
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

  function publishGaugeSnapshot() {
    metrics.gauge("supervisor.instances.total", aggregateCounts.total);
    metrics.gauge("supervisor.instances.ready", aggregateCounts.ready);
    metrics.gauge("supervisor.instances.busy", aggregateCounts.busy);
    metrics.gauge("supervisor.pending_spawns", aggregateCounts.pending);
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

  async function callInstanceJsonRpc(meta, token, method, params) {
    const url = new URL(meta.networkAddress);
    const payload = JSON.stringify({
      jsonrpc: "2.0",
      method,
      params,
      id: `supervisor-${crypto.randomBytes(6).toString("hex")}`,
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

  async function handleInstanceTransportFailure(slug, containerId, reasonPayload) {
    const failureReason = reasonPayload && reasonPayload.reason ? reasonPayload.reason : "transport_failure";
    metrics.increment("supervisor.instance.failed", { slug, reason: failureReason });
    metrics.increment("supervisor.executions.error", { slug, reason: failureReason });

    await withSlugLock(slug, async () => {
      removeInstanceLocked(slug, containerId);
    });

    const terminateResult = await spawner.terminateSkill(containerId);
    const details = {
      containerId,
      reason: reasonPayload && reasonPayload.reason ? reasonPayload.reason : "transport_failure",
    };

    if (reasonPayload && Object.prototype.hasOwnProperty.call(reasonPayload, "statusCode")) {
      details.statusCode = reasonPayload.statusCode;
    }

    if (isSpawnerError(terminateResult)) {
      details.terminateError = {
        code: terminateResult.error.code,
        message: terminateResult.error.message,
      };
    } else {
      metrics.increment("supervisor.instance.terminated", { slug, source: "failure_cleanup" });
    }

    throw makeFailure("INSTANCE_FAILED", "Instance execution failed", details);
  }

  async function initialize() {
    await ensureInitialized();
    return {
      ok: true,
      initialized: true,
    };
  }

  async function execute(rawSlug, rawMethod, rawParams) {
    if (isShuttingDown) {
      throw makeFailure("SUPERVISOR_SHUTTING_DOWN", "Supervisor is shutting down");
    }

    await ensureInitialized();

    if (isShuttingDown) {
      throw makeFailure("SUPERVISOR_SHUTTING_DOWN", "Supervisor is shutting down");
    }

    const slug = normalizeSlug(rawSlug);
    const method = normalizeMethod(rawMethod);
    const params = typeof rawParams === "undefined" ? {} : rawParams;

    ensureSkillAndMethod(slug, method);
    const executionStartedAt = Date.now();
    metrics.increment("supervisor.executions.total", { slug, method });

    try {
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
          metrics.increment("supervisor.executions.capacity_rejected", { slug });
          metrics.increment("supervisor.executions.error", { slug, reason: "capacity_rejected" });
        }
        throw error;
      }

      if (shouldSpawn) {
        const spawnStartedAt = Date.now();
        const spawnResult = await spawner.spawnSkill(slug);
        metrics.observe("supervisor.spawn.duration_ms", Date.now() - spawnStartedAt, { slug });

        if (isSpawnerError(spawnResult)) {
          metrics.increment("supervisor.spawn.failure", { slug });
          metrics.increment("supervisor.executions.error", { slug, reason: "spawn_failed" });
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
          metrics.increment("supervisor.spawn.failure", { slug });
          metrics.increment("supervisor.executions.error", { slug, reason: "invalid_spawn_payload" });
          await withSlugLock(slug, async () => {
            setPendingSpawns(slug, getPendingSpawns(slug) - 1);
          });
          throw makeFailure("SPAWN_FAILED", `Spawner returned invalid instance payload for '${slug}'`, { slug });
        }

        metrics.increment("supervisor.spawn.success", { slug });
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
          const terminateResult = await spawner.terminateSkill(spawnResult.containerId);
          if (!isSpawnerError(terminateResult)) {
            metrics.increment("supervisor.instance.terminated", { slug, source: "shutdown_after_spawn" });
          }
          metrics.increment("supervisor.executions.error", { slug, reason: "shutting_down" });
          throw makeFailure("SUPERVISOR_SHUTTING_DOWN", "Supervisor is shutting down");
        }
      }

      if (!acquiredContainerId) {
        metrics.increment("supervisor.executions.error", { slug, reason: "instance_unavailable" });
        throw makeFailure("INSTANCE_FAILED", "Unable to acquire an instance");
      }

      const meta = instanceMetaById.get(acquiredContainerId);
      const token = instanceTokenById.get(acquiredContainerId);

      if (!meta || !token) {
        await handleInstanceTransportFailure(slug, acquiredContainerId, {
          reason: "missing_instance_metadata",
        });
      }

      const rpcResult = await callInstanceJsonRpc(meta, token, method, params);

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
        metrics.increment("supervisor.executions.success", { slug, method });
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
        metrics.increment("supervisor.executions.error", { slug, reason: "jsonrpc_error" });
        return buildRuntimeStyleErrorFromJsonRpc(rpcResult.error);
      }

      await handleInstanceTransportFailure(slug, acquiredContainerId, rpcResult);
    } finally {
      metrics.observe("supervisor.execution.duration_ms", Date.now() - executionStartedAt, { slug, method });
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
          reaped += 1;
          metrics.increment("supervisor.instance.reaped", { slug });
          metrics.increment("supervisor.instance.terminated", { slug, source: "reap" });
        } else {
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
        failed += 1;
        errors.push({
          containerId: target.containerId,
          code: terminateResult.error.code,
          message: terminateResult.error.message,
        });
      } else {
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
    aggregateCounts.total = 0;
    aggregateCounts.ready = 0;
    aggregateCounts.busy = 0;
    aggregateCounts.pending = 0;
    publishGaugeSnapshot();

    return {
      ok: true,
      terminated,
      failed,
      errors,
    };
  }

  publishGaugeSnapshot();

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
