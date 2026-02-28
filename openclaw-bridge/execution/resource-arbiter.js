const crypto = require("node:crypto");

const ARBITER_NAMESPACE = "f1b33811-5f63-5f8b-95d7-6f0ca6c2f0f7";

function isPlainObject(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function normalizeString(value) {
  return typeof value === "string" ? value.trim() : "";
}

function parsePositiveInteger(value, fallback) {
  const parsed = Number.parseInt(String(value ?? "").trim(), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
}

function createNoopMetrics() {
  return {
    increment: () => {},
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
  };
}

function createNoopLogger() {
  return {
    info: () => {},
    error: () => {},
  };
}

function createSafeLogger(rawLogger) {
  const noop = createNoopLogger();
  const source = rawLogger && typeof rawLogger === "object" ? rawLogger : noop;
  return {
    info: (...args) => {
      try {
        if (typeof source.info === "function") {
          source.info(...args);
        }
      } catch {}
    },
    error: (...args) => {
      try {
        if (typeof source.error === "function") {
          source.error(...args);
        }
      } catch {}
    },
  };
}

function hashPrincipal(principalId) {
  const normalized = normalizeString(principalId) || "anonymous";
  return crypto.createHash("sha256").update(normalized, "utf8").digest("hex").slice(0, 16);
}

function parseUuid(uuid) {
  const raw = normalizeString(uuid).replace(/-/g, "").toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(raw)) {
    throw new Error("Invalid UUID format");
  }
  return Buffer.from(raw, "hex");
}

function formatUuid(buffer) {
  const hex = buffer.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function uuidV5(name, namespace) {
  const namespaceBytes = parseUuid(namespace);
  const nameBytes = Buffer.from(String(name || ""), "utf8");
  const hash = crypto.createHash("sha1").update(namespaceBytes).update(nameBytes).digest();
  const bytes = Buffer.from(hash.slice(0, 16));

  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;

  return formatUuid(bytes);
}

function normalizeResourceLimits(rawLimits) {
  const limits = isPlainObject(rawLimits) ? rawLimits : {};
  return {
    cpuShares: parsePositiveInteger(limits.cpuShares, null),
    memoryLimitMb: parsePositiveInteger(limits.memoryLimitMb, null),
    maxRuntimeSeconds: parsePositiveInteger(limits.maxRuntimeSeconds, null),
    maxOutputBytes: parsePositiveInteger(limits.maxOutputBytes, null),
  };
}

function makeRejectError(code, message, details = {}) {
  const error = new Error(String(message || "Execution rejected by resource arbiter"));
  error.code = String(code || "NODE_CAPACITY_EXCEEDED");
  error.details = details;
  return error;
}

function normalizeToolLimits(rawMap) {
  const map = {};
  if (!isPlainObject(rawMap)) {
    return map;
  }

  for (const [key, value] of Object.entries(rawMap)) {
    const slug = normalizeString(key).toLowerCase();
    if (!slug) {
      continue;
    }
    const parsed = parsePositiveInteger(value, null);
    if (!parsed) {
      continue;
    }
    map[slug] = parsed;
  }

  return map;
}

function createResourceArbiter(options = {}) {
  const execution = isPlainObject(options.execution) ? options.execution : {};
  const metrics = createSafeMetrics(options.metrics);
  const logger = createSafeLogger(options.logger);
  const nodeId = normalizeString(options.nodeId) || normalizeString(process.env.SUPERVISOR_NODE_ID) || "node-unknown";
  const namespace = normalizeString(options.namespace) || ARBITER_NAMESPACE;

  let maxConcurrentContainersPerNode = parsePositiveInteger(
    execution.maxConcurrentContainersPerNode,
    Number.POSITIVE_INFINITY,
  );
  if (!Number.isFinite(maxConcurrentContainersPerNode)) {
    maxConcurrentContainersPerNode = Number.MAX_SAFE_INTEGER;
  }

  let nodeMemoryHardCapMb = parsePositiveInteger(execution.nodeMemoryHardCapMb, Number.POSITIVE_INFINITY);
  if (!Number.isFinite(nodeMemoryHardCapMb)) {
    nodeMemoryHardCapMb = Number.MAX_SAFE_INTEGER;
  }

  let nodeCpuHardCapShares = parsePositiveInteger(execution.nodeCpuHardCapShares, Number.POSITIVE_INFINITY);
  if (!Number.isFinite(nodeCpuHardCapShares)) {
    nodeCpuHardCapShares = Number.MAX_SAFE_INTEGER;
  }

  const toolConcurrencyLimits = normalizeToolLimits(execution.toolConcurrencyLimits);

  const leases = new Map();
  const toolLeaseCounts = new Map();

  let totalMemoryMb = 0;
  let totalCpuShares = 0;

  function emitRejection(reasonCode, toolSlug, principalHash) {
    metrics.increment("tool.execution.rejected", {
      reason: reasonCode,
      node_id: nodeId,
      tool: normalizeString(toolSlug).toLowerCase() || "unknown",
      principal_hash: normalizeString(principalHash) || "anonymous",
    });
  }

  function incrementToolCount(toolSlug) {
    const slug = normalizeString(toolSlug).toLowerCase();
    const current = toolLeaseCounts.get(slug) || 0;
    toolLeaseCounts.set(slug, current + 1);
  }

  function decrementToolCount(toolSlug) {
    const slug = normalizeString(toolSlug).toLowerCase();
    const current = toolLeaseCounts.get(slug) || 0;
    const next = Math.max(0, current - 1);
    if (next === 0) {
      toolLeaseCounts.delete(slug);
      return;
    }
    toolLeaseCounts.set(slug, next);
  }

  function makeLeaseRecord(input, leaseId, extra = {}) {
    const requestId = normalizeString(input.requestId);
    const principalId = normalizeString(input.principalId) || "anonymous";
    const toolSlug = normalizeString(input.toolSlug).toLowerCase();
    const limits = normalizeResourceLimits(input.resourceLimits);
    const principalHash = normalizeString(input.principalHash) || hashPrincipal(principalId);

    return {
      leaseId,
      requestId,
      principalId,
      principalHash,
      toolSlug,
      resourceLimits: limits,
      createdAt: Number.isFinite(Number(input.createdAt)) ? Number(input.createdAt) : Date.now(),
      recovered: extra.recovered === true,
      containerId: normalizeString(input.containerId),
    };
  }

  function validateAcquireInput(input) {
    if (!isPlainObject(input)) {
      throw makeRejectError("NODE_CAPACITY_EXCEEDED", "Arbiter input must be an object");
    }

    const requestId = normalizeString(input.requestId);
    if (!requestId) {
      throw makeRejectError("NODE_CAPACITY_EXCEEDED", "requestId is required for arbitration");
    }

    const toolSlug = normalizeString(input.toolSlug).toLowerCase();
    if (!toolSlug) {
      throw makeRejectError("NODE_CAPACITY_EXCEEDED", "toolSlug is required for arbitration");
    }

    const limits = normalizeResourceLimits(input.resourceLimits);
    if (!limits.cpuShares || !limits.memoryLimitMb) {
      throw makeRejectError("NODE_CAPACITY_EXCEEDED", "resourceLimits with cpuShares and memoryLimitMb are required");
    }

    return {
      requestId,
      toolSlug,
      limits,
      principalId: normalizeString(input.principalId) || "anonymous",
      principalHash: normalizeString(input.principalHash) || hashPrincipal(input.principalId),
    };
  }

  function getProjectedState(toolSlug, limits) {
    const normalizedTool = normalizeString(toolSlug).toLowerCase();
    const toolCount = toolLeaseCounts.get(normalizedTool) || 0;
    return {
      projectedNodeCount: leases.size + 1,
      projectedToolCount: toolCount + 1,
      projectedMemoryMb: totalMemoryMb + limits.memoryLimitMb,
      projectedCpuShares: totalCpuShares + limits.cpuShares,
    };
  }

  function reject(reasonCode, message, input, projection) {
    const principalHash = normalizeString(input.principalHash) || hashPrincipal(input.principalId);
    emitRejection(reasonCode, input.toolSlug, principalHash);
    throw makeRejectError(reasonCode, message, {
      nodeId,
      requestId: normalizeString(input.requestId),
      toolSlug: normalizeString(input.toolSlug).toLowerCase(),
      principalHash,
      projection,
      limits: normalizeResourceLimits(input.resourceLimits),
      maxConcurrentContainersPerNode,
      nodeMemoryHardCapMb,
      nodeCpuHardCapShares,
      toolLimit: toolConcurrencyLimits[normalizeString(input.toolSlug).toLowerCase()] || null,
    });
  }

  function tryAcquire(input = {}) {
    const normalized = validateAcquireInput(input);
    const leaseId = uuidV5(normalized.requestId, namespace);

    const existing = leases.get(leaseId);
    if (existing) {
      return {
        ok: true,
        leaseId,
        lease: { ...existing },
        idempotent: true,
      };
    }

    const projection = getProjectedState(normalized.toolSlug, normalized.limits);

    if (projection.projectedNodeCount > maxConcurrentContainersPerNode) {
      reject(
        "NODE_CAPACITY_EXCEEDED",
        "Node concurrency cap exceeded",
        {
          ...input,
          principalHash: normalized.principalHash,
          toolSlug: normalized.toolSlug,
        },
        projection,
      );
    }

    const toolLimit = toolConcurrencyLimits[normalized.toolSlug];
    if (toolLimit && projection.projectedToolCount > toolLimit) {
      reject(
        "TOOL_CONCURRENCY_LIMIT_EXCEEDED",
        `Tool concurrency limit exceeded for '${normalized.toolSlug}'`,
        {
          ...input,
          principalHash: normalized.principalHash,
          toolSlug: normalized.toolSlug,
        },
        projection,
      );
    }

    if (projection.projectedMemoryMb > nodeMemoryHardCapMb) {
      reject(
        "NODE_MEMORY_PRESSURE_EXCEEDED",
        "Node memory hard cap exceeded",
        {
          ...input,
          principalHash: normalized.principalHash,
          toolSlug: normalized.toolSlug,
        },
        projection,
      );
    }

    if (projection.projectedCpuShares > nodeCpuHardCapShares) {
      reject(
        "NODE_CPU_SATURATION_EXCEEDED",
        "Node CPU hard cap exceeded",
        {
          ...input,
          principalHash: normalized.principalHash,
          toolSlug: normalized.toolSlug,
        },
        projection,
      );
    }

    const lease = makeLeaseRecord(
      {
        ...input,
        requestId: normalized.requestId,
        toolSlug: normalized.toolSlug,
        principalId: normalized.principalId,
        principalHash: normalized.principalHash,
        resourceLimits: normalized.limits,
      },
      leaseId,
    );

    leases.set(leaseId, lease);
    incrementToolCount(lease.toolSlug);
    totalMemoryMb += lease.resourceLimits.memoryLimitMb;
    totalCpuShares += lease.resourceLimits.cpuShares;

    return {
      ok: true,
      leaseId,
      lease: { ...lease },
      idempotent: false,
    };
  }

  function release(leaseId) {
    const key = normalizeString(leaseId);
    if (!key) {
      return { ok: true, released: false };
    }

    const lease = leases.get(key);
    if (!lease) {
      return { ok: true, released: false };
    }

    leases.delete(key);
    decrementToolCount(lease.toolSlug);
    totalMemoryMb = Math.max(0, totalMemoryMb - lease.resourceLimits.memoryLimitMb);
    totalCpuShares = Math.max(0, totalCpuShares - lease.resourceLimits.cpuShares);

    return {
      ok: true,
      released: true,
      leaseId: key,
    };
  }

  function rebuildFromLeases(records = []) {
    leases.clear();
    toolLeaseCounts.clear();
    totalMemoryMb = 0;
    totalCpuShares = 0;

    const restored = [];

    for (const record of records) {
      try {
        const requestId = normalizeString(record.requestId);
        const toolSlug = normalizeString(record.toolSlug).toLowerCase();
        const limits = normalizeResourceLimits(record.resourceLimits);
        if (!requestId || !toolSlug || !limits.cpuShares || !limits.memoryLimitMb) {
          continue;
        }

        const leaseId = uuidV5(requestId, namespace);
        if (leases.has(leaseId)) {
          continue;
        }

        const lease = makeLeaseRecord(
          {
            requestId,
            principalId: normalizeString(record.principalId) || "anonymous",
            principalHash: normalizeString(record.principalHash),
            toolSlug,
            resourceLimits: limits,
            createdAt: record.createdAt,
            containerId: normalizeString(record.containerId),
          },
          leaseId,
          { recovered: true },
        );

        leases.set(leaseId, lease);
        incrementToolCount(lease.toolSlug);
        totalMemoryMb += lease.resourceLimits.memoryLimitMb;
        totalCpuShares += lease.resourceLimits.cpuShares;
        restored.push({ ...lease });
      } catch {}
    }

    logger.info({
      event: "resource_arbiter_rebuild",
      node_id: nodeId,
      restored_count: restored.length,
      total_memory_mb: totalMemoryMb,
      total_cpu_shares: totalCpuShares,
      total_leases: leases.size,
      timestamp: new Date().toISOString(),
    });

    return {
      ok: true,
      restored,
      restoredCount: restored.length,
    };
  }

  async function reconstructFromActiveExecutions(recordsOrProvider) {
    if (Array.isArray(recordsOrProvider)) {
      return rebuildFromLeases(recordsOrProvider);
    }

    if (recordsOrProvider && typeof recordsOrProvider.listActiveExecutions === "function") {
      try {
        const records = await recordsOrProvider.listActiveExecutions();
        return rebuildFromLeases(Array.isArray(records) ? records : []);
      } catch (error) {
        logger.error({
          event: "resource_arbiter_rebuild_failed",
          node_id: nodeId,
          message: error && error.message ? error.message : String(error),
          timestamp: new Date().toISOString(),
        });
        return {
          ok: false,
          restored: [],
          restoredCount: 0,
        };
      }
    }

    return rebuildFromLeases([]);
  }

  function getSnapshot() {
    return {
      nodeId,
      totalLeases: leases.size,
      totalMemoryMb,
      totalCpuShares,
      maxConcurrentContainersPerNode,
      nodeMemoryHardCapMb,
      nodeCpuHardCapShares,
      toolConcurrencyLimits: { ...toolConcurrencyLimits },
      leases: Array.from(leases.values())
        .map((lease) => ({ ...lease }))
        .sort((a, b) => a.leaseId.localeCompare(b.leaseId)),
    };
  }

  return {
    nodeId,
    ARBITER_NAMESPACE,
    hashPrincipal,
    tryAcquire,
    release,
    reconstructFromActiveExecutions,
    getSnapshot,
  };
}

module.exports = {
  ARBITER_NAMESPACE,
  createResourceArbiter,
  hashPrincipal,
};
