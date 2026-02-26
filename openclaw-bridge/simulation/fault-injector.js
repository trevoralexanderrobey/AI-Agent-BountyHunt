"use strict";

function normalizeNodeId(value) {
  return typeof value === "string" ? value.trim() : "";
}

function normalizeStatusCode(value) {
  if (value === null || typeof value === "undefined") {
    return null;
  }
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return null;
  }
  const code = Math.floor(parsed);
  if (code < 100 || code > 599) {
    return null;
  }
  return code;
}

function normalizeLatencyMs(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) {
    return 0;
  }
  return Math.floor(parsed);
}

function normalizeConfigPatch(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return {};
  }
  const out = {};
  if (Object.prototype.hasOwnProperty.call(raw, "shardCount")) {
    const shardCount = Number(raw.shardCount);
    if (Number.isFinite(shardCount) && shardCount > 0) {
      out.shardCount = Math.floor(shardCount);
    }
  }
  if (Object.prototype.hasOwnProperty.call(raw, "leaderTimeoutMs")) {
    const leaderTimeoutMs = Number(raw.leaderTimeoutMs);
    if (Number.isFinite(leaderTimeoutMs) && leaderTimeoutMs > 0) {
      out.leaderTimeoutMs = Math.floor(leaderTimeoutMs);
    }
  }
  if (Object.prototype.hasOwnProperty.call(raw, "heartbeatIntervalMs")) {
    const heartbeatIntervalMs = Number(raw.heartbeatIntervalMs);
    if (Number.isFinite(heartbeatIntervalMs) && heartbeatIntervalMs > 0) {
      out.heartbeatIntervalMs = Math.floor(heartbeatIntervalMs);
    }
  }
  if (Object.prototype.hasOwnProperty.call(raw, "configHash")) {
    out.configHash = typeof raw.configHash === "string" ? raw.configHash.trim() : "";
  }
  return out;
}

function edgeKey(fromNodeId, toNodeId) {
  return `${fromNodeId}->${toNodeId}`;
}

function pairKey(leftNodeId, rightNodeId) {
  const pair = [leftNodeId, rightNodeId].sort((a, b) => a.localeCompare(b));
  return `${pair[0]}|${pair[1]}`;
}

function createFaultInjector(options = {}) {
  const downNodes = new Set();
  const timeoutTargets = new Set();
  const latencyByTarget = new Map();
  const statusOverrideByTarget = new Map();
  const directionalDrops = new Set();
  const symmetricPartitionPairs = new Set();
  const versionSkewByNode = new Map();
  const configMismatchByNode = new Map();
  const listeners = new Set();

  const defaultLatencyMs = normalizeLatencyMs(options.defaultLatencyMs || 0);

  function emitChange() {
    for (const listener of Array.from(listeners)) {
      try {
        listener();
      } catch {}
    }
  }

  function onChange(listener) {
    if (typeof listener !== "function") {
      return () => {};
    }
    listeners.add(listener);
    return () => {
      listeners.delete(listener);
    };
  }

  function setNodeDown(rawNodeId, down = true) {
    const nodeId = normalizeNodeId(rawNodeId);
    if (!nodeId) {
      return false;
    }
    if (down) {
      downNodes.add(nodeId);
    } else {
      downNodes.delete(nodeId);
    }
    emitChange();
    return true;
  }

  function setLatency(rawNodeId, latencyMs) {
    const nodeId = normalizeNodeId(rawNodeId);
    if (!nodeId) {
      return false;
    }
    const normalized = normalizeLatencyMs(latencyMs);
    if (normalized <= 0) {
      latencyByTarget.delete(nodeId);
    } else {
      latencyByTarget.set(nodeId, normalized);
    }
    emitChange();
    return true;
  }

  function setTimeoutFault(rawNodeId, enabled = true) {
    const nodeId = normalizeNodeId(rawNodeId);
    if (!nodeId) {
      return false;
    }
    if (enabled) {
      timeoutTargets.add(nodeId);
    } else {
      timeoutTargets.delete(nodeId);
    }
    emitChange();
    return true;
  }

  function setStatusOverride(rawNodeId, statusCodeOrNull) {
    const nodeId = normalizeNodeId(rawNodeId);
    if (!nodeId) {
      return false;
    }
    const code = normalizeStatusCode(statusCodeOrNull);
    if (code === null) {
      statusOverrideByTarget.delete(nodeId);
    } else {
      statusOverrideByTarget.set(nodeId, code);
    }
    emitChange();
    return true;
  }

  function injectVersionSkew(rawNodeId, rawVersion) {
    const nodeId = normalizeNodeId(rawNodeId);
    if (!nodeId) {
      return false;
    }
    const version = typeof rawVersion === "string" ? rawVersion.trim() : "";
    if (!version) {
      versionSkewByNode.delete(nodeId);
    } else {
      versionSkewByNode.set(nodeId, version);
    }
    emitChange();
    return true;
  }

  function injectConfigMismatch(rawNodeId, partialConfig = {}) {
    const nodeId = normalizeNodeId(rawNodeId);
    if (!nodeId) {
      return false;
    }
    const patch = normalizeConfigPatch(partialConfig);
    if (Object.keys(patch).length === 0) {
      configMismatchByNode.delete(nodeId);
    } else {
      configMismatchByNode.set(nodeId, patch);
    }
    emitChange();
    return true;
  }

  function setPartition(nodesA = [], nodesB = []) {
    const groupA = Array.from(new Set((Array.isArray(nodesA) ? nodesA : []).map((item) => normalizeNodeId(item)).filter(Boolean)));
    const groupB = Array.from(new Set((Array.isArray(nodesB) ? nodesB : []).map((item) => normalizeNodeId(item)).filter(Boolean)));
    for (const left of groupA) {
      for (const right of groupB) {
        if (left === right) {
          continue;
        }
        symmetricPartitionPairs.add(pairKey(left, right));
      }
    }
    emitChange();
    return {
      ok: true,
      groups: {
        a: groupA,
        b: groupB,
      },
    };
  }

  function clearPartition() {
    symmetricPartitionPairs.clear();
    directionalDrops.clear();
    emitChange();
    return {
      ok: true,
    };
  }

  function setDirectionalDrop(rawFromNodeId, rawToNodeId, enabled = true) {
    const fromNodeId = normalizeNodeId(rawFromNodeId);
    const toNodeId = normalizeNodeId(rawToNodeId);
    if (!fromNodeId || !toNodeId || fromNodeId === toNodeId) {
      return false;
    }
    const key = edgeKey(fromNodeId, toNodeId);
    if (enabled) {
      directionalDrops.add(key);
    } else {
      directionalDrops.delete(key);
    }
    emitChange();
    return true;
  }

  function isLinkBlocked(fromNodeId, toNodeId) {
    const from = normalizeNodeId(fromNodeId);
    const to = normalizeNodeId(toNodeId);
    if (!from || !to || from === to) {
      return false;
    }
    if (directionalDrops.has(edgeKey(from, to))) {
      return true;
    }
    return symmetricPartitionPairs.has(pairKey(from, to));
  }

  function getInjectedVersion(rawNodeId) {
    const nodeId = normalizeNodeId(rawNodeId);
    if (!nodeId) {
      return "";
    }
    return versionSkewByNode.get(nodeId) || "";
  }

  function getInjectedConfig(rawNodeId) {
    const nodeId = normalizeNodeId(rawNodeId);
    if (!nodeId) {
      return null;
    }
    const patch = configMismatchByNode.get(nodeId);
    if (!patch) {
      return null;
    }
    return {
      ...patch,
    };
  }

  function evaluateRequest(context = {}) {
    const sourceNodeId = normalizeNodeId(context.sourceNodeId);
    const targetNodeId = normalizeNodeId(context.targetNodeId);
    const blocked = isLinkBlocked(sourceNodeId, targetNodeId);
    const targetDown = targetNodeId ? downNodes.has(targetNodeId) : false;
    const timeout = blocked || targetDown || (targetNodeId ? timeoutTargets.has(targetNodeId) : false);
    const statusCode = targetNodeId ? statusOverrideByTarget.get(targetNodeId) || null : null;
    const latencyMs = targetNodeId ? latencyByTarget.get(targetNodeId) || defaultLatencyMs : defaultLatencyMs;

    return {
      timeout,
      blocked,
      targetDown,
      statusCode,
      latencyMs,
    };
  }

  function getState() {
    return {
      downNodes: Array.from(downNodes).sort((a, b) => a.localeCompare(b)),
      timeoutTargets: Array.from(timeoutTargets).sort((a, b) => a.localeCompare(b)),
      latencyByTarget: Array.from(latencyByTarget.entries())
        .sort((a, b) => a[0].localeCompare(b[0]))
        .map(([nodeId, latencyMs]) => ({ nodeId, latencyMs })),
      statusOverrides: Array.from(statusOverrideByTarget.entries())
        .sort((a, b) => a[0].localeCompare(b[0]))
        .map(([nodeId, statusCode]) => ({ nodeId, statusCode })),
      directionalDrops: Array.from(directionalDrops).sort((a, b) => a.localeCompare(b)),
      symmetricPartitionPairs: Array.from(symmetricPartitionPairs).sort((a, b) => a.localeCompare(b)),
      versionSkews: Array.from(versionSkewByNode.entries())
        .sort((a, b) => a[0].localeCompare(b[0]))
        .map(([nodeId, softwareVersion]) => ({ nodeId, softwareVersion })),
      configMismatches: Array.from(configMismatchByNode.entries())
        .sort((a, b) => a[0].localeCompare(b[0]))
        .map(([nodeId, patch]) => ({ nodeId, patch: { ...patch } })),
    };
  }

  return {
    setNodeDown,
    setLatency,
    setTimeout: setTimeoutFault,
    setStatusOverride,
    injectVersionSkew,
    injectConfigMismatch,
    setPartition,
    clearPartition,
    setDirectionalDrop,
    evaluateRequest,
    getInjectedVersion,
    getInjectedConfig,
    getState,
    onChange,
  };
}

module.exports = {
  createFaultInjector,
};
