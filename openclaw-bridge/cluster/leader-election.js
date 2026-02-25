const DEFAULT_LEADER_TIMEOUT_MS = 15000;

function parsePositiveInt(value, fallback) {
  const parsed = Number.parseInt(String(value ?? "").trim(), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
}

function normalizeNodeId(value) {
  return typeof value === "string" ? value.trim() : "";
}

function dedupeAndSortNodeIds(nodeIds) {
  const unique = new Set();
  for (const nodeId of nodeIds) {
    const normalized = normalizeNodeId(nodeId);
    if (normalized) {
      unique.add(normalized);
    }
  }
  return Array.from(unique).sort((left, right) => left.localeCompare(right));
}

function createLeaderElection(options = {}) {
  const localNodeId = normalizeNodeId(options.localNodeId || options.nodeId);
  if (!localNodeId) {
    throw new Error("cluster localNodeId is required");
  }

  const leaderTimeoutMs = parsePositiveInt(options.leaderTimeoutMs, DEFAULT_LEADER_TIMEOUT_MS);
  const listeners = new Set();
  const lastSeenByNode = new Map();
  let currentLeader = "";

  function emitLeadershipChange(previousLeader, nextLeader, healthyNodeIds, timestamp) {
    const payload = {
      previousLeader: previousLeader || null,
      currentLeader: nextLeader || null,
      healthyNodeIds: healthyNodeIds.slice(),
      timestamp,
    };
    for (const callback of listeners) {
      try {
        callback(payload);
      } catch {}
    }
  }

  function recordHeartbeat(rawNodeId, timestamp = Date.now()) {
    const nodeId = normalizeNodeId(rawNodeId);
    if (!nodeId) {
      return false;
    }
    const ts = Number.isFinite(Number(timestamp)) ? Math.max(0, Number(timestamp)) : Date.now();
    lastSeenByNode.set(nodeId, ts);
    return true;
  }

  function getHealthyNodeIds(now = Date.now()) {
    const safeNow = Number.isFinite(Number(now)) ? Math.max(0, Number(now)) : Date.now();
    const healthy = [];
    for (const [nodeId, lastSeen] of lastSeenByNode.entries()) {
      if (safeNow - lastSeen <= leaderTimeoutMs) {
        healthy.push(nodeId);
      }
    }
    return dedupeAndSortNodeIds(healthy);
  }

  function recompute(snapshot = {}) {
    const timestamp = Number.isFinite(Number(snapshot.timestamp)) ? Math.max(0, Number(snapshot.timestamp)) : Date.now();
    const healthyNodeIds = Array.isArray(snapshot.healthyNodeIds)
      ? dedupeAndSortNodeIds(snapshot.healthyNodeIds)
      : Array.isArray(snapshot.healthyNodes)
      ? dedupeAndSortNodeIds(snapshot.healthyNodes.map((item) => (item && typeof item === "object" ? item.nodeId : item)))
      : getHealthyNodeIds(timestamp);

    const previousLeader = currentLeader;
    currentLeader = healthyNodeIds.length > 0 ? healthyNodeIds[0] : "";
    const changed = previousLeader !== currentLeader;

    if (changed) {
      emitLeadershipChange(previousLeader, currentLeader, healthyNodeIds, timestamp);
    }

    return {
      changed,
      previousLeader: previousLeader || null,
      currentLeader: currentLeader || null,
      healthyNodeIds,
    };
  }

  function isLeader() {
    return Boolean(currentLeader && currentLeader === localNodeId);
  }

  function getCurrentLeader() {
    return currentLeader || null;
  }

  function onLeadershipChange(callback) {
    if (typeof callback !== "function") {
      return () => {};
    }
    listeners.add(callback);
    return () => {
      listeners.delete(callback);
    };
  }

  return {
    localNodeId,
    leaderTimeoutMs,
    recordHeartbeat,
    getHealthyNodeIds,
    recompute,
    isLeader,
    getCurrentLeader,
    onLeadershipChange,
  };
}

module.exports = {
  createLeaderElection,
};
