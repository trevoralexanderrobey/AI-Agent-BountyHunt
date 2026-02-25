const crypto = require("node:crypto");
const http = require("node:http");
const https = require("node:https");

const { STATUS_DOWN, STATUS_UP } = require("../federation/peer-registry.js");
const { createLeaderElection } = require("./leader-election.js");

const DEFAULT_SHARD_COUNT = 16;
const DEFAULT_HEARTBEAT_INTERVAL_MS = 5000;
const DEFAULT_LEADER_TIMEOUT_MS = 15000;
const DEFAULT_METRICS_FETCH_TIMEOUT_MS = 3000;

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

function normalizeSlug(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function normalizeCapabilities(raw) {
  if (!Array.isArray(raw)) {
    return [];
  }
  const unique = new Set();
  for (const value of raw) {
    if (typeof value !== "string") {
      continue;
    }
    const normalized = normalizeSlug(value);
    if (!normalized) {
      continue;
    }
    unique.add(normalized);
  }
  return Array.from(unique).sort((left, right) => left.localeCompare(right));
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

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  Object.freeze(value);
  for (const key of Object.keys(value)) {
    deepFreeze(value[key]);
  }
  return value;
}

function computeShardId(slug, shardCount) {
  const digest = crypto.createHash("sha256").update(String(slug), "utf8").digest();
  const raw = digest.readUInt32BE(0);
  return raw % shardCount;
}

function scoreNodeForShard(shardId, nodeId) {
  const digest = crypto
    .createHash("sha256")
    .update(`${String(shardId)}:${String(nodeId)}`, "utf8")
    .digest("hex");
  return BigInt(`0x${digest}`);
}

function computeShardAssignmentDigest(shardCount, healthyNodeIds) {
  const nodeIds = Array.from(new Set(healthyNodeIds.map((item) => normalizeNodeId(item)).filter(Boolean))).sort((left, right) =>
    left.localeCompare(right),
  );
  if (nodeIds.length === 0) {
    return "";
  }

  const owners = [];
  for (let shardId = 0; shardId < shardCount; shardId += 1) {
    let bestNodeId = "";
    let bestScore = -1n;
    for (const nodeId of nodeIds) {
      const score = scoreNodeForShard(shardId, nodeId);
      if (score > bestScore || (score === bestScore && nodeId.localeCompare(bestNodeId) < 0)) {
        bestScore = score;
        bestNodeId = nodeId;
      }
    }
    owners.push(`${String(shardId)}:${bestNodeId}`);
  }

  return crypto.createHash("sha256").update(owners.join("|"), "utf8").digest("hex");
}

function extractGaugeValue(gauges, name) {
  if (!Array.isArray(gauges)) {
    return null;
  }

  for (const gauge of gauges) {
    if (!gauge || typeof gauge !== "object") {
      continue;
    }
    if (gauge.name !== name) {
      continue;
    }
    const labels = gauge.labels && typeof gauge.labels === "object" ? gauge.labels : {};
    if (Object.keys(labels).length > 0) {
      continue;
    }
    const numericValue = Number(gauge.value);
    if (!Number.isFinite(numericValue)) {
      continue;
    }
    return numericValue;
  }

  return null;
}

function fetchPeerClusterConfig(peer, timeoutMs) {
  return new Promise((resolve) => {
    const peerId = normalizeNodeId(peer && peer.peerId);
    const peerUrl = typeof peer?.url === "string" ? peer.url.trim() : "";
    const authToken = typeof peer?.authToken === "string" ? peer.authToken.trim() : "";

    if (!peerId || !peerUrl || !authToken) {
      resolve({
        ok: false,
        reason: "invalid_peer_metadata",
      });
      return;
    }

    let endpoint;
    try {
      endpoint = new URL("/metrics", peerUrl);
    } catch {
      resolve({
        ok: false,
        reason: "invalid_peer_url",
      });
      return;
    }

    const transport = endpoint.protocol === "https:" ? https : http;
    const req = transport.request(
      {
        protocol: endpoint.protocol,
        hostname: endpoint.hostname,
        port: endpoint.port || (endpoint.protocol === "https:" ? 443 : 80),
        path: `${endpoint.pathname}${endpoint.search}`,
        method: "GET",
        headers: {
          accept: "application/json",
          authorization: `Bearer ${authToken}`,
        },
      },
      (res) => {
        let raw = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => {
          raw += chunk;
        });
        res.on("end", () => {
          if (res.statusCode !== 200) {
            resolve({
              ok: false,
              reason: "metrics_http_status",
              statusCode: res.statusCode,
            });
            return;
          }

          let parsed;
          try {
            parsed = raw ? JSON.parse(raw) : {};
          } catch {
            resolve({
              ok: false,
              reason: "invalid_metrics_payload",
            });
            return;
          }

          const gauges = Array.isArray(parsed && parsed.metrics && parsed.metrics.gauges) ? parsed.metrics.gauges : [];
          const shardCount = extractGaugeValue(gauges, "cluster.shard_count");
          const leaderTimeoutMs = extractGaugeValue(gauges, "cluster.leader_timeout_ms");
          const heartbeatIntervalMs = extractGaugeValue(gauges, "cluster.heartbeat_interval_ms");

          if (shardCount === null || leaderTimeoutMs === null || heartbeatIntervalMs === null) {
            resolve({
              ok: false,
              reason: "missing_cluster_config_gauges",
            });
            return;
          }

          resolve({
            ok: true,
            config: {
              shardCount: Math.floor(shardCount),
              leaderTimeoutMs: Math.floor(leaderTimeoutMs),
              heartbeatIntervalMs: Math.floor(heartbeatIntervalMs),
            },
          });
        });
      },
    );

    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error("cluster metrics timeout"));
    });

    req.on("error", () => {
      resolve({
        ok: false,
        reason: "metrics_transport_error",
      });
    });

    req.end();
  });
}

function normalizeExcludeNodeIds(rawExcludeNodeIds) {
  const excluded = new Set();
  if (!Array.isArray(rawExcludeNodeIds)) {
    return excluded;
  }
  for (const nodeId of rawExcludeNodeIds) {
    const normalized = normalizeNodeId(nodeId);
    if (normalized) {
      excluded.add(normalized);
    }
  }
  return excluded;
}

function createClusterManager(options = {}) {
  const localNodeId = normalizeNodeId(options.nodeId || options.localNodeId);
  if (!localNodeId) {
    throw new Error("cluster nodeId is required");
  }

  const peerRegistry = options.peerRegistry;
  if (
    !peerRegistry ||
    typeof peerRegistry.listPeers !== "function" ||
    typeof peerRegistry.getPeer !== "function" ||
    typeof peerRegistry.updatePeerHealth !== "function"
  ) {
    throw new Error("cluster peerRegistry with listPeers(), getPeer(), and updatePeerHealth() is required");
  }

  const federationHeartbeat = options.heartbeat;
  if (!federationHeartbeat || typeof federationHeartbeat.runOnce !== "function" || typeof federationHeartbeat.stop !== "function") {
    throw new Error("cluster heartbeat with runOnce() and stop() is required");
  }

  const shardCount = parsePositiveInt(options.shardCount, DEFAULT_SHARD_COUNT);
  const heartbeatIntervalMs = parsePositiveInt(options.heartbeatIntervalMs, DEFAULT_HEARTBEAT_INTERVAL_MS);
  const leaderTimeoutMs = parsePositiveInt(options.leaderTimeoutMs, DEFAULT_LEADER_TIMEOUT_MS);
  const metricsFetchTimeoutMs = parsePositiveInt(options.metricsFetchTimeoutMs, DEFAULT_METRICS_FETCH_TIMEOUT_MS);
  const metrics = createSafeMetrics(options.metrics);
  const localCapabilities = normalizeCapabilities(options.localCapabilities);
  const leaderElection = createLeaderElection({
    localNodeId,
    leaderTimeoutMs,
  });

  const expectedClusterConfig = {
    shardCount,
    heartbeatIntervalMs,
    leaderTimeoutMs,
  };

  let running = false;
  let reconcileInFlight = false;
  let timer = null;
  let snapshotVersion = 0;
  let hasShardBaseline = false;
  let previousMembershipKey = "";
  let previousAssignmentDigest = "";
  let previousNonSelfHealthyCount = 0;

  const mismatchStateByPeer = new Map();
  const mismatchReasonByPeer = new Map();

  let currentSnapshot = deepFreeze({
    version: 0,
    createdAt: 0,
    clusterConfig: {
      shardCount,
      heartbeatIntervalMs,
      leaderTimeoutMs,
    },
    healthyNodes: [],
    nodes: [],
    capabilities: [],
    configCompatibility: {
      allCompatible: true,
      mismatchedNodeIds: [],
    },
  });

  function publishClusterConfigGauges() {
    metrics.gauge("cluster.shard_count", shardCount);
    metrics.gauge("cluster.leader_timeout_ms", leaderTimeoutMs);
    metrics.gauge("cluster.heartbeat_interval_ms", heartbeatIntervalMs);
  }

  function supportsSlug(capabilities, slug) {
    if (!Array.isArray(capabilities) || capabilities.length === 0) {
      return false;
    }
    return capabilities.includes("*") || capabilities.includes(slug);
  }

  function buildSnapshot(peers, now) {
    const nodes = [];

    nodes.push({
      nodeId: localNodeId,
      isLocal: true,
      healthy: true,
      status: STATUS_UP,
      capabilities: localCapabilities.slice(),
      configCompatible: true,
      configMismatch: false,
      configMismatchReason: "",
      lastHeartbeat: now,
      lastLatencyMs: 0,
    });

    for (const peer of peers) {
      const peerId = normalizeNodeId(peer && peer.peerId);
      if (!peerId || peerId === localNodeId) {
        continue;
      }

      const mismatch = mismatchStateByPeer.get(peerId) === true;
      const effectiveStatus = mismatch ? STATUS_DOWN : peer.status === STATUS_UP ? STATUS_UP : STATUS_DOWN;

      nodes.push({
        nodeId: peerId,
        isLocal: false,
        healthy: effectiveStatus === STATUS_UP,
        status: effectiveStatus,
        capabilities: normalizeCapabilities(peer.capabilities),
        configCompatible: !mismatch,
        configMismatch: mismatch,
        configMismatchReason: mismatch ? mismatchReasonByPeer.get(peerId) || "cluster_config_mismatch" : "",
        lastHeartbeat: Number.isFinite(Number(peer.lastHeartbeat)) ? Math.max(0, Number(peer.lastHeartbeat)) : 0,
        lastLatencyMs: Number.isFinite(Number(peer.lastLatencyMs)) ? Math.max(0, Number(peer.lastLatencyMs)) : 0,
      });
    }

    nodes.sort((left, right) => left.nodeId.localeCompare(right.nodeId));

    const healthyNodes = nodes
      .filter((node) => node.healthy)
      .map((node) => ({
        nodeId: node.nodeId,
        isLocal: node.isLocal,
        capabilities: node.capabilities.slice(),
        lastHeartbeat: node.lastHeartbeat,
        lastLatencyMs: node.lastLatencyMs,
      }));

    const capabilities = nodes.map((node) => ({
      nodeId: node.nodeId,
      capabilities: node.capabilities.slice(),
    }));

    const configCompatibility = {
      allCompatible: nodes.every((node) => node.configCompatible),
      mismatchedNodeIds: nodes.filter((node) => node.configMismatch).map((node) => node.nodeId),
    };

    snapshotVersion += 1;

    return deepFreeze({
      version: snapshotVersion,
      createdAt: now,
      clusterConfig: {
        shardCount,
        heartbeatIntervalMs,
        leaderTimeoutMs,
      },
      healthyNodes,
      nodes,
      capabilities,
      configCompatibility,
    });
  }

  function evaluateShardRebalance(snapshot) {
    const healthyNodeIds = snapshot.healthyNodes.map((node) => node.nodeId);
    const nextMembershipKey = healthyNodeIds.slice().sort((left, right) => left.localeCompare(right)).join(",");
    const nextAssignmentDigest = computeShardAssignmentDigest(shardCount, healthyNodeIds);
    const nextNonSelfHealthyCount = snapshot.healthyNodes.filter((node) => !node.isLocal).length;

    if (!hasShardBaseline) {
      hasShardBaseline = true;
      previousMembershipKey = nextMembershipKey;
      previousAssignmentDigest = nextAssignmentDigest;
      previousNonSelfHealthyCount = nextNonSelfHealthyCount;
      return;
    }

    const membershipChanged = nextMembershipKey !== previousMembershipKey;
    const assignmentChanged = nextAssignmentDigest !== previousAssignmentDigest;
    const shouldCountRebalance =
      membershipChanged && assignmentChanged && previousNonSelfHealthyCount > 0 && nextNonSelfHealthyCount > 0;

    if (shouldCountRebalance) {
      metrics.increment("cluster.shard_rebalance");
    }

    previousMembershipKey = nextMembershipKey;
    previousAssignmentDigest = nextAssignmentDigest;
    previousNonSelfHealthyCount = nextNonSelfHealthyCount;
  }

  function publishNodeGauges(snapshot) {
    const currentLeader = leaderElection.getCurrentLeader();
    for (const node of snapshot.nodes) {
      metrics.gauge("cluster.node_status", node.healthy ? 1 : 0, { node_id: node.nodeId });
      metrics.gauge("cluster.current_leader", currentLeader && currentLeader === node.nodeId ? 1 : 0, {
        node_id: node.nodeId,
      });
    }
  }

  async function validatePeerClusterConfig(peer, now) {
    const peerId = normalizeNodeId(peer && peer.peerId);
    if (!peerId || peerId === localNodeId) {
      return {
        peerId,
        mismatch: false,
      };
    }

    if (peer.status !== STATUS_UP) {
      return {
        peerId,
        mismatch: false,
      };
    }

    const fullPeer = peerRegistry.getPeer(peerId);
    const fetched = await fetchPeerClusterConfig(fullPeer, metricsFetchTimeoutMs);
    if (!fetched.ok) {
      return {
        peerId,
        mismatch: true,
        reason: fetched.reason || "cluster_config_unavailable",
      };
    }

    const remoteConfig = fetched.config || {};
    const mismatch =
      remoteConfig.shardCount !== expectedClusterConfig.shardCount ||
      remoteConfig.heartbeatIntervalMs !== expectedClusterConfig.heartbeatIntervalMs ||
      remoteConfig.leaderTimeoutMs !== expectedClusterConfig.leaderTimeoutMs;

    if (!mismatch) {
      return {
        peerId,
        mismatch: false,
      };
    }

    return {
      peerId,
      mismatch: true,
      reason: "cluster_config_mismatch",
      details: {
        expected: expectedClusterConfig,
        received: remoteConfig,
      },
    };
  }

  async function reconcile(options = {}) {
    if (reconcileInFlight) {
      return {
        ok: true,
        skipped: true,
      };
    }

    reconcileInFlight = true;
    const strictMode = Boolean(options.strictMode);

    try {
      publishClusterConfigGauges();
      federationHeartbeat.stop();
      await federationHeartbeat.runOnce();

      const now = Date.now();
      const peers = peerRegistry.listPeers();
      const seenPeerIds = new Set();
      const mismatches = [];

      for (const peer of peers) {
        const peerId = normalizeNodeId(peer && peer.peerId);
        if (!peerId || peerId === localNodeId) {
          continue;
        }

        seenPeerIds.add(peerId);
        const validation = await validatePeerClusterConfig(peer, now);
        const nextMismatch = Boolean(validation.mismatch);
        const previousMismatch = mismatchStateByPeer.get(peerId) === true;

        if (nextMismatch) {
          mismatchReasonByPeer.set(peerId, validation.reason || "cluster_config_mismatch");
          mismatches.push({
            peerId,
            reason: validation.reason || "cluster_config_mismatch",
            details: validation.details || null,
          });
          peerRegistry.updatePeerHealth(peerId, {
            status: STATUS_DOWN,
            lastHeartbeat: now,
          });
        } else {
          mismatchReasonByPeer.delete(peerId);
        }

        mismatchStateByPeer.set(peerId, nextMismatch);
        if (nextMismatch && !previousMismatch) {
          metrics.increment("cluster.config_mismatch");
        }
      }

      for (const peerId of Array.from(mismatchStateByPeer.keys())) {
        if (!seenPeerIds.has(peerId)) {
          mismatchStateByPeer.delete(peerId);
          mismatchReasonByPeer.delete(peerId);
        }
      }

      if (strictMode && mismatches.length > 0) {
        const strictError = new Error("Cluster configuration mismatch detected during startup");
        strictError.code = "CLUSTER_CONFIG_MISMATCH";
        strictError.details = {
          mismatches,
          expected: expectedClusterConfig,
        };
        throw strictError;
      }

      const snapshot = buildSnapshot(peers, now);
      currentSnapshot = snapshot;

      const healthyNodeIds = snapshot.healthyNodes.map((node) => node.nodeId);
      for (const node of snapshot.healthyNodes) {
        leaderElection.recordHeartbeat(node.nodeId, node.lastHeartbeat || now);
      }

      const election = leaderElection.recompute({
        healthyNodeIds,
        timestamp: now,
      });
      if (election.changed && election.currentLeader) {
        metrics.increment("cluster.leader_elected");
      }

      evaluateShardRebalance(snapshot);
      publishClusterConfigGauges();
      publishNodeGauges(snapshot);

      return {
        ok: true,
        snapshot,
        election,
      };
    } finally {
      reconcileInFlight = false;
    }
  }

  function getSnapshot() {
    return currentSnapshot;
  }

  function resolveOwnerForSlug(rawSlug, options = {}) {
    const slug = normalizeSlug(rawSlug);
    const snapshot = options.snapshot && typeof options.snapshot === "object" ? options.snapshot : currentSnapshot;
    const excludedNodeIds = normalizeExcludeNodeIds(options.excludeNodeIds);

    if (!slug || !snapshot || !Array.isArray(snapshot.healthyNodes)) {
      return {
        shardId: null,
        ownerNodeId: null,
        ownerIsLocal: false,
        candidates: [],
        snapshotVersion: snapshot && Number.isFinite(Number(snapshot.version)) ? Number(snapshot.version) : 0,
      };
    }

    const shardId = computeShardId(slug, shardCount);
    const candidates = [];

    for (const node of snapshot.healthyNodes) {
      const nodeId = normalizeNodeId(node && node.nodeId);
      if (!nodeId || excludedNodeIds.has(nodeId)) {
        continue;
      }
      const capabilities = normalizeCapabilities(node && node.capabilities);
      if (!supportsSlug(capabilities, slug)) {
        continue;
      }
      candidates.push({
        nodeId,
        isLocal: nodeId === localNodeId,
        score: scoreNodeForShard(shardId, nodeId),
      });
    }

    candidates.sort((left, right) => {
      if (left.score === right.score) {
        return left.nodeId.localeCompare(right.nodeId);
      }
      return left.score > right.score ? -1 : 1;
    });

    const normalizedCandidates = candidates.map((candidate) => ({
      nodeId: candidate.nodeId,
      isLocal: candidate.isLocal,
      scoreHex: candidate.score.toString(16),
    }));

    return {
      shardId,
      ownerNodeId: normalizedCandidates.length > 0 ? normalizedCandidates[0].nodeId : null,
      ownerIsLocal: normalizedCandidates.length > 0 ? normalizedCandidates[0].isLocal : false,
      candidates: normalizedCandidates,
      snapshotVersion: Number.isFinite(Number(snapshot.version)) ? Number(snapshot.version) : 0,
    };
  }

  function getPeerForNode(rawNodeId) {
    const nodeId = normalizeNodeId(rawNodeId);
    if (!nodeId || nodeId === localNodeId) {
      return null;
    }
    const peer = peerRegistry.getPeer(nodeId);
    if (!peer || typeof peer !== "object") {
      return null;
    }
    const authToken = typeof peer.authToken === "string" ? peer.authToken.trim() : "";
    if (!authToken) {
      return null;
    }
    return peer;
  }

  function markNodeDown(rawNodeId, timestamp = Date.now()) {
    const nodeId = normalizeNodeId(rawNodeId);
    if (!nodeId || nodeId === localNodeId) {
      return false;
    }
    return peerRegistry.updatePeerHealth(nodeId, {
      status: STATUS_DOWN,
      lastHeartbeat: Number.isFinite(Number(timestamp)) ? Math.max(0, Number(timestamp)) : Date.now(),
    });
  }

  async function start() {
    if (running) {
      return {
        ok: true,
        started: false,
        snapshotVersion: currentSnapshot.version,
      };
    }

    running = true;
    federationHeartbeat.stop();
    try {
      await reconcile({ strictMode: true });
    } catch (error) {
      running = false;
      throw error;
    }

    timer = setInterval(() => {
      reconcile({ strictMode: false }).catch(() => {});
    }, heartbeatIntervalMs);
    if (timer && typeof timer.unref === "function") {
      timer.unref();
    }

    return {
      ok: true,
      started: true,
      snapshotVersion: currentSnapshot.version,
    };
  }

  function stop() {
    running = false;
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
    federationHeartbeat.stop();
    return {
      ok: true,
      stopped: true,
    };
  }

  async function runOnce() {
    return reconcile({ strictMode: false });
  }

  function isRunning() {
    return running;
  }

  function isLeader() {
    return leaderElection.isLeader();
  }

  function getCurrentLeader() {
    return leaderElection.getCurrentLeader();
  }

  function onLeadershipChange(callback) {
    return leaderElection.onLeadershipChange(callback);
  }

  return {
    nodeId: localNodeId,
    shardCount,
    heartbeatIntervalMs,
    leaderTimeoutMs,
    start,
    stop,
    runOnce,
    isRunning,
    isLeader,
    getCurrentLeader,
    onLeadershipChange,
    getSnapshot,
    resolveOwnerForSlug,
    getPeerForNode,
    markNodeDown,
  };
}

module.exports = {
  createClusterManager,
};
