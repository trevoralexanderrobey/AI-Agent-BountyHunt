const crypto = require("node:crypto");
const http = require("node:http");
const https = require("node:https");

const { STATUS_DOWN, STATUS_UP } = require("../federation/peer-registry.js");
const { createVersionGuard } = require("../deployment/version-guard.js");
const { createLeaderElection } = require("./leader-election.js");
const { createPartitionDetector } = require("./partition-detector.js");

const DEFAULT_SHARD_COUNT = 16;
const DEFAULT_HEARTBEAT_INTERVAL_MS = 5000;
const DEFAULT_LEADER_TIMEOUT_MS = 15000;
const DEFAULT_CONVERGENCE_WINDOW_MS = 10000;
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

function extractNodeMetadataGauge(gauges, peerId) {
  if (!Array.isArray(gauges)) {
    return null;
  }

  for (const gauge of gauges) {
    if (!gauge || typeof gauge !== "object" || gauge.name !== "cluster.node_metadata") {
      continue;
    }

    const labels = gauge.labels && typeof gauge.labels === "object" ? gauge.labels : {};
    const labelNodeId = normalizeNodeId(labels.node_id);
    if (peerId && labelNodeId && labelNodeId !== peerId) {
      continue;
    }

    const softwareVersion = typeof labels.software_version === "string" ? labels.software_version.trim() : "";
    const configHash = typeof labels.config_hash === "string" ? labels.config_hash.trim() : "";
    if (!softwareVersion || !configHash) {
      continue;
    }

    return {
      nodeId: labelNodeId,
      softwareVersion,
      configHash,
    };
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
          const nodeMetadata = extractNodeMetadataGauge(gauges, peerId);

          if (shardCount === null || leaderTimeoutMs === null || heartbeatIntervalMs === null || !nodeMetadata) {
            resolve({
              ok: false,
              reason: "missing_cluster_metadata_gauges",
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
            metadata: nodeMetadata,
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

function membershipKey(nodeIds) {
  return Array.from(new Set((Array.isArray(nodeIds) ? nodeIds : []).map((id) => normalizeNodeId(id)).filter(Boolean)))
    .sort((left, right) => left.localeCompare(right))
    .join(",");
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
  const convergenceWindowMs = parsePositiveInt(options.convergenceWindowMs, DEFAULT_CONVERGENCE_WINDOW_MS);
  const metricsFetchTimeoutMs = parsePositiveInt(options.metricsFetchTimeoutMs, DEFAULT_METRICS_FETCH_TIMEOUT_MS);
  const localSoftwareVersion =
    typeof options.softwareVersion === "string" && options.softwareVersion.trim() ? options.softwareVersion.trim() : "0.0.0";
  const localConfigHash = typeof options.configHash === "string" ? options.configHash.trim() : "unknown";

  const metrics = createSafeMetrics(options.metrics);
  const localCapabilities = normalizeCapabilities(options.localCapabilities);
  const versionGuard = createVersionGuard();
  const leaderElection = createLeaderElection({
    localNodeId,
    leaderTimeoutMs,
  });
  const partitionDetector = createPartitionDetector({
    localNodeId,
  });

  const expectedClusterConfig = {
    shardCount,
    heartbeatIntervalMs,
    leaderTimeoutMs,
  };

  let running = false;
  let reconcileInFlight = false;
  let timer = null;

  let observedSnapshotVersion = 0;
  let stableSnapshotVersion = 0;

  let hasShardBaseline = false;
  let previousMembershipKey = "";
  let previousAssignmentDigest = "";
  let previousNonSelfHealthyCount = 0;

  let pendingMembershipKey = "";
  let pendingFirstSeenAt = 0;
  let pendingStableTicks = 0;
  let lastObservedMembershipKey = "";
  let freezeActive = false;
  let observedPopulation = 0;
  let compatiblePopulation = 0;

  const configMismatchStateByPeer = new Map();
  const configMismatchReasonByPeer = new Map();
  const versionMismatchStateByPeer = new Map();
  const versionMismatchReasonByPeer = new Map();
  const peerMetadataByPeer = new Map();

  let observedSnapshot = createSnapshot({
    version: 0,
    createdAt: 0,
    nodes: [],
  });

  let stableSnapshot = createSnapshot({
    version: 0,
    createdAt: 0,
    nodes: [],
  });

  let lastPartitionEvaluation = {
    partitioned: false,
    entered: false,
    recovered: false,
    reason: "steady",
    timestamp: 0,
    stableMembershipKey: "",
    stableSize: 0,
    observedMembershipKey: "",
    observedSize: 0,
    partitionEnteredAt: 0,
    partitionEntryBaselineSize: 0,
    recoveryMembershipKey: "",
    recoveryStableTicks: 0,
    recoveryThreshold: 0,
    thresholdMet: false,
    lastStableMembershipKey: "",
    lastStableMembershipSize: 0,
  };

  let publishedSnapshot = buildPublishedSnapshot({
    convergenceDelayActive: 0,
    leaderComputation: null,
  });

  function createSnapshot({ version, createdAt, nodes }) {
    const normalizedNodes = Array.isArray(nodes)
      ? nodes
          .map((node) => {
            const nodeId = normalizeNodeId(node && node.nodeId);
            if (!nodeId) {
              return null;
            }
            const status = node && node.status === STATUS_UP ? STATUS_UP : STATUS_DOWN;
            const healthy = Boolean(node && node.healthy === true) || status === STATUS_UP;
            return {
              nodeId,
              isLocal: Boolean(node && node.isLocal),
              healthy,
              status: healthy ? STATUS_UP : STATUS_DOWN,
              capabilities: normalizeCapabilities(node && node.capabilities),
              softwareVersion: node && typeof node.softwareVersion === "string" ? node.softwareVersion.trim() : "",
              configHash: node && typeof node.configHash === "string" ? node.configHash.trim() : "",
              configCompatible: node && node.configCompatible === false ? false : true,
              configMismatch: Boolean(node && node.configMismatch),
              configMismatchReason:
                node && typeof node.configMismatchReason === "string" ? node.configMismatchReason : "",
              versionCompatible: node && node.versionCompatible === false ? false : true,
              versionMismatch: Boolean(node && node.versionMismatch),
              versionMismatchReason:
                node && typeof node.versionMismatchReason === "string" ? node.versionMismatchReason : "",
              lastHeartbeat: Number.isFinite(Number(node && node.lastHeartbeat)) ? Math.max(0, Number(node.lastHeartbeat)) : 0,
              lastLatencyMs: Number.isFinite(Number(node && node.lastLatencyMs)) ? Math.max(0, Number(node.lastLatencyMs)) : 0,
            };
          })
          .filter(Boolean)
          .sort((left, right) => left.nodeId.localeCompare(right.nodeId))
      : [];

    const healthyNodes = normalizedNodes
      .filter((node) => node.healthy)
      .map((node) => ({
        nodeId: node.nodeId,
        isLocal: node.isLocal,
        capabilities: node.capabilities.slice(),
        softwareVersion: node.softwareVersion,
        configHash: node.configHash,
        lastHeartbeat: node.lastHeartbeat,
        lastLatencyMs: node.lastLatencyMs,
      }));

    const capabilities = normalizedNodes.map((node) => ({
      nodeId: node.nodeId,
      capabilities: node.capabilities.slice(),
    }));

    const configCompatibility = {
      allCompatible: normalizedNodes.every((node) => node.configCompatible),
      mismatchedNodeIds: normalizedNodes.filter((node) => node.configMismatch).map((node) => node.nodeId),
    };

    const versionCompatibility = {
      allCompatible: normalizedNodes.every((node) => node.versionCompatible),
      mismatchedNodeIds: normalizedNodes.filter((node) => node.versionMismatch).map((node) => node.nodeId),
    };

    return deepFreeze({
      version,
      createdAt,
      clusterConfig: {
        shardCount,
        heartbeatIntervalMs,
        leaderTimeoutMs,
        convergenceWindowMs,
      },
      healthyNodes,
      nodes: normalizedNodes,
      capabilities,
      configCompatibility,
      versionCompatibility,
    });
  }

  function buildPublishedSnapshot({ convergenceDelayActive, leaderComputation }) {
    const partitioned = partitionDetector.isPartitioned();

    return deepFreeze({
      ...stableSnapshot,
      stableSnapshotVersion: stableSnapshot.version,
      observedSnapshotVersion: observedSnapshot.version,
      observedHealthyMembershipKey: lastObservedMembershipKey,
      partition: {
        partitioned,
        enteredAt: Number.isFinite(Number(lastPartitionEvaluation.partitionEnteredAt))
          ? Number(lastPartitionEvaluation.partitionEnteredAt)
          : 0,
        entryBaselineSize: Number.isFinite(Number(lastPartitionEvaluation.partitionEntryBaselineSize))
          ? Number(lastPartitionEvaluation.partitionEntryBaselineSize)
          : 0,
        recoveryStableTicks: Number.isFinite(Number(lastPartitionEvaluation.recoveryStableTicks))
          ? Number(lastPartitionEvaluation.recoveryStableTicks)
          : 0,
        recoveryThreshold: Number.isFinite(Number(lastPartitionEvaluation.recoveryThreshold))
          ? Number(lastPartitionEvaluation.recoveryThreshold)
          : 0,
      },
      convergence: {
        windowMs: convergenceWindowMs,
        delayActive: convergenceDelayActive ? 1 : 0,
        pendingMembershipKey,
        pendingStableTicks,
        pendingSince: pendingFirstSeenAt,
      },
      leader: {
        current: leaderElection.getCurrentLeader(),
        computedFromStableSnapshot: Boolean(leaderComputation && leaderComputation.computedFromStableSnapshot),
        transitionsSuppressed: Boolean(leaderComputation && leaderComputation.transitionsSuppressed),
        candidate:
          leaderComputation && typeof leaderComputation.candidate === "string" && leaderComputation.candidate
            ? leaderComputation.candidate
            : null,
      },
      upgradeCompatibility: {
        localSoftwareVersion,
        localConfigHash,
        observedPopulation,
        compatiblePopulation,
        freezeActive: freezeActive ? 1 : 0,
      },
    });
  }

  function publishClusterConfigGauges() {
    metrics.gauge("cluster.shard_count", shardCount);
    metrics.gauge("cluster.leader_timeout_ms", leaderTimeoutMs);
    metrics.gauge("cluster.heartbeat_interval_ms", heartbeatIntervalMs);
  }

  function publishContainmentGauges({ partitioned, convergenceDelayActive }) {
    metrics.gauge("cluster.partition_state", partitioned ? 1 : 0);
    metrics.gauge("cluster.convergence_delay_active", convergenceDelayActive ? 1 : 0);
  }

  function supportsSlug(capabilities, slug) {
    if (!Array.isArray(capabilities) || capabilities.length === 0) {
      return false;
    }
    return capabilities.includes("*") || capabilities.includes(slug);
  }

  function buildNodesFromPeers(peers, now) {
    const nodes = [];

    nodes.push({
      nodeId: localNodeId,
      isLocal: true,
      healthy: true,
      status: STATUS_UP,
      capabilities: localCapabilities.slice(),
      softwareVersion: localSoftwareVersion,
      configHash: localConfigHash,
      configCompatible: true,
      configMismatch: false,
      configMismatchReason: "",
      versionCompatible: true,
      versionMismatch: false,
      versionMismatchReason: "",
      lastHeartbeat: now,
      lastLatencyMs: 0,
    });

    for (const peer of peers) {
      const peerId = normalizeNodeId(peer && peer.peerId);
      if (!peerId || peerId === localNodeId) {
        continue;
      }

      const configMismatch = configMismatchStateByPeer.get(peerId) === true;
      const versionMismatch = versionMismatchStateByPeer.get(peerId) === true;
      const mismatch = configMismatch || versionMismatch;
      const effectiveStatus = mismatch ? STATUS_DOWN : peer.status === STATUS_UP ? STATUS_UP : STATUS_DOWN;
      const peerMetadata = peerMetadataByPeer.get(peerId);

      nodes.push({
        nodeId: peerId,
        isLocal: false,
        healthy: effectiveStatus === STATUS_UP,
        status: effectiveStatus,
        capabilities: normalizeCapabilities(peer.capabilities),
        softwareVersion: peerMetadata && typeof peerMetadata.softwareVersion === "string" ? peerMetadata.softwareVersion : "",
        configHash: peerMetadata && typeof peerMetadata.configHash === "string" ? peerMetadata.configHash : "",
        configCompatible: !configMismatch,
        configMismatch,
        configMismatchReason: configMismatch ? configMismatchReasonByPeer.get(peerId) || "cluster_config_mismatch" : "",
        versionCompatible: !versionMismatch,
        versionMismatch,
        versionMismatchReason: versionMismatch ? versionMismatchReasonByPeer.get(peerId) || "cluster_version_mismatch" : "",
        lastHeartbeat: Number.isFinite(Number(peer.lastHeartbeat)) ? Math.max(0, Number(peer.lastHeartbeat)) : 0,
        lastLatencyMs: Number.isFinite(Number(peer.lastLatencyMs)) ? Math.max(0, Number(peer.lastLatencyMs)) : 0,
      });
    }

    return nodes.sort((left, right) => left.nodeId.localeCompare(right.nodeId));
  }

  function snapshotMembershipKey(snapshot) {
    if (!snapshot || !Array.isArray(snapshot.healthyNodes)) {
      return "";
    }
    return membershipKey(snapshot.healthyNodes.map((node) => node && node.nodeId));
  }

  function resetPendingPromotion() {
    pendingMembershipKey = "";
    pendingFirstSeenAt = 0;
    pendingStableTicks = 0;
  }

  function promoteObservedToStable(now) {
    stableSnapshotVersion += 1;
    stableSnapshot = createSnapshot({
      version: stableSnapshotVersion,
      createdAt: now,
      nodes: observedSnapshot.nodes,
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

  function computeStableLeaderCandidate() {
    const stableHealthyNodeIds = stableSnapshot.healthyNodes
      .map((node) => normalizeNodeId(node && node.nodeId))
      .filter(Boolean)
      .sort((left, right) => left.localeCompare(right));

    return stableHealthyNodeIds.length > 0 ? stableHealthyNodeIds[0] : null;
  }

  function recomputeLeaderFromStable(options = {}) {
    const suppressTransitions = Boolean(options.suppressTransitions);
    const stableHealthyNodeIds = stableSnapshot.healthyNodes
      .map((node) => normalizeNodeId(node && node.nodeId))
      .filter(Boolean)
      .sort((left, right) => left.localeCompare(right));

    if (suppressTransitions) {
      return {
        computedFromStableSnapshot: true,
        transitionsSuppressed: true,
        candidate: computeStableLeaderCandidate(),
        changed: false,
      };
    }

    const now = Date.now();
    for (const node of stableSnapshot.healthyNodes) {
      leaderElection.recordHeartbeat(node.nodeId, node.lastHeartbeat || now);
    }

    const election = leaderElection.recompute({
      healthyNodeIds: stableHealthyNodeIds,
      timestamp: now,
    });

    if (election.changed && election.currentLeader) {
      metrics.increment("cluster.leader_elected");
    }

    return {
      ...election,
      computedFromStableSnapshot: true,
      transitionsSuppressed: false,
      candidate: election.currentLeader,
    };
  }

  async function validatePeerClusterConfig(peer) {
    const peerId = normalizeNodeId(peer && peer.peerId);
    if (!peerId || peerId === localNodeId) {
      return {
        peerId,
        configMismatch: false,
        versionMismatch: false,
        startupFatal: false,
        metadata: null,
      };
    }

    if (peer.status !== STATUS_UP) {
      return {
        peerId,
        configMismatch: false,
        versionMismatch: false,
        startupFatal: false,
        metadata: null,
      };
    }

    const fullPeer = peerRegistry.getPeer(peerId);
    const fetched = await fetchPeerClusterConfig(fullPeer, metricsFetchTimeoutMs);
    if (!fetched.ok) {
      return {
        peerId,
        configMismatch: true,
        configReason: fetched.reason || "cluster_config_unavailable",
        versionMismatch: false,
        startupFatal: true,
        metadata: null,
      };
    }

    const remoteConfig = fetched.config || {};
    const metadata = fetched.metadata && typeof fetched.metadata === "object" ? fetched.metadata : null;
    const configMismatch =
      remoteConfig.shardCount !== expectedClusterConfig.shardCount ||
      remoteConfig.heartbeatIntervalMs !== expectedClusterConfig.heartbeatIntervalMs ||
      remoteConfig.leaderTimeoutMs !== expectedClusterConfig.leaderTimeoutMs;
    const identityMismatch = metadata && metadata.nodeId ? normalizeNodeId(metadata.nodeId) !== peerId : false;
    const versionEvaluation = versionGuard.evaluateCompatibility(
      localSoftwareVersion,
      metadata && typeof metadata.softwareVersion === "string" ? metadata.softwareVersion : "",
    );
    const versionMismatch = !versionEvaluation.compatible;

    return {
      peerId,
      configMismatch: configMismatch || identityMismatch,
      configReason: configMismatch
        ? "cluster_config_mismatch"
        : identityMismatch
        ? "cluster_node_id_mismatch"
        : "",
      versionMismatch,
      versionReason: versionMismatch ? versionEvaluation.reason : "",
      startupFatal: Boolean(configMismatch || identityMismatch || (versionMismatch && versionEvaluation.startupFatal)),
      metadata,
      details: {
        expected: expectedClusterConfig,
        received: remoteConfig,
        localVersion: localSoftwareVersion,
        remoteVersion: metadata && typeof metadata.softwareVersion === "string" ? metadata.softwareVersion : "",
      },
    };
  }

  function computeVersionFreezeState(snapshot) {
    if (!snapshot || !Array.isArray(snapshot.healthyNodes)) {
      return {
        observedPopulation: 0,
        compatiblePopulation: 0,
        freezeActive: false,
      };
    }

    let observedCount = 0;
    let compatibleCount = 0;
    for (const node of snapshot.healthyNodes) {
      observedCount += 1;
      const remoteVersion = node && typeof node.softwareVersion === "string" ? node.softwareVersion : "";
      if (versionGuard.isCoexistenceAllowed(localSoftwareVersion, remoteVersion)) {
        compatibleCount += 1;
      }
    }

    return {
      observedPopulation: observedCount,
      compatiblePopulation: compatibleCount,
      freezeActive: observedCount > 0 && compatibleCount <= observedCount / 2,
    };
  }

  function buildOwnerCandidates(snapshot, slug, excludedNodeIds) {
    const candidates = [];

    for (const node of snapshot.healthyNodes) {
      const nodeId = normalizeNodeId(node && node.nodeId);
      if (!nodeId || (excludedNodeIds && excludedNodeIds.has(nodeId))) {
        continue;
      }

      const capabilities = normalizeCapabilities(node && node.capabilities);
      if (!supportsSlug(capabilities, slug)) {
        continue;
      }

      const shardId = computeShardId(slug, shardCount);
      candidates.push({
        nodeId,
        isLocal: nodeId === localNodeId,
        score: scoreNodeForShard(shardId, nodeId),
      });
    }

    return candidates.sort((left, right) => {
      if (left.score === right.score) {
        return left.nodeId.localeCompare(right.nodeId);
      }
      return left.score > right.score ? -1 : 1;
    });
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
      const strictFailures = [];

      for (const peer of peers) {
        const peerId = normalizeNodeId(peer && peer.peerId);
        if (!peerId || peerId === localNodeId) {
          continue;
        }

        seenPeerIds.add(peerId);
        const validation = await validatePeerClusterConfig(peer);
        const nextConfigMismatch = Boolean(validation.configMismatch);
        const previousConfigMismatch = configMismatchStateByPeer.get(peerId) === true;
        const nextVersionMismatch = Boolean(validation.versionMismatch);
        const previousVersionMismatch = versionMismatchStateByPeer.get(peerId) === true;
        const nextAnyMismatch = nextConfigMismatch || nextVersionMismatch;

        if (validation.metadata && typeof validation.metadata === "object") {
          peerMetadataByPeer.set(peerId, {
            softwareVersion: validation.metadata.softwareVersion,
            configHash: validation.metadata.configHash,
          });
        } else if (!nextAnyMismatch) {
          peerMetadataByPeer.delete(peerId);
        }

        if (nextConfigMismatch) {
          const reason = validation.configReason || "cluster_config_mismatch";
          configMismatchReasonByPeer.set(peerId, reason);
          mismatches.push({
            peerId,
            type: "config",
            reason,
            details: validation.details || null,
          });
        } else {
          configMismatchReasonByPeer.delete(peerId);
        }

        if (nextVersionMismatch) {
          const reason = validation.versionReason || "cluster_version_mismatch";
          versionMismatchReasonByPeer.set(peerId, reason);
          mismatches.push({
            peerId,
            type: "version",
            reason,
            details: validation.details || null,
          });
        } else {
          versionMismatchReasonByPeer.delete(peerId);
        }

        if (nextAnyMismatch) {
          peerRegistry.updatePeerHealth(peerId, {
            status: STATUS_DOWN,
            lastHeartbeat: now,
          });
        }

        configMismatchStateByPeer.set(peerId, nextConfigMismatch);
        versionMismatchStateByPeer.set(peerId, nextVersionMismatch);

        if (nextConfigMismatch && !previousConfigMismatch) {
          metrics.increment("cluster.config_mismatch");
        }
        if (nextVersionMismatch && !previousVersionMismatch) {
          metrics.increment("cluster.version_mismatch");
        }

        if (validation.startupFatal) {
          strictFailures.push({
            peerId,
            type: nextConfigMismatch ? "config" : "version",
            reason: nextConfigMismatch ? validation.configReason || "cluster_config_mismatch" : validation.versionReason || "invalid_version",
            details: validation.details || null,
          });
        }
      }

      for (const peerId of Array.from(configMismatchStateByPeer.keys())) {
        if (!seenPeerIds.has(peerId)) {
          configMismatchStateByPeer.delete(peerId);
          configMismatchReasonByPeer.delete(peerId);
        }
      }
      for (const peerId of Array.from(versionMismatchStateByPeer.keys())) {
        if (!seenPeerIds.has(peerId)) {
          versionMismatchStateByPeer.delete(peerId);
          versionMismatchReasonByPeer.delete(peerId);
        }
      }
      for (const peerId of Array.from(peerMetadataByPeer.keys())) {
        if (!seenPeerIds.has(peerId)) {
          peerMetadataByPeer.delete(peerId);
        }
      }

      if (strictMode && strictFailures.length > 0) {
        const strictError = new Error("Cluster compatibility mismatch detected during startup");
        strictError.code = "CLUSTER_COMPATIBILITY_MISMATCH";
        strictError.details = {
          mismatches: strictFailures,
          allMismatches: mismatches,
          expected: expectedClusterConfig,
        };
        throw strictError;
      }

      observedSnapshotVersion += 1;
      observedSnapshot = createSnapshot({
        version: observedSnapshotVersion,
        createdAt: now,
        nodes: buildNodesFromPeers(peers, now),
      });
      const versionFreezeState = computeVersionFreezeState(observedSnapshot);
      observedPopulation = versionFreezeState.observedPopulation;
      compatiblePopulation = versionFreezeState.compatiblePopulation;
      freezeActive = versionFreezeState.freezeActive;

      lastObservedMembershipKey = snapshotMembershipKey(observedSnapshot);
      lastPartitionEvaluation = partitionDetector.evaluateMembership({
        stableHealthyNodeIds: stableSnapshot.healthyNodes.map((node) => node.nodeId),
        observedHealthyNodeIds: observedSnapshot.healthyNodes.map((node) => node.nodeId),
        now,
      });

      if (lastPartitionEvaluation.entered) {
        metrics.increment("cluster.partition_detected");
      }
      if (lastPartitionEvaluation.recovered) {
        metrics.increment("cluster.partition_recovered");
      }

      const partitioned = partitionDetector.isPartitioned();
      let convergenceDelayActive = 0;

      if (stableSnapshot.version === 0) {
        if (!partitioned && !freezeActive) {
          promoteObservedToStable(now);
          evaluateShardRebalance(stableSnapshot);
          resetPendingPromotion();
        } else {
          resetPendingPromotion();
          convergenceDelayActive = freezeActive ? 1 : 0;
        }
      } else if (partitioned || freezeActive) {
        resetPendingPromotion();
        convergenceDelayActive = freezeActive ? 1 : 0;
      } else {
        const stableMembershipKey = snapshotMembershipKey(stableSnapshot);
        const observedMembershipKey = snapshotMembershipKey(observedSnapshot);

        if (stableMembershipKey === observedMembershipKey) {
          resetPendingPromotion();
        } else {
          if (pendingMembershipKey !== observedMembershipKey) {
            pendingMembershipKey = observedMembershipKey;
            pendingFirstSeenAt = now;
            pendingStableTicks = 1;
          } else {
            pendingStableTicks += 1;
          }

          const windowElapsed = now - pendingFirstSeenAt >= convergenceWindowMs;
          const stableTicksMet = pendingStableTicks >= 2;
          if (windowElapsed && stableTicksMet) {
            promoteObservedToStable(now);
            evaluateShardRebalance(stableSnapshot);
            resetPendingPromotion();
          } else {
            convergenceDelayActive = 1;
          }
        }
      }

      const leaderComputation = recomputeLeaderFromStable({
        suppressTransitions: partitioned || freezeActive,
      });

      publishClusterConfigGauges();
      publishNodeGauges(observedSnapshot);
      publishContainmentGauges({
        partitioned,
        convergenceDelayActive,
      });

      publishedSnapshot = buildPublishedSnapshot({
        convergenceDelayActive,
        leaderComputation,
      });

      return {
        ok: true,
        snapshot: publishedSnapshot,
        stableSnapshot,
        observedSnapshot,
        partitioned,
        freezeActive,
        observedPopulation,
        compatiblePopulation,
        convergenceDelayActive,
        partition: lastPartitionEvaluation,
      };
    } finally {
      reconcileInFlight = false;
    }
  }

  function getSnapshot() {
    return publishedSnapshot;
  }

  function resolveOwnerForSlug(rawSlug, options = {}) {
    const slug = normalizeSlug(rawSlug);
    const partitioned = partitionDetector.isPartitioned();
    const routingFrozen = freezeActive === true;
    const requestedSnapshot = options.snapshot && typeof options.snapshot === "object" ? options.snapshot : publishedSnapshot;
    const snapshot = partitioned || routingFrozen ? stableSnapshot : requestedSnapshot;
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

    if (partitioned || routingFrozen) {
      const partitionCandidates = buildOwnerCandidates(snapshot, slug, new Set());
      if (partitionCandidates.length === 0) {
        return {
          shardId,
          ownerNodeId: null,
          ownerIsLocal: false,
          candidates: [],
          snapshotVersion: Number.isFinite(Number(snapshot.version)) ? Number(snapshot.version) : 0,
        };
      }

      const stableOwner = partitionCandidates[0];
      if (excludedNodeIds.has(stableOwner.nodeId)) {
        return {
          shardId,
          ownerNodeId: null,
          ownerIsLocal: false,
          candidates: [
            {
              nodeId: stableOwner.nodeId,
              isLocal: stableOwner.isLocal,
              scoreHex: stableOwner.score.toString(16),
            },
          ],
          snapshotVersion: Number.isFinite(Number(snapshot.version)) ? Number(snapshot.version) : 0,
        };
      }

      return {
        shardId,
        ownerNodeId: stableOwner.nodeId,
        ownerIsLocal: stableOwner.isLocal,
        candidates: [
          {
            nodeId: stableOwner.nodeId,
            isLocal: stableOwner.isLocal,
            scoreHex: stableOwner.score.toString(16),
          },
        ],
        snapshotVersion: Number.isFinite(Number(snapshot.version)) ? Number(snapshot.version) : 0,
      };
    }

    const candidates = buildOwnerCandidates(snapshot, slug, excludedNodeIds);
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

    if (partitionDetector.isPartitioned()) {
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
        snapshotVersion: stableSnapshot.version,
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
      snapshotVersion: stableSnapshot.version,
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

  function isPartitioned() {
    return partitionDetector.isPartitioned();
  }

  function onPartitionChange(callback) {
    return partitionDetector.onPartitionChange(callback);
  }

  return {
    nodeId: localNodeId,
    softwareVersion: localSoftwareVersion,
    configHash: localConfigHash,
    shardCount,
    heartbeatIntervalMs,
    leaderTimeoutMs,
    convergenceWindowMs,
    start,
    stop,
    runOnce,
    isRunning,
    isLeader,
    getCurrentLeader,
    onLeadershipChange,
    isPartitioned,
    onPartitionChange,
    getSnapshot,
    resolveOwnerForSlug,
    getPeerForNode,
    markNodeDown,
  };
}

module.exports = {
  createClusterManager,
};
