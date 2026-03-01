const STATUS_UP = "UP";
const STATUS_DOWN = "DOWN";

function isPlainObject(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function normalizePeerId(peerId) {
  return typeof peerId === "string" ? peerId.trim() : "";
}

function normalizeSlug(slug) {
  return typeof slug === "string" ? slug.trim().toLowerCase() : "";
}

function normalizeCapabilities(value) {
  if (!Array.isArray(value)) {
    return [];
  }
  const seen = new Set();
  for (const item of value) {
    if (typeof item !== "string") {
      continue;
    }
    const normalized = normalizeSlug(item);
    if (!normalized) {
      continue;
    }
    seen.add(normalized);
  }
  return Array.from(seen).sort((a, b) => a.localeCompare(b));
}

function normalizeUrl(value) {
  if (typeof value !== "string" || !value.trim()) {
    return "";
  }
  try {
    const parsed = new URL(value.trim());
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return "";
    }
    parsed.hash = "";
    parsed.search = "";
    let normalized = parsed.toString();
    if (normalized.endsWith("/")) {
      normalized = normalized.slice(0, -1);
    }
    return normalized;
  } catch {
    return "";
  }
}

function normalizeExecutionConfigHash(value) {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : "";
  if (!normalized) {
    return "";
  }
  return /^[a-f0-9]{64}$/.test(normalized) ? normalized : "";
}

function normalizeMetadataVersion(value) {
  return typeof value === "string" ? value.trim() : "";
}

function normalizePolicyVersion(value) {
  const parsed = Number.parseInt(String(value ?? "").trim(), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return 0;
  }
  return parsed;
}

function sanitizePeer(peerId, entry, includeSecret = false) {
  const base = {
    peerId,
    url: entry.url,
    status: entry.status,
    capabilities: [...entry.capabilities],
    lastLatencyMs: entry.lastLatencyMs,
    lastHeartbeat: entry.lastHeartbeat,
    executionConfigHash: entry.executionConfigHash,
    executionPolicyHash: entry.executionPolicyHash,
    secretManifestHash: entry.secretManifestHash,
    executionConfigVersion: entry.executionConfigVersion,
    executionPolicyVersion: entry.executionPolicyVersion,
    expectedExecutionConfigVersion: entry.expectedExecutionConfigVersion,
    nodeId: entry.nodeId,
  };

  if (includeSecret) {
    base.authToken = entry.authToken;
  }

  return base;
}

function createPeerRegistry(options = {}) {
  const peers = new Map();
  const onChange = options && typeof options.onChange === "function" ? options.onChange : null;

  function emitChange() {
    if (!onChange) {
      return;
    }
    try {
      onChange();
    } catch {}
  }

  function registerPeer(rawPeerId, config = {}) {
    const peerId = normalizePeerId(rawPeerId);
    if (!peerId) {
      throw new Error("peerId is required");
    }
    if (!isPlainObject(config)) {
      throw new Error("peer config must be an object");
    }

    const url = normalizeUrl(config.url);
    if (!url) {
      throw new Error("peer url must be a valid http/https URL");
    }

    const authToken = typeof config.authToken === "string" ? config.authToken.trim() : "";
    if (!authToken) {
      throw new Error("peer authToken is required");
    }

    const capabilities = normalizeCapabilities(config.capabilities);
    const status = config.status === STATUS_UP ? STATUS_UP : STATUS_DOWN;
    const lastLatencyMs = Number.isFinite(Number(config.lastLatencyMs)) ? Number(config.lastLatencyMs) : 0;
    const lastHeartbeat = Number.isFinite(Number(config.lastHeartbeat)) ? Number(config.lastHeartbeat) : 0;

    const entry = {
      url,
      authToken,
      status,
      capabilities,
      lastLatencyMs,
      lastHeartbeat,
      executionConfigHash: normalizeExecutionConfigHash(config.executionConfigHash),
      executionPolicyHash: normalizeExecutionConfigHash(config.executionPolicyHash),
      secretManifestHash: normalizeExecutionConfigHash(config.secretManifestHash),
      executionConfigVersion: normalizeMetadataVersion(config.executionConfigVersion),
      executionPolicyVersion: normalizePolicyVersion(config.executionPolicyVersion),
      expectedExecutionConfigVersion: normalizeMetadataVersion(config.expectedExecutionConfigVersion),
      nodeId: normalizeMetadataVersion(config.nodeId),
    };

    peers.set(peerId, entry);
    emitChange();
    return sanitizePeer(peerId, entry, false);
  }

  function removePeer(rawPeerId) {
    const peerId = normalizePeerId(rawPeerId);
    if (!peerId) {
      return false;
    }
    const removed = peers.delete(peerId);
    if (removed) {
      emitChange();
    }
    return removed;
  }

  function listPeers() {
    return Array.from(peers.entries())
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([peerId, entry]) => sanitizePeer(peerId, entry, false));
  }

  function getPeer(rawPeerId) {
    const peerId = normalizePeerId(rawPeerId);
    if (!peerId) {
      return null;
    }
    const entry = peers.get(peerId);
    if (!entry) {
      return null;
    }
    return sanitizePeer(peerId, entry, true);
  }

  function getHealthyPeersForSlug(rawSlug) {
    const slug = normalizeSlug(rawSlug);
    if (!slug) {
      return [];
    }

    return Array.from(peers.entries())
      .filter(([, entry]) => {
        if (entry.status !== STATUS_UP) {
          return false;
        }
        if (!Array.isArray(entry.capabilities) || entry.capabilities.length === 0) {
          return false;
        }
        return entry.capabilities.includes(slug) || entry.capabilities.includes("*");
      })
      .sort((a, b) => {
        const latencyA = Number.isFinite(Number(a[1].lastLatencyMs)) ? Number(a[1].lastLatencyMs) : Number.POSITIVE_INFINITY;
        const latencyB = Number.isFinite(Number(b[1].lastLatencyMs)) ? Number(b[1].lastLatencyMs) : Number.POSITIVE_INFINITY;
        if (latencyA !== latencyB) {
          return latencyA - latencyB;
        }
        return a[0].localeCompare(b[0]);
      })
      .map(([peerId, entry]) => sanitizePeer(peerId, entry, true));
  }

  function updatePeerHealth(rawPeerId, health = {}) {
    const peerId = normalizePeerId(rawPeerId);
    if (!peerId || !isPlainObject(health)) {
      return false;
    }

    const entry = peers.get(peerId);
    if (!entry) {
      return false;
    }

    if (health.status === STATUS_UP || health.status === STATUS_DOWN) {
      if (!entry.authToken && health.status === STATUS_UP) {
        entry.status = STATUS_DOWN;
      } else {
        entry.status = health.status;
      }
    }

    if (Number.isFinite(Number(health.lastLatencyMs)) && Number(health.lastLatencyMs) >= 0) {
      entry.lastLatencyMs = Number(health.lastLatencyMs);
    }

    if (Number.isFinite(Number(health.lastHeartbeat)) && Number(health.lastHeartbeat) >= 0) {
      entry.lastHeartbeat = Number(health.lastHeartbeat);
    }

    if (Array.isArray(health.capabilities)) {
      entry.capabilities = normalizeCapabilities(health.capabilities);
    }
    if (typeof health.executionConfigHash === "string") {
      entry.executionConfigHash = normalizeExecutionConfigHash(health.executionConfigHash);
    }
    if (typeof health.executionPolicyHash === "string") {
      entry.executionPolicyHash = normalizeExecutionConfigHash(health.executionPolicyHash);
    }
    if (typeof health.secretManifestHash === "string") {
      entry.secretManifestHash = normalizeExecutionConfigHash(health.secretManifestHash);
    }
    if (typeof health.executionConfigVersion === "string") {
      entry.executionConfigVersion = normalizeMetadataVersion(health.executionConfigVersion);
    }
    if (typeof health.executionPolicyVersion !== "undefined") {
      entry.executionPolicyVersion = normalizePolicyVersion(health.executionPolicyVersion);
    }
    if (typeof health.expectedExecutionConfigVersion === "string") {
      entry.expectedExecutionConfigVersion = normalizeMetadataVersion(health.expectedExecutionConfigVersion);
    }
    if (typeof health.nodeId === "string") {
      entry.nodeId = normalizeMetadataVersion(health.nodeId);
    }

    peers.set(peerId, entry);
    emitChange();
    return true;
  }

  function exportMetadata() {
    return Array.from(peers.entries())
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([peerId, entry]) => ({
        peerId,
        url: entry.url,
        status: entry.status,
        capabilities: [...entry.capabilities],
        lastLatencyMs: entry.lastLatencyMs,
        lastHeartbeat: entry.lastHeartbeat,
        executionConfigHash: entry.executionConfigHash,
        executionPolicyHash: entry.executionPolicyHash,
        secretManifestHash: entry.secretManifestHash,
        executionConfigVersion: entry.executionConfigVersion,
        executionPolicyVersion: entry.executionPolicyVersion,
        expectedExecutionConfigVersion: entry.expectedExecutionConfigVersion,
        nodeId: entry.nodeId,
      }));
  }

  function importMetadata(rawMetadata) {
    if (!Array.isArray(rawMetadata)) {
      return {
        applied: 0,
        created: 0,
        skipped: 0,
      };
    }

    let applied = 0;
    let created = 0;
    let skipped = 0;

    for (const item of rawMetadata) {
      if (!isPlainObject(item)) {
        skipped += 1;
        continue;
      }

      const peerId = normalizePeerId(item.peerId);
      const url = normalizeUrl(item.url);
      if (!peerId || !url) {
        skipped += 1;
        continue;
      }

      const existing = peers.get(peerId);
      const capabilities = normalizeCapabilities(item.capabilities);
      const lastLatencyMs = Number.isFinite(Number(item.lastLatencyMs)) ? Math.max(0, Number(item.lastLatencyMs)) : 0;
      const lastHeartbeat = Number.isFinite(Number(item.lastHeartbeat)) ? Math.max(0, Number(item.lastHeartbeat)) : 0;
      const status = item.status === STATUS_UP || item.status === STATUS_DOWN ? item.status : STATUS_DOWN;
      const executionConfigHash = normalizeExecutionConfigHash(item.executionConfigHash);
      const executionPolicyHash = normalizeExecutionConfigHash(item.executionPolicyHash);
      const secretManifestHash = normalizeExecutionConfigHash(item.secretManifestHash);
      const executionConfigVersion = normalizeMetadataVersion(item.executionConfigVersion);
      const executionPolicyVersion = normalizePolicyVersion(item.executionPolicyVersion);
      const expectedExecutionConfigVersion = normalizeMetadataVersion(item.expectedExecutionConfigVersion);
      const nodeId = normalizeMetadataVersion(item.nodeId);

      if (!existing) {
        peers.set(peerId, {
          url,
          authToken: "",
          status: STATUS_DOWN,
          capabilities,
          lastLatencyMs,
          lastHeartbeat,
          executionConfigHash,
          executionPolicyHash,
          secretManifestHash,
          executionConfigVersion,
          executionPolicyVersion,
          expectedExecutionConfigVersion,
          nodeId,
        });
        created += 1;
        continue;
      }

      existing.url = url;
      existing.capabilities = capabilities;
      existing.lastLatencyMs = lastLatencyMs;
      existing.lastHeartbeat = lastHeartbeat;
      existing.executionConfigHash = executionConfigHash;
      existing.executionPolicyHash = executionPolicyHash;
      existing.secretManifestHash = secretManifestHash;
      existing.executionConfigVersion = executionConfigVersion;
      existing.executionPolicyVersion = executionPolicyVersion;
      existing.expectedExecutionConfigVersion = expectedExecutionConfigVersion;
      existing.nodeId = nodeId;
      if (existing.authToken) {
        existing.status = status;
      } else {
        existing.status = STATUS_DOWN;
      }
      peers.set(peerId, existing);
      applied += 1;
    }

    if (applied > 0 || created > 0) {
      emitChange();
    }

    return {
      applied,
      created,
      skipped,
    };
  }

  return {
    registerPeer,
    removePeer,
    listPeers,
    getPeer,
    getHealthyPeersForSlug,
    updatePeerHealth,
    exportMetadata,
    importMetadata,
    STATUS_UP,
    STATUS_DOWN,
  };
}

module.exports = {
  createPeerRegistry,
  STATUS_UP,
  STATUS_DOWN,
};
