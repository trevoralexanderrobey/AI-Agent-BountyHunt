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

function sanitizePeer(peerId, entry, includeSecret = false) {
  const base = {
    peerId,
    url: entry.url,
    status: entry.status,
    capabilities: [...entry.capabilities],
    lastLatencyMs: entry.lastLatencyMs,
    lastHeartbeat: entry.lastHeartbeat,
  };

  if (includeSecret) {
    base.authToken = entry.authToken;
  }

  return base;
}

function createPeerRegistry() {
  const peers = new Map();

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
    };

    peers.set(peerId, entry);
    return sanitizePeer(peerId, entry, false);
  }

  function removePeer(rawPeerId) {
    const peerId = normalizePeerId(rawPeerId);
    if (!peerId) {
      return false;
    }
    return peers.delete(peerId);
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
      entry.status = health.status;
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

    peers.set(peerId, entry);
    return true;
  }

  return {
    registerPeer,
    removePeer,
    listPeers,
    getPeer,
    getHealthyPeersForSlug,
    updatePeerHealth,
    STATUS_UP,
    STATUS_DOWN,
  };
}

module.exports = {
  createPeerRegistry,
  STATUS_UP,
  STATUS_DOWN,
};
