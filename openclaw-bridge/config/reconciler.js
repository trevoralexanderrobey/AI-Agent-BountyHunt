const crypto = require("node:crypto");

function normalizeString(value) {
  return typeof value === "string" ? value.trim() : "";
}

function isPlainObject(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function parsePositiveInteger(value, fallback) {
  const parsed = Number.parseInt(String(value ?? "").trim(), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
}

function stableStringify(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }

  const keys = Object.keys(value).sort((a, b) => a.localeCompare(b));
  const parts = keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`);
  return `{${parts.join(",")}}`;
}

function sha256(value) {
  return crypto.createHash("sha256").update(String(value || ""), "utf8").digest("hex");
}

function normalizeAllowedHashes(raw) {
  if (!isPlainObject(raw)) {
    return {};
  }

  const output = {};
  for (const [version, hashes] of Object.entries(raw)) {
    const normalizedVersion = normalizeString(version);
    if (!normalizedVersion) {
      continue;
    }

    const list = Array.isArray(hashes)
      ? hashes
          .map((item) => normalizeString(item).toLowerCase())
          .filter((item) => /^[a-f0-9]{64}$/.test(item))
      : [];

    if (list.length > 0) {
      output[normalizedVersion] = Array.from(new Set(list)).sort((a, b) => a.localeCompare(b));
    }
  }

  return output;
}

function toExecutionFingerprint(execution = {}) {
  return {
    executionMode: normalizeString(execution.executionMode).toLowerCase() || "host",
    containerRuntimeEnabled: execution.containerRuntimeEnabled === true,
    backend: normalizeString(execution.backend).toLowerCase() || "mock",
    allowedImageRegistries: Array.isArray(execution.allowedImageRegistries)
      ? execution.allowedImageRegistries.map((item) => normalizeString(item)).filter(Boolean).sort((a, b) => a.localeCompare(b))
      : [],
    requireSignatureVerificationInProduction: execution.requireSignatureVerificationInProduction !== false,
    externalNetworkName: normalizeString(execution.externalNetworkName),
    internalNetworkName: normalizeString(execution.internalNetworkName),
    nonRootUser: normalizeString(execution.nonRootUser),
    maxConcurrentContainersPerNode: parsePositiveInteger(execution.maxConcurrentContainersPerNode, 0),
    nodeMemoryHardCapMb: parsePositiveInteger(execution.nodeMemoryHardCapMb, 0),
    nodeCpuHardCapShares: parsePositiveInteger(execution.nodeCpuHardCapShares, 0),
    toolConcurrencyLimits: isPlainObject(execution.toolConcurrencyLimits) ? execution.toolConcurrencyLimits : {},
    resourcePolicies: isPlainObject(execution.resourcePolicies) ? execution.resourcePolicies : {},
    sandboxPolicies: isPlainObject(execution.sandboxPolicies) ? execution.sandboxPolicies : {},
    egressPolicies: isPlainObject(execution.egressPolicies) ? execution.egressPolicies : {},
    imagePolicies: isPlainObject(execution.imagePolicies) ? execution.imagePolicies : {},
    images: isPlainObject(execution.images) ? execution.images : {},
  };
}

function createExecutionConfigReconciler(options = {}) {
  const production = options.production === true;
  const nodeId = normalizeString(options.nodeId) || normalizeString(process.env.SUPERVISOR_NODE_ID) || "node-unknown";

  const execution = isPlainObject(options.execution) ? options.execution : {};
  const configVersion = normalizeString(execution.configVersion);
  const expectedExecutionConfigVersion = normalizeString(execution.expectedExecutionConfigVersion);
  const rollingUpgradeWindowMinutes = parsePositiveInteger(execution.rollingUpgradeWindowMinutes, 0);
  const rolloutWindowStartedAt = Date.parse(normalizeString(execution.rolloutWindowStartedAt));
  const allowedConfigHashesByVersion = normalizeAllowedHashes(execution.allowedConfigHashesByVersion);

  const fingerprint = toExecutionFingerprint(execution);
  const executionConfigHash = sha256(stableStringify(fingerprint));

  let lastSummary = {
    ok: true,
    status: "not_evaluated",
    criticalMismatches: [],
    warnings: [],
  };

  function localMetadata() {
    return {
      nodeId,
      executionConfigHash,
      executionConfigVersion: configVersion,
      expectedExecutionConfigVersion,
      rollingUpgradeWindowMinutes,
      rolloutWindowStartedAt: Number.isFinite(rolloutWindowStartedAt) ? rolloutWindowStartedAt : 0,
    };
  }

  function isWithinRollingWindow(now) {
    if (!Number.isFinite(rolloutWindowStartedAt) || rollingUpgradeWindowMinutes <= 0) {
      return false;
    }

    return now - rolloutWindowStartedAt <= rollingUpgradeWindowMinutes * 60 * 1000;
  }

  function isKnownVersionHash(version, hash) {
    const normalizedVersion = normalizeString(version);
    const normalizedHash = normalizeString(hash).toLowerCase();
    if (!normalizedVersion || !/^[a-f0-9]{64}$/.test(normalizedHash)) {
      return false;
    }

    const list = allowedConfigHashesByVersion[normalizedVersion];
    if (!Array.isArray(list) || list.length === 0) {
      return false;
    }

    return list.includes(normalizedHash);
  }

  function evaluate(peers = []) {
    const now = Date.now();
    const criticalMismatches = [];
    const warnings = [];
    const withinWindow = isWithinRollingWindow(now);

    if (production && normalizeString(expectedExecutionConfigVersion).length === 0) {
      criticalMismatches.push({
        peerId: "local",
        reason: "expected_execution_config_version_missing",
      });
    }
    if (production && normalizeString(expectedExecutionConfigVersion).length > 0 && configVersion !== expectedExecutionConfigVersion) {
      const localKnown = isKnownVersionHash(configVersion, executionConfigHash);
      const mismatch = {
        peerId: "local",
        reason: "local_execution_version_unexpected",
        localVersion: configVersion,
        expectedExecutionConfigVersion,
        localHash: executionConfigHash,
        withinWindow,
        localKnown,
      };
      if (withinWindow && localKnown) {
        warnings.push(mismatch);
      } else {
        criticalMismatches.push(mismatch);
      }
    }

    const healthyPeers = Array.isArray(peers) ? peers.filter((peer) => String(peer && peer.status || "").toUpperCase() === "UP") : [];

    for (const peer of healthyPeers) {
      const peerId = normalizeString(peer.peerId) || "unknown-peer";
      const peerHash = normalizeString(peer.executionConfigHash).toLowerCase();
      const peerVersion = normalizeString(peer.executionConfigVersion);

      if (!peerHash || !peerVersion) {
        if (production) {
          criticalMismatches.push({
            peerId,
            reason: "peer_execution_metadata_missing",
          });
        } else {
          warnings.push({
            peerId,
            reason: "peer_execution_metadata_missing",
          });
        }
        continue;
      }

      if (peerHash === executionConfigHash) {
        continue;
      }

      const versionMismatch = peerVersion !== configVersion;
      if (!versionMismatch) {
        const mismatch = {
          peerId,
          reason: "execution_hash_mismatch_same_version",
          peerVersion,
          peerHash,
          localVersion: configVersion,
          localHash: executionConfigHash,
        };
        if (production) {
          criticalMismatches.push(mismatch);
        } else {
          warnings.push(mismatch);
        }
        continue;
      }

      const localKnown = isKnownVersionHash(configVersion, executionConfigHash);
      const peerKnown = isKnownVersionHash(peerVersion, peerHash);
      if (withinWindow && localKnown && peerKnown) {
        warnings.push({
          peerId,
          reason: "rolling_window_version_mismatch_allowed",
          peerVersion,
          peerHash,
          localVersion: configVersion,
          localHash: executionConfigHash,
        });
        continue;
      }

      const mismatch = {
        peerId,
        reason: "execution_hash_version_mismatch_blocked",
        peerVersion,
        peerHash,
        localVersion: configVersion,
        localHash: executionConfigHash,
        withinWindow,
        localKnown,
        peerKnown,
      };

      if (production) {
        criticalMismatches.push(mismatch);
      } else {
        warnings.push(mismatch);
      }
    }

    const ok = criticalMismatches.length === 0;
    const status = ok ? "aligned" : "mismatch";

    lastSummary = {
      ok,
      status,
      criticalMismatches,
      warnings,
      timestamp: now,
    };

    return lastSummary;
  }

  function assertExecutionAllowed(peers = []) {
    const summary = evaluate(peers);
    if (summary.ok) {
      return summary;
    }

    const error = new Error("Execution config mismatch detected");
    error.code = "EXECUTION_CONFIG_MISMATCH";
    error.details = summary;
    throw error;
  }

  function getLastSummary() {
    return {
      ...lastSummary,
      criticalMismatches: Array.isArray(lastSummary.criticalMismatches) ? lastSummary.criticalMismatches.slice() : [],
      warnings: Array.isArray(lastSummary.warnings) ? lastSummary.warnings.slice() : [],
    };
  }

  return {
    localMetadata,
    evaluate,
    assertExecutionAllowed,
    getLastSummary,
  };
}

module.exports = {
  createExecutionConfigReconciler,
  toExecutionFingerprint,
};
