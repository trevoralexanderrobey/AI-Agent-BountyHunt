function normalizeString(value) {
  return typeof value === "string" ? value.trim() : "";
}

function parseBoolean(value, fallback = false) {
  if (typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    return value !== 0;
  }
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (normalized === "true" || normalized === "1" || normalized === "yes") {
      return true;
    }
    if (normalized === "false" || normalized === "0" || normalized === "no") {
      return false;
    }
  }
  return fallback;
}

function parsePositiveInteger(value, fallback = 0) {
  const parsed = Number.parseInt(String(value ?? "").trim(), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
}

function deepFreeze(value) {
  if (!value || typeof value !== "object") {
    return value;
  }
  Object.freeze(value);
  for (const key of Object.keys(value)) {
    const child = value[key];
    if (child && typeof child === "object" && !Object.isFrozen(child)) {
      deepFreeze(child);
    }
  }
  return value;
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

function createNoopAuditLogger() {
  return {
    log: () => {},
  };
}

function createSafeAuditLogger(rawLogger) {
  const source = rawLogger && typeof rawLogger === "object" ? rawLogger : createNoopAuditLogger();
  return {
    log: (...args) => {
      try {
        if (typeof source.log === "function") {
          source.log(...args);
        }
      } catch {}
    },
  };
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function createPolicyRuntime(options = {}) {
  const production = parseBoolean(options.production, normalizeString(process.env.NODE_ENV).toLowerCase() === "production");
  const nodeId = normalizeString(options.nodeId) || normalizeString(process.env.SUPERVISOR_NODE_ID) || "node-unknown";
  const metrics = createSafeMetrics(options.metrics);
  const auditLogger = createSafeAuditLogger(options.auditLogger || options.logger);

  let activeBundle = null;
  let lastSummary = {
    ok: true,
    status: "not_evaluated",
    criticalMismatches: [],
    warnings: [],
    timestamp: Date.now(),
  };

  function makePolicyError(code, message, details = {}) {
    const error = new Error(String(message || "Execution policy mismatch detected"));
    error.code = String(code || "EXECUTION_CONFIG_MISMATCH");
    error.details = details;
    return error;
  }

  function getUpgradeWindowMs(policy) {
    const minutes = parsePositiveInteger(
      policy && policy.policy && policy.policy.allowedUpgradeWindowMinutes,
      0,
    );
    return minutes <= 0 ? 0 : minutes * 60 * 1000;
  }

  function allowDowngrade(newPolicy, currentVersion, currentHash) {
    const metadata = newPolicy && newPolicy.metadata && typeof newPolicy.metadata === "object" ? newPolicy.metadata : {};
    const allowVersions = Array.isArray(metadata.allowDowngradeFromVersions) ? metadata.allowDowngradeFromVersions : [];
    const allowHashes = Array.isArray(metadata.allowDowngradeFromHashes) ? metadata.allowDowngradeFromHashes : [];

    const versionAllowed = allowVersions.some((item) => Number(item) === Number(currentVersion));
    const hashAllowed = allowHashes.some(
      (item) => normalizeString(item).toLowerCase() === normalizeString(currentHash).toLowerCase(),
    );

    return versionAllowed || hashAllowed;
  }

  function activatePolicy(bundle = {}) {
    const policy = bundle && bundle.policy && typeof bundle.policy === "object" ? bundle.policy : null;
    const policyHash = normalizeString(bundle.policyHash).toLowerCase();
    const policyVersion = Number(bundle.policyVersion || (policy && policy.policyVersion));

    if (!policy || !policyHash || !Number.isInteger(policyVersion) || policyVersion <= 0) {
      throw makePolicyError("POLICY_ACTIVATION_INVALID", "Policy activation bundle is invalid", {
        hasPolicy: Boolean(policy),
        policyHash,
        policyVersion,
      });
    }

    if (activeBundle && policyVersion < activeBundle.policyVersion) {
      if (!allowDowngrade(policy, activeBundle.policyVersion, activeBundle.policyHash)) {
        throw makePolicyError("POLICY_VERSION_DOWNGRADE_NOT_ALLOWED", "Policy downgrade is not allowlisted", {
          fromVersion: activeBundle.policyVersion,
          toVersion: policyVersion,
          fromHash: activeBundle.policyHash,
          toHash: policyHash,
        });
      }

      auditLogger.log({
        event: "policy_downgrade",
        principal_id: "system",
        slug: "",
        request_id: "",
        status: "failure",
        details: {
          node_id: nodeId,
          from_version: activeBundle.policyVersion,
          to_version: policyVersion,
          from_hash: activeBundle.policyHash,
          to_hash: policyHash,
        },
      });
    }

    const activatedAt = Date.now();
    const upgradeWindowMs = getUpgradeWindowMs(policy);
    const upgradeWindowEndsAt = upgradeWindowMs > 0 ? activatedAt + upgradeWindowMs : activatedAt;

    activeBundle = deepFreeze({
      policy: deepFreeze(clone(policy)),
      policyHash,
      policyVersion,
      signatureVerified: bundle.signatureVerified === true,
      source: normalizeString(bundle.source) || "unknown",
      activatedAt,
      upgradeWindowMs,
      upgradeWindowEndsAt,
    });

    metrics.gauge("policy.version.active", policyVersion, {
      node_id: nodeId,
    });
    metrics.increment("policy.activation", {
      node_id: nodeId,
      source: activeBundle.source,
    });

    return activeBundle;
  }

  function captureExecutionSnapshot() {
    if (!activeBundle) {
      return null;
    }
    return activeBundle;
  }

  function normalizePeerVersion(peer) {
    const explicitPolicyVersion = Number(peer.executionPolicyVersion);
    if (Number.isInteger(explicitPolicyVersion) && explicitPolicyVersion > 0) {
      return explicitPolicyVersion;
    }

    const explicitConfigVersion = Number(peer.executionConfigVersion);
    if (Number.isInteger(explicitConfigVersion) && explicitConfigVersion > 0) {
      return explicitConfigVersion;
    }

    const raw =
      normalizeString(peer.executionPolicyVersion) ||
      normalizeString(peer.execution_policy_version) ||
      normalizeString(peer.executionConfigVersion) ||
      normalizeString(peer.execution_config_version);
    const parsed = Number.parseInt(raw, 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      return 0;
    }
    return parsed;
  }

  function normalizePeerHash(peer) {
    const raw =
      normalizeString(peer.executionPolicyHash) ||
      normalizeString(peer.execution_policy_hash) ||
      normalizeString(peer.executionConfigHash) ||
      normalizeString(peer.execution_config_hash);
    return raw.toLowerCase();
  }

  function classifyPeers(peers = []) {
    const now = Date.now();
    const withinWindow =
      Boolean(activeBundle) &&
      activeBundle.upgradeWindowMs > 0 &&
      now <= activeBundle.upgradeWindowEndsAt;

    const criticalMismatches = [];
    const warnings = [];

    if (!activeBundle) {
      criticalMismatches.push({
        classification: "MISSING_POLICY",
        peerId: "local",
        reason: "local_policy_missing",
      });
      return {
        ok: false,
        status: "mismatch",
        criticalMismatches,
        warnings,
        withinWindow,
        timestamp: now,
      };
    }

    const healthyPeers = Array.isArray(peers)
      ? peers.filter((peer) => normalizeString(peer && peer.status).toUpperCase() === "UP")
      : [];

    for (const peer of healthyPeers) {
      const peerId = normalizeString(peer.peerId) || "unknown-peer";
      const peerVersion = normalizePeerVersion(peer);
      const peerHash = normalizePeerHash(peer);

      if (!peerVersion || !/^[a-f0-9]{64}$/.test(peerHash)) {
        const entry = {
          classification: "MISSING_POLICY",
          peerId,
          peerVersion,
          peerHash,
        };
        if (production) {
          criticalMismatches.push(entry);
        } else {
          warnings.push(entry);
        }
        continue;
      }

      if (peerVersion === activeBundle.policyVersion && peerHash !== activeBundle.policyHash) {
        const entry = {
          classification: "HASH_MISMATCH_SAME_VERSION",
          peerId,
          localVersion: activeBundle.policyVersion,
          peerVersion,
          localHash: activeBundle.policyHash,
          peerHash,
        };
        metrics.increment("policy.hash.mismatch", {
          node_id: nodeId,
          peer_id: peerId,
        });
        if (production) {
          criticalMismatches.push(entry);
        } else {
          warnings.push(entry);
        }
        continue;
      }

      if (peerVersion !== activeBundle.policyVersion) {
        const entry = {
          classification: "VERSION_SKEW",
          peerId,
          localVersion: activeBundle.policyVersion,
          peerVersion,
          localHash: activeBundle.policyHash,
          peerHash,
          withinWindow,
        };
        metrics.increment("policy.version.skew", {
          node_id: nodeId,
          peer_id: peerId,
        });
        if (withinWindow) {
          warnings.push(entry);
        } else if (production) {
          criticalMismatches.push(entry);
        } else {
          warnings.push(entry);
        }
      }
    }

    const ok = criticalMismatches.length === 0;
    return {
      ok,
      status: ok ? "aligned" : "mismatch",
      criticalMismatches,
      warnings,
      withinWindow,
      timestamp: now,
    };
  }

  function evaluate(peers = []) {
    lastSummary = classifyPeers(peers);
    return lastSummary;
  }

  function assertExecutionAllowed(peers = []) {
    const summary = evaluate(peers);
    if (summary.ok) {
      return summary;
    }

    auditLogger.log({
      event: "policy_mismatch_block",
      principal_id: "system",
      slug: "",
      request_id: "",
      status: "failure",
      details: {
        node_id: nodeId,
        mismatches: summary.criticalMismatches,
        warnings: summary.warnings,
      },
    });

    throw makePolicyError("EXECUTION_CONFIG_MISMATCH", "Execution policy mismatch detected", summary);
  }

  function getActiveMetadata() {
    if (!activeBundle) {
      return {
        nodeId,
        executionPolicyVersion: 0,
        executionPolicyHash: "",
      };
    }

    return {
      nodeId,
      executionPolicyVersion: activeBundle.policyVersion,
      executionPolicyHash: activeBundle.policyHash,
      executionConfigVersion: `v${activeBundle.policyVersion}`,
      executionConfigHash: activeBundle.policyHash,
      upgradeWindowEndsAt: activeBundle.upgradeWindowEndsAt,
      allowedUpgradeWindowMinutes: Math.floor(activeBundle.upgradeWindowMs / 60000),
    };
  }

  function getLastSummary() {
    return {
      ...lastSummary,
      criticalMismatches: Array.isArray(lastSummary.criticalMismatches)
        ? lastSummary.criticalMismatches.slice()
        : [],
      warnings: Array.isArray(lastSummary.warnings) ? lastSummary.warnings.slice() : [],
    };
  }

  return {
    activatePolicy,
    captureExecutionSnapshot,
    evaluate,
    assertExecutionAllowed,
    getActiveMetadata,
    getLastSummary,
  };
}

module.exports = {
  createPolicyRuntime,
};
