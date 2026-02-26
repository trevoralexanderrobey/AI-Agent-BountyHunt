function normalizeNodeId(value) {
  return typeof value === "string" ? value.trim() : "";
}

function normalizeMembership(rawNodeIds) {
  if (!Array.isArray(rawNodeIds)) {
    return [];
  }

  const unique = new Set();
  for (const rawNodeId of rawNodeIds) {
    const nodeId = normalizeNodeId(rawNodeId);
    if (nodeId) {
      unique.add(nodeId);
    }
  }

  return Array.from(unique).sort((left, right) => left.localeCompare(right));
}

function membershipKey(nodeIds) {
  return normalizeMembership(nodeIds).join(",");
}

function createPartitionDetector(options = {}) {
  const listeners = new Set();
  let partitioned = false;
  let partitionEnteredAt = 0;
  let partitionEntryBaselineSize = 0;
  let lastStableMembershipKey = "";
  let lastStableMembershipSize = 0;
  let recoveryMembershipKey = "";
  let recoveryStableTicks = 0;

  function emitPartitionChange(payload) {
    for (const callback of listeners) {
      try {
        callback(payload);
      } catch {}
    }
  }

  function isPartitioned() {
    return partitioned;
  }

  function onPartitionChange(callback) {
    if (typeof callback !== "function") {
      return () => {};
    }
    listeners.add(callback);
    return () => {
      listeners.delete(callback);
    };
  }

  function evaluateMembership(input = {}) {
    const now = Number.isFinite(Number(input.now)) ? Math.max(0, Number(input.now)) : Date.now();
    const stableNodeIds = normalizeMembership(input.stableHealthyNodeIds);
    const observedNodeIds = normalizeMembership(input.observedHealthyNodeIds);

    const stableKey = membershipKey(stableNodeIds);
    const observedKey = membershipKey(observedNodeIds);
    const stableSize = stableNodeIds.length;
    const observedSize = observedNodeIds.length;

    lastStableMembershipKey = stableKey;
    lastStableMembershipSize = stableSize;

    let entered = false;
    let recovered = false;
    let reason = "steady";

    if (!partitioned) {
      if (stableSize > 0 && observedSize <= stableSize / 2) {
        partitioned = true;
        entered = true;
        reason = "majority_loss_guard";
        partitionEnteredAt = now;
        partitionEntryBaselineSize = stableSize;
        recoveryMembershipKey = "";
        recoveryStableTicks = 0;
      }
    } else {
      const recoveryThreshold = Math.ceil(partitionEntryBaselineSize / 2);
      const thresholdMet = observedSize >= recoveryThreshold;
      if (!thresholdMet) {
        reason = "recovery_threshold_not_met";
        recoveryMembershipKey = "";
        recoveryStableTicks = 0;
      } else {
        if (observedKey && observedKey === recoveryMembershipKey) {
          recoveryStableTicks += 1;
        } else {
          recoveryMembershipKey = observedKey;
          recoveryStableTicks = observedKey ? 1 : 0;
        }

        reason = "recovery_stabilizing";
        if (recoveryStableTicks >= 2) {
          partitioned = false;
          recovered = true;
          reason = "recovered_stable_membership";
          partitionEnteredAt = 0;
          partitionEntryBaselineSize = 0;
          recoveryMembershipKey = "";
          recoveryStableTicks = 0;
        }
      }
    }

    if (entered || recovered) {
      emitPartitionChange({
        partitioned,
        entered,
        recovered,
        timestamp: now,
        reason,
        baselineSize: partitionEntryBaselineSize,
        stableSize,
        observedSize,
      });
    }

    return {
      partitioned,
      entered,
      recovered,
      reason,
      timestamp: now,
      stableMembershipKey: stableKey,
      stableSize,
      observedMembershipKey: observedKey,
      observedSize,
      partitionEnteredAt,
      partitionEntryBaselineSize,
      recoveryMembershipKey,
      recoveryStableTicks,
      recoveryThreshold: Math.ceil(Math.max(0, partitionEntryBaselineSize) / 2),
      thresholdMet: partitionEntryBaselineSize > 0 ? observedSize >= Math.ceil(partitionEntryBaselineSize / 2) : false,
      lastStableMembershipKey,
      lastStableMembershipSize,
    };
  }

  if (options && typeof options === "object") {
    if (Array.isArray(options.initialStableHealthyNodeIds)) {
      const normalized = normalizeMembership(options.initialStableHealthyNodeIds);
      lastStableMembershipKey = normalized.join(",");
      lastStableMembershipSize = normalized.length;
    }
  }

  return {
    isPartitioned,
    onPartitionChange,
    evaluateMembership,
  };
}

module.exports = {
  createPartitionDetector,
};
