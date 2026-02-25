const CIRCUIT_STATE = Object.freeze({
  CLOSED: "CLOSED",
  OPEN: "OPEN",
  HALF_OPEN: "HALF_OPEN",
});

function parsePositiveInt(value, fallback) {
  const parsed = Number.parseInt(String(value ?? "").trim(), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
}

function createCircuitBreaker(options = {}) {
  const enabled = Boolean(options && options.enabled);
  const failureThreshold = parsePositiveInt(options && options.failureThreshold, 5);
  const successThreshold = parsePositiveInt(options && options.successThreshold, 2);
  const timeoutMs = parsePositiveInt(options && options.timeout, 30000);
  const stateBySlug = new Map();

  function getOrCreate(slug) {
    let existing = stateBySlug.get(slug);
    if (!existing) {
      const now = Date.now();
      existing = {
        state: CIRCUIT_STATE.CLOSED,
        failureCount: 0,
        successCount: 0,
        lastFailureAt: 0,
        lastTransitionAt: now,
        halfOpenInFlight: false,
      };
      stateBySlug.set(slug, existing);
    }
    return existing;
  }

  function getHealthScore(entry) {
    if (entry.state === CIRCUIT_STATE.OPEN) {
      return 0;
    }
    if (entry.state === CIRCUIT_STATE.HALF_OPEN) {
      return 50;
    }
    return 100;
  }

  function toSnapshot(entry) {
    return {
      state: entry.state,
      failureCount: entry.failureCount,
      successCount: entry.successCount,
      lastFailureAt: entry.lastFailureAt,
      lastTransitionAt: entry.lastTransitionAt,
      healthScore: getHealthScore(entry),
    };
  }

  function makeTransition(fromState, entry) {
    return {
      transitioned: fromState !== entry.state,
      from: fromState,
      to: entry.state,
      snapshot: toSnapshot(entry),
    };
  }

  function moveOpenToHalfOpenIfReady(entry, now) {
    if (entry.state !== CIRCUIT_STATE.OPEN) {
      return false;
    }
    if (now - entry.lastTransitionAt < timeoutMs) {
      return false;
    }
    entry.state = CIRCUIT_STATE.HALF_OPEN;
    entry.successCount = 0;
    entry.halfOpenInFlight = false;
    entry.lastTransitionAt = now;
    return true;
  }

  function checkBeforeRequest(slug, now = Date.now()) {
    const entry = getOrCreate(slug);
    const fromState = entry.state;
    moveOpenToHalfOpenIfReady(entry, now);
    const transition = makeTransition(fromState, entry);

    if (entry.state === CIRCUIT_STATE.OPEN) {
      return {
        allowed: false,
        leaseAcquired: false,
        nextRetryAt: entry.lastTransitionAt + timeoutMs,
        ...transition,
      };
    }

    if (entry.state === CIRCUIT_STATE.HALF_OPEN) {
      if (entry.halfOpenInFlight) {
        return {
          allowed: false,
          leaseAcquired: false,
          nextRetryAt: entry.lastTransitionAt + timeoutMs,
          ...transition,
        };
      }
      entry.halfOpenInFlight = true;
      return {
        allowed: true,
        leaseAcquired: true,
        ...transition,
      };
    }

    return {
      allowed: true,
      leaseAcquired: false,
      ...transition,
    };
  }

  function recordSuccess(slug, now = Date.now()) {
    const entry = getOrCreate(slug);
    const fromState = entry.state;

    if (entry.state === CIRCUIT_STATE.HALF_OPEN) {
      entry.successCount += 1;
      entry.halfOpenInFlight = false;
      if (entry.successCount >= successThreshold) {
        entry.state = CIRCUIT_STATE.CLOSED;
        entry.failureCount = 0;
        entry.successCount = 0;
        entry.lastTransitionAt = now;
      }
      return makeTransition(fromState, entry);
    }

    if (entry.state === CIRCUIT_STATE.CLOSED) {
      entry.failureCount = 0;
      entry.successCount = 0;
    }

    return makeTransition(fromState, entry);
  }

  function recordFailure(slug, now = Date.now()) {
    const entry = getOrCreate(slug);
    const fromState = entry.state;

    if (entry.state === CIRCUIT_STATE.HALF_OPEN) {
      entry.halfOpenInFlight = false;
      entry.successCount = 0;
      entry.failureCount = Math.max(entry.failureCount + 1, failureThreshold);
      entry.lastFailureAt = now;
      entry.state = CIRCUIT_STATE.OPEN;
      entry.lastTransitionAt = now;
      return makeTransition(fromState, entry);
    }

    if (entry.state === CIRCUIT_STATE.CLOSED) {
      entry.failureCount += 1;
      entry.lastFailureAt = now;
      if (entry.failureCount >= failureThreshold) {
        entry.successCount = 0;
        entry.state = CIRCUIT_STATE.OPEN;
        entry.lastTransitionAt = now;
      }
      return makeTransition(fromState, entry);
    }

    entry.lastFailureAt = now;
    return makeTransition(fromState, entry);
  }

  function releaseHalfOpenLease(slug) {
    const entry = stateBySlug.get(slug);
    if (!entry) {
      return;
    }
    if (entry.state === CIRCUIT_STATE.HALF_OPEN) {
      entry.halfOpenInFlight = false;
    }
  }

  function getSnapshot(slug, now = Date.now()) {
    const entry = getOrCreate(slug);
    moveOpenToHalfOpenIfReady(entry, now);
    return toSnapshot(entry);
  }

  function exportState() {
    return Array.from(stateBySlug.entries())
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([slug, entry]) => ({
        slug,
        state: entry.state,
        failureCount: entry.failureCount,
        successCount: entry.successCount,
        lastFailureAt: entry.lastFailureAt,
        lastTransitionAt: entry.lastTransitionAt,
        halfOpenInFlight: entry.halfOpenInFlight === true,
      }));
  }

  function importState(rawState, options = {}) {
    const entries = Array.isArray(rawState) ? rawState : [];
    const now = Date.now();
    const resetHalfOpenToOpen = options && options.resetHalfOpenToOpen === true;
    stateBySlug.clear();

    for (const item of entries) {
      if (!item || typeof item !== "object") {
        continue;
      }
      const slug = typeof item.slug === "string" ? item.slug.trim().toLowerCase() : "";
      if (!slug) {
        continue;
      }

      const state =
        item.state === CIRCUIT_STATE.OPEN || item.state === CIRCUIT_STATE.HALF_OPEN || item.state === CIRCUIT_STATE.CLOSED
          ? item.state
          : CIRCUIT_STATE.CLOSED;
      const normalizedState = resetHalfOpenToOpen && state === CIRCUIT_STATE.HALF_OPEN ? CIRCUIT_STATE.OPEN : state;
      const failureCount = Number.isFinite(Number(item.failureCount)) ? Math.max(0, Math.floor(Number(item.failureCount))) : 0;
      const successCount = Number.isFinite(Number(item.successCount)) ? Math.max(0, Math.floor(Number(item.successCount))) : 0;
      const lastFailureAt = Number.isFinite(Number(item.lastFailureAt)) ? Math.max(0, Math.floor(Number(item.lastFailureAt))) : 0;
      const lastTransitionAt = Number.isFinite(Number(item.lastTransitionAt))
        ? Math.max(0, Math.floor(Number(item.lastTransitionAt)))
        : now;

      stateBySlug.set(slug, {
        state: normalizedState,
        failureCount,
        successCount,
        lastFailureAt,
        lastTransitionAt,
        halfOpenInFlight: false,
      });
    }
  }

  return {
    enabled,
    checkBeforeRequest,
    recordSuccess,
    recordFailure,
    releaseHalfOpenLease,
    getSnapshot,
    exportState,
    importState,
    constants: {
      failureThreshold,
      successThreshold,
      timeoutMs,
    },
    states: CIRCUIT_STATE,
  };
}

module.exports = {
  createCircuitBreaker,
  CIRCUIT_STATE,
};
