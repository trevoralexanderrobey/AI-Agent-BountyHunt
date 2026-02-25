function makeRateLimitError(requestId) {
  const error = new Error("Rate limit exceeded");
  error.code = "SUPERVISOR_RATE_LIMIT_EXCEEDED";
  if (requestId) {
    error.request_id = requestId;
    error.details = { request_id: requestId };
  }
  return error;
}

const MAX_PRINCIPALS = 10_000;
const OVERFLOW_PRINCIPAL_KEY = "__overflow__";

function parsePositiveNumber(value, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
}

function normalizePrincipalId(principalId) {
  if (typeof principalId !== "string") {
    return "anonymous";
  }
  const trimmed = principalId.trim();
  return trimmed || "anonymous";
}

function createRateLimiter(config = {}) {
  const enabled = Boolean(config && config.enabled);
  const rps = parsePositiveNumber(config && config.rps, 10);
  const burst = parsePositiveNumber(config && config.burst, 20);
  const buckets = new Map();
  let overflowBucket = {
    tokens: burst,
    lastRefillTimestamp: Date.now(),
  };

  function check(principalId, requestId) {
    if (!enabled) {
      return { ok: true, principalId: normalizePrincipalId(principalId) };
    }

    const normalizedPrincipal = normalizePrincipalId(principalId);
    const shouldUseOverflow = !buckets.has(normalizedPrincipal) && buckets.size >= MAX_PRINCIPALS;
    const key = shouldUseOverflow ? OVERFLOW_PRINCIPAL_KEY : normalizedPrincipal;
    const now = Date.now();

    let bucket = shouldUseOverflow ? overflowBucket : buckets.get(key);
    if (!bucket) {
      bucket = {
        tokens: burst,
        lastRefillTimestamp: now,
      };
      if (shouldUseOverflow) {
        overflowBucket = bucket;
      } else {
        buckets.set(key, bucket);
      }
    }

    const elapsedMs = Math.max(0, now - bucket.lastRefillTimestamp);
    if (elapsedMs > 0) {
      const refill = (elapsedMs / 1000) * rps;
      bucket.tokens = Math.min(burst, bucket.tokens + refill);
      bucket.lastRefillTimestamp = now;
    }

    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return { ok: true, principalId: key };
    }

    throw makeRateLimitError(requestId);
  }

  return {
    check,
  };
}

module.exports = {
  createRateLimiter,
};
