const crypto = require("node:crypto");

let redisModule = null;
try {
  // Optional at runtime for non-production; required in production when quota is enabled.
  redisModule = require("redis");
} catch {
  redisModule = null;
}

const LUA_CONSUME = `
local hourKey = KEYS[1]
local minuteKey = KEYS[2]
local member = ARGV[1]
local hourWindowMs = tonumber(ARGV[2])
local hourLimit = tonumber(ARGV[3])
local minuteWindowMs = tonumber(ARGV[4])
local minuteLimit = tonumber(ARGV[5])
local ttlMs = tonumber(ARGV[6])

local nowParts = redis.call('TIME')
local nowMs = tonumber(nowParts[1]) * 1000 + math.floor(tonumber(nowParts[2]) / 1000)

redis.call('ZREMRANGEBYSCORE', hourKey, 0, nowMs - hourWindowMs)
redis.call('ZREMRANGEBYSCORE', minuteKey, 0, nowMs - minuteWindowMs)

local hourCount = redis.call('ZCARD', hourKey)
local minuteCount = redis.call('ZCARD', minuteKey)

if minuteLimit > 0 and minuteCount >= minuteLimit then
  return {0, 'EXECUTION_RATE_LIMIT_EXCEEDED', tostring(nowMs), tostring(minuteCount), tostring(hourCount)}
end

if hourLimit > 0 and hourCount >= hourLimit then
  return {0, 'EXECUTION_QUOTA_EXCEEDED', tostring(nowMs), tostring(minuteCount), tostring(hourCount)}
end

redis.call('ZADD', hourKey, 'NX', nowMs, member)
redis.call('ZADD', minuteKey, 'NX', nowMs, member)
redis.call('PEXPIRE', hourKey, ttlMs)
redis.call('PEXPIRE', minuteKey, ttlMs)

hourCount = redis.call('ZCARD', hourKey)
minuteCount = redis.call('ZCARD', minuteKey)

return {1, 'OK', tostring(nowMs), tostring(minuteCount), tostring(hourCount)}
`;

function normalizeString(value) {
  return typeof value === "string" ? value.trim() : "";
}

function parsePositiveInteger(value, fallback) {
  const parsed = Number.parseInt(String(value ?? "").trim(), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
}

function isPlainObject(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function createNoopMetrics() {
  return {
    increment: () => {},
  };
}

function createSafeMetrics(rawMetrics) {
  const noop = createNoopMetrics();
  const source = rawMetrics && typeof rawMetrics === "object" ? rawMetrics : noop;
  return {
    increment: (...args) => {
      try {
        if (typeof source.increment === "function") {
          source.increment(...args);
        }
      } catch {}
    },
  };
}

function createNoopLogger() {
  return {
    info: () => {},
    error: () => {},
  };
}

function createSafeLogger(rawLogger) {
  const noop = createNoopLogger();
  const source = rawLogger && typeof rawLogger === "object" ? rawLogger : noop;
  return {
    info: (...args) => {
      try {
        if (typeof source.info === "function") {
          source.info(...args);
        }
      } catch {}
    },
    error: (...args) => {
      try {
        if (typeof source.error === "function") {
          source.error(...args);
        }
      } catch {}
    },
  };
}

function hashPrincipal(principalId) {
  const normalized = normalizeString(principalId) || "anonymous";
  return crypto.createHash("sha256").update(normalized, "utf8").digest("hex").slice(0, 16);
}

function makeResult(ok, code, message, details = {}) {
  return {
    ok,
    code,
    message,
    details,
  };
}

function createExecutionQuotaStore(options = {}) {
  const production = options.production === true;
  const security = isPlainObject(options.security) ? options.security : {};
  const nodeId = normalizeString(options.nodeId) || normalizeString(process.env.SUPERVISOR_NODE_ID) || "node-unknown";

  const executionQuotaPerHour = parsePositiveInteger(
    security.executionQuotaPerHour,
    parsePositiveInteger(process.env.EXECUTION_QUOTA_PER_HOUR, 0),
  );
  const executionBurstLimitPerMinute = parsePositiveInteger(
    security.executionBurstLimitPerMinute,
    parsePositiveInteger(process.env.EXECUTION_BURST_LIMIT_PER_MINUTE, 0),
  );
  const redisUrl = normalizeString(security.quotaRedisUrl || process.env.EXECUTION_QUOTA_REDIS_URL);
  const redisPrefix = normalizeString(security.quotaRedisPrefix || process.env.EXECUTION_QUOTA_REDIS_PREFIX) || "openclaw:quota";

  const metrics = createSafeMetrics(options.metrics);
  const logger = createSafeLogger(options.logger);

  const enabled = executionQuotaPerHour > 0 || executionBurstLimitPerMinute > 0;

  let client = options.client || null;
  let connected = false;

  async function ensureClient() {
    if (!enabled) {
      return null;
    }

    if (!client) {
      if (!redisModule || typeof redisModule.createClient !== "function") {
        throw new Error("redis module is unavailable");
      }

      if (!redisUrl) {
        throw new Error("quotaRedisUrl is required");
      }

      client = redisModule.createClient({
        url: redisUrl,
        socket: {
          reconnectStrategy: false,
          connectTimeout: 3000,
        },
      });

      client.on("error", (error) => {
        logger.error({
          event: "quota_store_error",
          message: error && error.message ? error.message : String(error),
          timestamp: new Date().toISOString(),
        });
      });
    }

    if (!connected && typeof client.connect === "function") {
      await client.connect();
      connected = true;
    }

    return client;
  }

  function buildKeys(principalId) {
    const principalHash = hashPrincipal(principalId);
    return {
      principalHash,
      hourKey: `${redisPrefix}:${principalHash}:hour`,
      minuteKey: `${redisPrefix}:${principalHash}:minute`,
    };
  }

  function emitRejection(reasonCode, toolSlug, principalHash) {
    metrics.increment("tool.execution.rejected", {
      reason: reasonCode,
      node_id: nodeId,
      tool: normalizeString(toolSlug).toLowerCase() || "unknown",
      principal_hash: principalHash || "anonymous",
    });
  }

  async function consume(input = {}) {
    if (!enabled) {
      return makeResult(true, "QUOTA_DISABLED", "Execution quota is disabled", { skipped: true });
    }

    const principalId = normalizeString(input.principalId);
    const requestId = normalizeString(input.requestId) || crypto.randomBytes(16).toString("hex");
    const toolSlug = normalizeString(input.toolSlug).toLowerCase() || "unknown";

    if (!principalId) {
      const principalHash = hashPrincipal("anonymous");
      emitRejection("UNAUTHENTICATED_EXECUTION", toolSlug, principalHash);
      return makeResult(false, "UNAUTHENTICATED_EXECUTION", "Execution requires authenticated identity", {
        principalHash,
      });
    }

    let resolvedClient;
    try {
      resolvedClient = await ensureClient();
    } catch (error) {
      if (production) {
        const principalHash = hashPrincipal(principalId);
        emitRejection("EXECUTION_QUOTA_EXCEEDED", toolSlug, principalHash);
        return makeResult(false, "EXECUTION_QUOTA_EXCEEDED", "Execution quota storage unavailable in production", {
          principalHash,
          reason: error && error.message ? error.message : String(error),
        });
      }

      logger.error({
        event: "quota_store_unavailable_non_prod",
        message: error && error.message ? error.message : String(error),
        timestamp: new Date().toISOString(),
      });
      return makeResult(true, "QUOTA_STORE_UNAVAILABLE_NON_PROD", "Quota storage unavailable in non-production", {
        skipped: true,
      });
    }

    const keys = buildKeys(principalId);
    const ttlMs = Math.max(3600_000, 2 * 3600_000);

    let response;
    try {
      response = await resolvedClient.eval(LUA_CONSUME, {
        keys: [keys.hourKey, keys.minuteKey],
        arguments: [
          requestId,
          String(3600_000),
          String(Math.max(0, executionQuotaPerHour)),
          String(60_000),
          String(Math.max(0, executionBurstLimitPerMinute)),
          String(ttlMs),
        ],
      });
    } catch (error) {
      if (production) {
        emitRejection("EXECUTION_QUOTA_EXCEEDED", toolSlug, keys.principalHash);
        return makeResult(false, "EXECUTION_QUOTA_EXCEEDED", "Execution quota check failed in production", {
          principalHash: keys.principalHash,
          reason: error && error.message ? error.message : String(error),
        });
      }
      return makeResult(true, "QUOTA_CHECK_FAILED_NON_PROD", "Execution quota check failed in non-production", {
        skipped: true,
      });
    }

    const allowed = Array.isArray(response) && Number(response[0]) === 1;
    const code = Array.isArray(response) && typeof response[1] === "string" ? response[1] : "EXECUTION_QUOTA_EXCEEDED";
    const minuteCount = Array.isArray(response) ? Number(response[3]) || 0 : 0;
    const hourCount = Array.isArray(response) ? Number(response[4]) || 0 : 0;

    if (!allowed) {
      emitRejection(code, toolSlug, keys.principalHash);
      return makeResult(false, code, "Execution quota exceeded", {
        principalHash: keys.principalHash,
        minuteCount,
        hourCount,
      });
    }

    return makeResult(true, "OK", "Quota check passed", {
      principalHash: keys.principalHash,
      minuteCount,
      hourCount,
    });
  }

  async function close() {
    if (!client || typeof client.quit !== "function") {
      return;
    }

    try {
      await client.quit();
    } catch {
      try {
        if (typeof client.disconnect === "function") {
          client.disconnect();
        }
      } catch {}
    }

    connected = false;
  }

  return {
    enabled,
    production,
    executionQuotaPerHour,
    executionBurstLimitPerMinute,
    consume,
    close,
  };
}

module.exports = {
  createExecutionQuotaStore,
};
