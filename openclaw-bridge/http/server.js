const http = require("node:http");
const https = require("node:https");
const { PassThrough } = require("node:stream");

const { createMetrics } = require("../observability/metrics.js");
const { createPrometheusExporter } = require("../monitoring/prometheus-exporter.js");
const { createRequestSigner } = require("../security/request-signing.js");
const { createTLSConfig } = require("../security/tls-config.js");
const { createSupervisorV1 } = require("../supervisor/supervisor-v1.js");
const { createHttpHandlers } = require("./handlers.js");

function createNoopLogger() {
  return {
    info: () => {},
    error: () => {},
  };
}

function parsePositiveInt(value, fallback) {
  const parsed = Number.parseInt(String(value ?? "").trim(), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
}

function parseBoolean(value, fallback = false) {
  if (typeof value === "boolean") {
    return value;
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

function parseCsv(value) {
  if (typeof value !== "string") {
    return [];
  }
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function parseCsvOrUndefined(value) {
  const parsed = parseCsv(value);
  return parsed.length > 0 ? parsed : undefined;
}

function parseJsonObject(value, fallback = {}) {
  if (typeof value !== "string" || value.trim().length === 0) {
    return fallback;
  }
  try {
    const parsed = JSON.parse(value);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed;
    }
  } catch {}
  return fallback;
}

function normalizeExecutionMode(value) {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : "";
  return normalized === "container" ? "container" : "host";
}

function normalizeExecutionBackend(value) {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : "";
  if (normalized === "docker" || normalized === "containerd" || normalized === "mock") {
    return normalized;
  }
  return "mock";
}

function getBaseContentType(rawHeader) {
  if (typeof rawHeader !== "string") {
    return "";
  }
  return rawHeader.split(";")[0].trim().toLowerCase();
}

function nowIso() {
  return new Date().toISOString();
}

function writeJson(res, statusCode, payload) {
  const body = JSON.stringify(payload);
  res.statusCode = statusCode;
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Content-Length", Buffer.byteLength(body, "utf8"));
  res.end(body);
}

function writeApiError(res, statusCode, code, message) {
  writeJson(res, statusCode, {
    ok: false,
    error: {
      code,
      message,
    },
    api_version: "v1",
    timestamp: nowIso(),
  });
}

function writeServiceUnavailable(res) {
  writeApiError(res, 503, "INTERNAL_ERROR", "Service unavailable");
}

function createHttpServer(options = {}) {
  const httpConfig = {
    enabled: Boolean(options.httpServer && options.httpServer.enabled),
    port: parsePositiveInt(options.httpServer && options.httpServer.port, 8080),
    host:
      options.httpServer && typeof options.httpServer.host === "string" && options.httpServer.host.trim().length > 0
        ? options.httpServer.host.trim()
        : "127.0.0.1",
  };

  const shutdownTimeoutMs = parsePositiveInt(options.shutdownTimeoutMs, 30000);
  const maxBodyBytes = parsePositiveInt(options.maxBodyBytes, 1024 * 1024);
  const installSignalHandlers = options.installSignalHandlers !== false;
  const exitOnSignal = options.exitOnSignal !== false;
  const logger = options.logger && typeof options.logger === "object" ? options.logger : createNoopLogger();
  const metrics = options.metrics && typeof options.metrics === "object" ? options.metrics : createMetrics();
  const supervisor = options.supervisor || createSupervisorV1(options.supervisorOptions || {});
  const authEnabled = Boolean(
    (options.supervisorOptions && options.supervisorOptions.auth && options.supervisorOptions.auth.enabled) || options.authEnabled,
  );
  const tlsConfig = createTLSConfig(options.tls || {});
  const requestSigner = createRequestSigner({
    enabled:
      options.requestSigning && typeof options.requestSigning.enabled !== "undefined"
        ? options.requestSigning.enabled
        : parseBoolean(process.env.REQUEST_SIGNING_ENABLED, false),
    secret:
      options.requestSigning && typeof options.requestSigning.secret === "string"
        ? options.requestSigning.secret
        : process.env.REQUEST_SIGNING_SECRET || "",
  });
  const prometheusEnabled =
    options.prometheusExporter && typeof options.prometheusExporter.enabled !== "undefined"
      ? Boolean(options.prometheusExporter.enabled)
      : parseBoolean(process.env.PROMETHEUS_EXPORTER_ENABLED, false);

  const state = {
    server: null,
    listening: false,
    shuttingDown: false,
    inFlight: 0,
    supervisorReady: false,
  };

  let settleInFlightWaiter = null;
  let signalBound = false;
  let signalHandler = null;

  const handlers = createHttpHandlers({
    supervisor,
    metrics,
    logger,
    authEnabled,
    isShuttingDown: () => state.shuttingDown,
    maxBodyBytes,
  });
  const prometheusExporter = createPrometheusExporter({
    snapshot: () => {
      const supervisorSnapshot = supervisor.getMetrics();
      const httpSnapshot = metrics.snapshot();
      return {
        counters: [...(supervisorSnapshot.counters || []), ...(httpSnapshot.counters || [])],
        histograms: [...(supervisorSnapshot.histograms || []), ...(httpSnapshot.histograms || [])],
        gauges: [...(supervisorSnapshot.gauges || []), ...(httpSnapshot.gauges || [])],
      };
    },
  });

  function notifyInFlightChange() {
    if (state.inFlight === 0 && settleInFlightWaiter) {
      const resolve = settleInFlightWaiter;
      settleInFlightWaiter = null;
      resolve();
    }
  }

  async function readRawBody(req) {
    return new Promise((resolve, reject) => {
      let raw = "";
      let bytes = 0;
      req.setEncoding("utf8");
      req.on("data", (chunk) => {
        bytes += Buffer.byteLength(chunk, "utf8");
        if (bytes > maxBodyBytes) {
          reject(new Error("PAYLOAD_TOO_LARGE"));
          req.destroy();
          return;
        }
        raw += chunk;
      });
      req.on("end", () => resolve(raw));
      req.on("error", reject);
    });
  }

  function createReplayRequest(req, rawBody) {
    const replay = new PassThrough();
    replay.url = req.url;
    replay.method = req.method;
    replay.headers = req.headers;
    replay.httpVersion = req.httpVersion;
    replay.socket = req.socket;
    replay.connection = req.connection;
    process.nextTick(() => {
      if (rawBody && rawBody.length > 0) {
        replay.write(rawBody);
      }
      replay.end();
    });
    return replay;
  }

  async function dispatchRequest(req, res) {
    const path = new URL(req.url || "/", "http://localhost").pathname;
    if (prometheusEnabled && path === "/metrics/prometheus") {
      if (req.method !== "GET") {
        writeApiError(res, 405, "INVALID_REQUEST", "Method not allowed");
        return;
      }
      const output = prometheusExporter.render();
      res.statusCode = 200;
      res.setHeader("Content-Type", "text/plain; version=0.0.4; charset=utf-8");
      res.setHeader("Content-Length", Buffer.byteLength(output, "utf8"));
      res.end(output);
      return;
    }

    if (requestSigner.enabled && req.method === "POST" && getBaseContentType(req.headers["content-type"]) === "application/json") {
      const providedSignature = typeof req.headers["x-signature"] === "string" ? req.headers["x-signature"] : "";
      const rawBody = await readRawBody(req);
      const verification = requestSigner.parseAndVerify(rawBody, providedSignature);
      if (!verification.ok) {
        const statusCode = verification.code === "INVALID_SIGNATURE" ? 401 : 400;
        writeApiError(res, statusCode, verification.code, verification.message);
        return;
      }
      const replayReq = createReplayRequest(req, rawBody);
      await handlers.handle(replayReq, res);
      return;
    }

    await handlers.handle(req, res);
  }

  function bindSignals() {
    if (!installSignalHandlers || signalBound) {
      return;
    }

    signalHandler = async (signal) => {
      try {
        await shutdown({ signal });
        if (exitOnSignal) {
          process.exit(0);
        }
      } catch {
        if (exitOnSignal) {
          process.exit(1);
        }
      }
    };

    process.on("SIGINT", signalHandler);
    process.on("SIGTERM", signalHandler);
    signalBound = true;
  }

  function unbindSignals() {
    if (!signalBound || !signalHandler) {
      return;
    }
    process.off("SIGINT", signalHandler);
    process.off("SIGTERM", signalHandler);
    signalBound = false;
    signalHandler = null;
  }

  async function start() {
    if (!httpConfig.enabled) {
      return {
        ok: true,
        enabled: false,
        host: httpConfig.host,
        port: httpConfig.port,
        protocol: tlsConfig.enabled ? "https" : "http",
      };
    }

    if (state.listening) {
      return {
        ok: true,
        enabled: true,
        host: httpConfig.host,
        port: httpConfig.port,
        protocol: tlsConfig.enabled ? "https" : "http",
      };
    }

    await supervisor.initialize();
    state.supervisorReady = true;
    if (requestSigner.enabled && !requestSigner.ready) {
      throw new Error("Request signing enabled but REQUEST_SIGNING_SECRET is not configured");
    }

    const requestHandler = (req, res) => {
      if (state.shuttingDown) {
        writeServiceUnavailable(res);
        return;
      }

      state.inFlight += 1;
      dispatchRequest(req, res)
        .catch((error) => {
          logger.error({
            event: "http_handler_error",
            code: error && error.code ? error.code : "INTERNAL_ERROR",
            message: error && error.message ? error.message : "Unexpected HTTP handler failure",
            timestamp: nowIso(),
          });
          if (!res.headersSent) {
            if (error && error.message === "PAYLOAD_TOO_LARGE") {
              writeApiError(res, 413, "INVALID_REQUEST", "Request body too large");
            } else {
              writeApiError(res, 500, "INTERNAL_ERROR", "Internal server error");
            }
          }
        })
        .finally(() => {
          state.inFlight = Math.max(0, state.inFlight - 1);
          notifyInFlightChange();
        });
    };

    state.server = tlsConfig.enabled ? https.createServer(tlsConfig.serverOptions, requestHandler) : http.createServer(requestHandler);

    await new Promise((resolve, reject) => {
      state.server.once("error", reject);
      state.server.listen(httpConfig.port, httpConfig.host, () => {
        state.server.removeListener("error", reject);
        resolve();
      });
    });

    state.listening = true;
    bindSignals();

    const protocol = tlsConfig.enabled ? "https" : "http";

    logger.info({
      event: "http_server_started",
      host: httpConfig.host,
      port: httpConfig.port,
      protocol,
      mtls_enabled: tlsConfig.enabled ? tlsConfig.mtlsEnabled : false,
      certificate_expires: tlsConfig.enabled && tlsConfig.certificateInfo ? tlsConfig.certificateInfo.validTo : null,
      message: `Server listening on ${protocol}://${httpConfig.host}:${httpConfig.port}`,
      timestamp: nowIso(),
    });

    return {
      ok: true,
      enabled: true,
      host: httpConfig.host,
      port: httpConfig.port,
      protocol,
    };
  }

  async function waitForInFlightToDrain(timeoutMs) {
    if (state.inFlight === 0) {
      return true;
    }

    const drained = new Promise((resolve) => {
      settleInFlightWaiter = resolve;
    });
    const timedOut = new Promise((resolve) => {
      setTimeout(() => resolve(false), timeoutMs);
    });

    const result = await Promise.race([drained.then(() => true), timedOut]);
    if (result === false && settleInFlightWaiter) {
      settleInFlightWaiter = null;
    }
    return result;
  }

  async function shutdown(context = {}) {
    if (state.shuttingDown) {
      return {
        ok: true,
        draining: true,
      };
    }

    state.shuttingDown = true;
    logger.info({
      event: "http_server_shutdown_start",
      signal: context.signal || null,
      timestamp: nowIso(),
    });

    await waitForInFlightToDrain(shutdownTimeoutMs);

    if (state.server) {
      await new Promise((resolve) => {
        state.server.close(() => resolve());
      });
      state.server = null;
      state.listening = false;
    }

    await supervisor.shutdown();
    state.supervisorReady = false;
    unbindSignals();

    logger.info({
      event: "http_server_shutdown_complete",
      timestamp: nowIso(),
    });

    return {
      ok: true,
      shutdown: true,
    };
  }

  function getState() {
    return {
      enabled: httpConfig.enabled,
      listening: state.listening,
      shuttingDown: state.shuttingDown,
      inFlight: state.inFlight,
      supervisorReady: state.supervisorReady,
      host: httpConfig.host,
      port: httpConfig.port,
      protocol: tlsConfig.enabled ? "https" : "http",
      mtlsEnabled: tlsConfig.enabled ? tlsConfig.mtlsEnabled : false,
      requestSigningEnabled: requestSigner.enabled,
      prometheusEnabled,
    };
  }

  return {
    start,
    shutdown,
    getState,
  };
}

module.exports = {
  createHttpServer,
};

if (require.main === module) {
  const server = createHttpServer({
    httpServer: {
      enabled: true,
      port: parsePositiveInt(process.env.OPENCLAW_HTTP_PORT, 8080),
      host: process.env.OPENCLAW_HTTP_HOST || "127.0.0.1",
    },
    supervisorOptions: {
      auth: {
        enabled: process.env.SUPERVISOR_AUTH_ENABLED === "true",
        mode: "bearer",
      },
      rateLimit: {
        enabled: process.env.SUPERVISOR_RATE_LIMIT_ENABLED === "true",
        rps: process.env.SUPERVISOR_RATE_LIMIT_RPS,
        burst: process.env.SUPERVISOR_RATE_LIMIT_BURST,
      },
      idempotency: {
        enabled: process.env.SUPERVISOR_IDEMPOTENCY_ENABLED === "true",
        ttlMs: process.env.SUPERVISOR_IDEMPOTENCY_TTL_MS,
        maxEntries: process.env.SUPERVISOR_IDEMPOTENCY_MAX_ENTRIES,
      },
      queue: {
        enabled: process.env.SUPERVISOR_QUEUE_ENABLED === "true",
        maxLength: process.env.SUPERVISOR_QUEUE_MAX_LENGTH,
        pollIntervalMs: process.env.SUPERVISOR_QUEUE_POLL_INTERVAL_MS,
      },
      circuitBreaker: {
        enabled: process.env.SUPERVISOR_CB_ENABLED === "true",
        failureThreshold: process.env.SUPERVISOR_CB_FAILURE_THRESHOLD,
        successThreshold: process.env.SUPERVISOR_CB_SUCCESS_THRESHOLD,
        timeout: process.env.SUPERVISOR_CB_TIMEOUT_MS,
      },
      auditLog: {
        enabled: parseBoolean(process.env.AUDIT_LOG_ENABLED, true),
        path: process.env.AUDIT_LOG_PATH,
        rotationPolicy: {
          daily: parseBoolean(process.env.AUDIT_LOG_ROTATE_DAILY, true),
          maxBytes: process.env.AUDIT_LOG_MAX_BYTES,
        },
      },
      execution: {
        executionMode: normalizeExecutionMode(process.env.TOOL_EXECUTION_MODE),
        containerRuntimeEnabled: parseBoolean(process.env.CONTAINER_RUNTIME_ENABLED, false),
        backend: normalizeExecutionBackend(process.env.CONTAINER_RUNTIME_BACKEND),
        allowedImageRegistries: parseCsvOrUndefined(process.env.EXECUTION_ALLOWED_IMAGE_REGISTRIES),
        requireSignatureVerificationInProduction: parseBoolean(
          process.env.EXECUTION_REQUIRE_SIGNATURE_VERIFICATION_IN_PRODUCTION,
          true,
        ),
        externalNetworkName: process.env.EXECUTION_EXTERNAL_NETWORK_NAME,
        internalNetworkName: process.env.EXECUTION_INTERNAL_NETWORK_NAME,
        nonRootUser: process.env.EXECUTION_CONTAINER_NON_ROOT_USER,
        maxConcurrentContainersPerNode: parsePositiveInt(process.env.EXECUTION_MAX_CONCURRENT_CONTAINERS_PER_NODE, null),
        toolConcurrencyLimits: parseJsonObject(process.env.EXECUTION_TOOL_CONCURRENCY_LIMITS, {}),
        nodeMemoryHardCapMb: parsePositiveInt(process.env.EXECUTION_NODE_MEMORY_HARD_CAP_MB, null),
        nodeCpuHardCapShares: parsePositiveInt(process.env.EXECUTION_NODE_CPU_HARD_CAP_SHARES, null),
        egressAnomalyThresholdPerMinute: parsePositiveInt(process.env.EXECUTION_EGRESS_ANOMALY_THRESHOLD_PER_MINUTE, 100),
        configVersion: process.env.EXECUTION_CONFIG_VERSION || "",
        expectedExecutionConfigVersion: process.env.EXPECTED_EXECUTION_CONFIG_VERSION || "",
        rollingUpgradeWindowMinutes: parsePositiveInt(process.env.EXECUTION_ROLLING_UPGRADE_WINDOW_MINUTES, 0),
        rolloutWindowStartedAt: process.env.EXECUTION_ROLLOUT_WINDOW_STARTED_AT || "",
        allowedConfigHashesByVersion: parseJsonObject(process.env.EXECUTION_ALLOWED_CONFIG_HASHES_BY_VERSION, {}),
      },
      security: {
        executionQuotaPerHour: parsePositiveInt(process.env.EXECUTION_QUOTA_PER_HOUR, 0),
        executionBurstLimitPerMinute: parsePositiveInt(process.env.EXECUTION_BURST_LIMIT_PER_MINUTE, 0),
        quotaRedisUrl: process.env.EXECUTION_QUOTA_REDIS_URL || "",
        quotaRedisPrefix: process.env.EXECUTION_QUOTA_REDIS_PREFIX || "openclaw:quota",
      },
      observability: {
        thresholdScope: process.env.OBSERVABILITY_THRESHOLD_SCOPE || "node",
        alertThresholds: parseJsonObject(process.env.OBSERVABILITY_ALERT_THRESHOLDS, {}),
      },
    },
    tls: {
      enabled: parseBoolean(process.env.TLS_ENABLED, false),
      certPath: process.env.TLS_CERT_PATH,
      keyPath: process.env.TLS_KEY_PATH,
      mtlsEnabled: parseBoolean(process.env.MTLS_ENABLED, false),
      caPath: process.env.MTLS_CA_PATH,
    },
    requestSigning: {
      enabled: parseBoolean(process.env.REQUEST_SIGNING_ENABLED, false),
      secret: process.env.REQUEST_SIGNING_SECRET || "",
    },
    prometheusExporter: {
      enabled: parseBoolean(process.env.PROMETHEUS_EXPORTER_ENABLED, false),
    },
  });

  server.start().catch(() => {
    process.exit(1);
  });
}
