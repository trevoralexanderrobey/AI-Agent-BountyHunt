const crypto = require("node:crypto");

const MAX_BODY_BYTES = 1024 * 1024;

function createNoopLogger() {
  return {
    info: () => {},
    error: () => {},
  };
}

function nowIso() {
  return new Date().toISOString();
}

function resolveRequestId(headerValue) {
  if (typeof headerValue === "string") {
    const trimmed = headerValue.trim();
    if (trimmed && trimmed.length <= 128) {
      return trimmed;
    }
  }
  if (typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return crypto.randomBytes(16).toString("hex");
}

function getApiVersion(rawHeader) {
  if (typeof rawHeader !== "string") {
    return "v1";
  }
  const version = rawHeader.trim().toLowerCase();
  return version || "v1";
}

function getBaseContentType(rawHeader) {
  if (typeof rawHeader !== "string") {
    return "";
  }
  return rawHeader.split(";")[0].trim().toLowerCase();
}

function isPlainObject(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function writeJson(res, statusCode, payload) {
  const body = JSON.stringify(payload);
  res.statusCode = statusCode;
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Content-Length", Buffer.byteLength(body, "utf8"));
  res.end(body);
}

function makeErrorEnvelope({ code, message, requestId, apiVersion }) {
  return {
    ok: false,
    error: {
      code,
      message,
      request_id: requestId,
    },
    api_version: apiVersion,
    timestamp: nowIso(),
  };
}

function validateExecutePayload(payload) {
  if (!isPlainObject(payload)) {
    return "Request body must be a JSON object";
  }

  if (typeof payload.slug !== "string" || payload.slug.trim().length === 0) {
    return "Field 'slug' must be a non-empty string";
  }

  if (typeof payload.method !== "string" || payload.method.trim().length === 0) {
    return "Field 'method' must be a non-empty string";
  }

  if (!Object.prototype.hasOwnProperty.call(payload, "params")) {
    return "Field 'params' is required";
  }

  if (!(payload.params === null || isPlainObject(payload.params))) {
    return "Field 'params' must be an object or null";
  }

  if (typeof payload.idempotencyKey !== "undefined") {
    if (typeof payload.idempotencyKey !== "string") {
      return "Field 'idempotencyKey' must be a string";
    }
    if (payload.idempotencyKey.length > 128) {
      return "Field 'idempotencyKey' must be <= 128 characters";
    }
  }

  if (typeof payload.retryPolicy !== "undefined") {
    if (!isPlainObject(payload.retryPolicy)) {
      return "Field 'retryPolicy' must be an object";
    }

    if (typeof payload.retryPolicy.retries !== "undefined") {
      const retries = Number(payload.retryPolicy.retries);
      if (!Number.isInteger(retries) || retries < 0 || retries > 10) {
        return "Field 'retryPolicy.retries' must be an integer between 0 and 10";
      }
    }

    if (typeof payload.retryPolicy.delayMs !== "undefined") {
      const delayMs = Number(payload.retryPolicy.delayMs);
      if (!Number.isFinite(delayMs) || delayMs < 0) {
        return "Field 'retryPolicy.delayMs' must be >= 0";
      }
    }

    if (typeof payload.retryPolicy.backoffFactor !== "undefined") {
      const backoffFactor = Number(payload.retryPolicy.backoffFactor);
      if (!Number.isFinite(backoffFactor) || backoffFactor < 1) {
        return "Field 'retryPolicy.backoffFactor' must be >= 1";
      }
    }
  }

  return null;
}

function mapSupervisorError(error) {
  const code = error && typeof error.code === "string" ? error.code : "INTERNAL_ERROR";
  if (code === "UNAUTHORIZED") {
    return { statusCode: 401, code: "UNAUTHORIZED", message: "Authentication failed" };
  }
  if (code === "UNAUTHORIZED_INTERNAL_BYPASS") {
    return { statusCode: 401, code: "UNAUTHORIZED_INTERNAL_BYPASS", message: "Internal bypass denied" };
  }
  if (code === "UNAUTHORIZED_TOOL") {
    return { statusCode: 403, code: "UNAUTHORIZED_TOOL", message: "Tool not exposed to caller role" };
  }
  if (code === "UNAUTHORIZED_ROLE") {
    return { statusCode: 403, code: "UNAUTHORIZED_ROLE", message: "Role is not authorized" };
  }
  if (code === "PATH_OUTSIDE_WORKSPACE") {
    return { statusCode: 403, code: "PATH_OUTSIDE_WORKSPACE", message: "Path outside workspace boundary" };
  }
  if (code === "TOKEN_FILE_PERMISSIONS_INVALID") {
    return { statusCode: 500, code: "TOKEN_FILE_PERMISSIONS_INVALID", message: "Token configuration is invalid" };
  }
  if (code === "INVALID_ARGUMENT") {
    return { statusCode: 400, code: "INVALID_ARGUMENT", message: "Tool arguments are invalid" };
  }
  if (code === "RATE_LIMIT_EXCEEDED") {
    return { statusCode: 429, code: "RATE_LIMIT_EXCEEDED", message: "Execution rate limit exceeded" };
  }
  if (code === "MAX_CONCURRENT_EXECUTIONS_EXCEEDED" || code === "SOURCE_CONCURRENCY_LIMIT_EXCEEDED") {
    return { statusCode: 429, code, message: "Execution concurrency limit exceeded" };
  }
  if (code === "UNAUTHENTICATED_EXECUTION") {
    return { statusCode: 401, code: "UNAUTHENTICATED_EXECUTION", message: "Execution requires authenticated identity" };
  }
  if (code === "SUPERVISOR_RATE_LIMIT_EXCEEDED") {
    return { statusCode: 429, code: "RATE_LIMIT_EXCEEDED", message: "Rate limit exceeded" };
  }
  if (code === "EXECUTION_RATE_LIMIT_EXCEEDED") {
    return { statusCode: 429, code: "EXECUTION_RATE_LIMIT_EXCEEDED", message: "Per-minute execution rate limit exceeded" };
  }
  if (code === "EXECUTION_QUOTA_EXCEEDED") {
    return { statusCode: 429, code: "EXECUTION_QUOTA_EXCEEDED", message: "Hourly execution quota exceeded" };
  }
  if (code === "CIRCUIT_BREAKER_OPEN") {
    return { statusCode: 503, code: "CIRCUIT_BREAKER_OPEN", message: "Skill circuit breaker is open" };
  }
  if (code === "NODE_CAPACITY_EXCEEDED") {
    return { statusCode: 503, code: "NODE_CAPACITY_EXCEEDED", message: "Node concurrency capacity exceeded" };
  }
  if (code === "TOOL_CONCURRENCY_LIMIT_EXCEEDED") {
    return { statusCode: 503, code: "TOOL_CONCURRENCY_LIMIT_EXCEEDED", message: "Tool concurrency limit exceeded" };
  }
  if (code === "NODE_MEMORY_PRESSURE_EXCEEDED") {
    return { statusCode: 503, code: "NODE_MEMORY_PRESSURE_EXCEEDED", message: "Node memory pressure exceeded" };
  }
  if (code === "NODE_CPU_SATURATION_EXCEEDED") {
    return { statusCode: 503, code: "NODE_CPU_SATURATION_EXCEEDED", message: "Node CPU saturation exceeded" };
  }
  if (code === "EXECUTION_CONFIG_MISMATCH") {
    return { statusCode: 503, code: "EXECUTION_CONFIG_MISMATCH", message: "Execution config mismatch across nodes" };
  }
  if (code === "SECRET_SCOPE_VIOLATION") {
    return { statusCode: 403, code: "SECRET_SCOPE_VIOLATION", message: "Secret scope violation" };
  }
  if (code === "SECRET_MANIFEST_MISMATCH") {
    return { statusCode: 503, code: "SECRET_MANIFEST_MISMATCH", message: "Secret manifest mismatch across nodes" };
  }
  if (code === "SECRET_LEAK_DETECTED") {
    return { statusCode: 503, code: "SECRET_LEAK_DETECTED", message: "Secret leak detected in tool output" };
  }
  if (
    code === "SECRET_AUTHORITY_UNINITIALIZED" ||
    code === "SECRET_STORE_UNREACHABLE" ||
    code === "SECRET_STORE_PROVIDER_INVALID" ||
    code === "SECRET_MANIFEST_MISSING" ||
    code === "SECRET_MANIFEST_INVALID" ||
    code === "SECRET_MANIFEST_SCHEMA_INVALID" ||
    code === "SECRET_MANIFEST_PATH_OVERRIDE_FORBIDDEN" ||
    code === "SECRET_FETCH_TIMEOUT" ||
    code === "REQUIRED_SECRET_UNAVAILABLE" ||
    code === "SECRET_FETCH_FAILURE"
  ) {
    return { statusCode: 503, code: "EXECUTION_CONFIG_MISMATCH", message: "Secret authority mismatch" };
  }
  if (
    code === "POLICY_SIGNATURE_INVALID" ||
    code === "POLICY_SCHEMA_INVALID" ||
    code === "POLICY_HASH_MISMATCH" ||
    code === "POLICY_FILE_NOT_PRESENT"
  ) {
    return { statusCode: 503, code: "EXECUTION_CONFIG_MISMATCH", message: "Execution policy authority mismatch" };
  }
  if (
    code === "WORKLOAD_NOT_VERIFIED" ||
    code === "WORKLOAD_HASH_MISMATCH" ||
    code === "WORKLOAD_IMAGE_MISMATCH" ||
    code === "WORKLOAD_MANIFEST_MISMATCH" ||
    code === "WORKLOAD_MUTATION_DETECTED" ||
    code === "WORKLOAD_MANIFEST_SCHEMA_INVALID" ||
    code === "WORKLOAD_MANIFEST_MISSING" ||
    code === "WORKLOAD_MANIFEST_PATH_OVERRIDE_FORBIDDEN" ||
    code === "WORKLOAD_MANIFEST_WRITABLE_IN_PRODUCTION"
  ) {
    return { statusCode: 503, code, message: "Execution integrity verification failed" };
  }
  if (code === "SUPERVISOR_CAPACITY_EXCEEDED") {
    return { statusCode: 503, code: "INTERNAL_ERROR", message: "Service capacity exceeded" };
  }
  if (code === "INVALID_SLUG" || code === "INVALID_METHOD" || code === "INVALID_REQUEST") {
    return { statusCode: 400, code: "INVALID_REQUEST", message: error.message || "Invalid request" };
  }
  return { statusCode: 500, code: "INTERNAL_ERROR", message: "Internal server error" };
}

function extractQueueLength(snapshot) {
  if (!snapshot || !Array.isArray(snapshot.gauges)) {
    return 0;
  }
  const found = snapshot.gauges.find((entry) => entry && entry.name === "supervisor.queue.length");
  if (!found || !Number.isFinite(Number(found.value))) {
    return 0;
  }
  return Number(found.value);
}

function mergeMetricSnapshots(a, b) {
  const counters = [...(Array.isArray(a.counters) ? a.counters : []), ...(Array.isArray(b.counters) ? b.counters : [])];
  const histograms = [...(Array.isArray(a.histograms) ? a.histograms : []), ...(Array.isArray(b.histograms) ? b.histograms : [])];
  const gauges = [...(Array.isArray(a.gauges) ? a.gauges : []), ...(Array.isArray(b.gauges) ? b.gauges : [])];

  const sorter = (left, right) => {
    const leftName = typeof left.name === "string" ? left.name : "";
    const rightName = typeof right.name === "string" ? right.name : "";
    if (leftName !== rightName) {
      return leftName.localeCompare(rightName);
    }
    return JSON.stringify(left.labels || {}).localeCompare(JSON.stringify(right.labels || {}));
  };

  counters.sort(sorter);
  histograms.sort(sorter);
  gauges.sort(sorter);

  return { counters, histograms, gauges };
}

function isBearerHeader(value) {
  return typeof value === "string" && /^Bearer\s+\S+/i.test(value.trim());
}

function parseBody(req, maxBodyBytes = MAX_BODY_BYTES) {
  return new Promise((resolve, reject) => {
    let raw = "";
    let bytes = 0;

    req.setEncoding("utf8");

    req.on("data", (chunk) => {
      bytes += Buffer.byteLength(chunk, "utf8");
      if (bytes > maxBodyBytes) {
        reject(new Error("BODY_TOO_LARGE"));
        req.destroy();
        return;
      }
      raw += chunk;
    });

    req.on("end", () => {
      resolve(raw);
    });

    req.on("error", (error) => {
      reject(error);
    });
  });
}

function createHttpHandlers(options = {}) {
  const supervisor = options.supervisor;
  const executionRouter =
    options.executionRouter && typeof options.executionRouter === "object" && typeof options.executionRouter.execute === "function"
      ? options.executionRouter
      : null;
  const workspaceRoot =
    typeof options.workspaceRoot === "string" && options.workspaceRoot.trim().length > 0
      ? options.workspaceRoot.trim()
      : process.env.BRIDGE_WORKSPACE_ROOT || process.cwd();
  const metrics = options.metrics;
  const logger = options.logger && typeof options.logger === "object" ? options.logger : createNoopLogger();
  const authEnabled = Boolean(options.authEnabled);
  const isShuttingDown = typeof options.isShuttingDown === "function" ? options.isShuttingDown : () => false;
  const maxBodyBytes = Number.isFinite(Number(options.maxBodyBytes)) ? Number(options.maxBodyBytes) : MAX_BODY_BYTES;

  async function handleExecute(req, res) {
    const apiVersion = getApiVersion(req.headers["x-api-version"]);
    const requestId = resolveRequestId(req.headers["x-request-id"]);
    const startedAt = Date.now();
    metrics.increment("http.requests.total", { route: "/api/v1/execute", method: "POST" });
    logger.info({
      event: "request_entry",
      route: "/api/v1/execute",
      method: "POST",
      request_id: requestId,
      timestamp: nowIso(),
    });

    try {
      if (isShuttingDown()) {
        metrics.increment("http.requests.error", { route: "/api/v1/execute", code: "SERVICE_UNAVAILABLE" });
        metrics.increment("http.errors_by_code", { code: "SERVICE_UNAVAILABLE" });
        writeJson(
          res,
          503,
          makeErrorEnvelope({
            code: "INTERNAL_ERROR",
            message: "Service unavailable",
            requestId,
            apiVersion,
          }),
        );
        return;
      }

      if (req.method !== "POST") {
        metrics.increment("http.requests.error", { route: "/api/v1/execute", code: "METHOD_NOT_ALLOWED" });
        metrics.increment("http.errors_by_code", { code: "METHOD_NOT_ALLOWED" });
        writeJson(
          res,
          405,
          makeErrorEnvelope({
            code: "INVALID_REQUEST",
            message: "Method not allowed",
            requestId,
            apiVersion,
          }),
        );
        return;
      }

      if (getBaseContentType(req.headers["content-type"]) !== "application/json") {
        metrics.increment("http.requests.error", { route: "/api/v1/execute", code: "UNSUPPORTED_MEDIA_TYPE" });
        metrics.increment("http.errors_by_code", { code: "UNSUPPORTED_MEDIA_TYPE" });
        writeJson(
          res,
          415,
          makeErrorEnvelope({
            code: "INVALID_REQUEST",
            message: "Content-Type must be application/json",
            requestId,
            apiVersion,
          }),
        );
        return;
      }

      const authHeader = typeof req.headers.authorization === "string" ? req.headers.authorization : "";
      const requireTransportAuth = !executionRouter && authEnabled;
      if (requireTransportAuth && !isBearerHeader(authHeader)) {
        logger.info({
          event: "execution_audit",
          decision: "deny",
          phase: "auth",
          reason: "missing_or_invalid_bearer",
          request_id: requestId,
          route: "/api/v1/execute",
          timestamp: nowIso(),
        });
        metrics.increment("http.requests.error", { route: "/api/v1/execute", code: "UNAUTHORIZED" });
        metrics.increment("http.errors_by_code", { code: "UNAUTHORIZED" });
        writeJson(
          res,
          401,
          makeErrorEnvelope({
            code: "UNAUTHORIZED",
            message: "Authentication failed",
            requestId,
            apiVersion,
          }),
        );
        return;
      }

      let parsed;
      try {
        const rawBody = await parseBody(req, maxBodyBytes);
        parsed = JSON.parse(rawBody || "{}");
      } catch (error) {
        const parseCode = error && error.message === "BODY_TOO_LARGE" ? "PAYLOAD_TOO_LARGE" : "INVALID_JSON";
        const statusCode = parseCode === "PAYLOAD_TOO_LARGE" ? 413 : 400;
        metrics.increment("http.requests.error", { route: "/api/v1/execute", code: parseCode });
        metrics.increment("http.errors_by_code", { code: parseCode });
        writeJson(
          res,
          statusCode,
          makeErrorEnvelope({
            code: "INVALID_REQUEST",
            message: "Invalid JSON body",
            requestId,
            apiVersion,
          }),
        );
        return;
      }

      const validationError = validateExecutePayload(parsed);
      if (validationError) {
        metrics.increment("http.requests.error", { route: "/api/v1/execute", code: "INVALID_REQUEST" });
        metrics.increment("http.errors_by_code", { code: "INVALID_REQUEST" });
        writeJson(
          res,
          400,
          makeErrorEnvelope({
            code: "INVALID_REQUEST",
            message: validationError,
            requestId,
            apiVersion,
          }),
        );
        return;
      }

      const principalHeader = req.headers["x-principal-id"];
      const principalId = typeof principalHeader === "string" ? principalHeader.trim() : "";
      if (!executionRouter && !principalId) {
        logger.info({
          event: "execution_audit",
          decision: "deny",
          phase: "identity",
          reason: "missing_principal_id",
          request_id: requestId,
          route: "/api/v1/execute",
          timestamp: nowIso(),
        });
        metrics.increment("http.requests.error", { route: "/api/v1/execute", code: "UNAUTHENTICATED_EXECUTION" });
        metrics.increment("http.errors_by_code", { code: "UNAUTHENTICATED_EXECUTION" });
        writeJson(
          res,
          401,
          makeErrorEnvelope({
            code: "UNAUTHENTICATED_EXECUTION",
            message: "Execution requires authenticated identity",
            requestId,
            apiVersion,
          }),
        );
        return;
      }

      const requestContext = {
        requestId,
        authHeader,
        principalId: principalId || "router-context",
      };
      if (typeof parsed.idempotencyKey === "string" && parsed.idempotencyKey.length > 0) {
        requestContext.idempotencyKey = parsed.idempotencyKey;
      }
      if (typeof parsed.retryPolicy === "object" && parsed.retryPolicy !== null) {
        requestContext.retryPolicy = parsed.retryPolicy;
      }

      let result;
      try {
        logger.info({
          event: "execution_audit",
          decision: "allow",
          phase: "authz",
          route: "/api/v1/execute",
          request_id: requestId,
          principal_id: principalId,
          slug: parsed.slug,
          method: parsed.method,
          timestamp: nowIso(),
        });
        if (executionRouter) {
          const tool = `${parsed.slug}.${parsed.method}`;
          const executionMetadata =
            supervisor && typeof supervisor.getExecutionMetadata === "function" ? supervisor.getExecutionMetadata() : {};
          const executionPeers =
            supervisor && typeof supervisor.getExecutionPeers === "function" ? supervisor.getExecutionPeers() : [];
          const execution = await executionRouter.execute(tool, isPlainObject(parsed.params) ? parsed.params : {}, {
            requestId,
            workspaceRoot,
            source: "http_api",
            caller: "http_api_execute",
            authHeader,
            trustedInProcessCaller: false,
            transportMetadata: {
              slug: parsed.slug,
              method: parsed.method,
              principalId,
              executionMetadata,
              peers: Array.isArray(executionPeers) ? executionPeers : [],
            },
            legacyExecute: async () => supervisor.execute(parsed.slug, parsed.method, parsed.params, requestContext),
          });

          if (!execution.ok) {
            const error = new Error(execution.message || execution.code || "Execution failed");
            error.code = execution.code || "INTERNAL_ERROR";
            error.request_id = requestId;
            throw error;
          }
          result = execution.data;
        } else {
          result = await supervisor.execute(parsed.slug, parsed.method, parsed.params, requestContext);
        }
      } catch (error) {
        const mapped = mapSupervisorError(error);
        metrics.increment("http.requests.error", { route: "/api/v1/execute", code: mapped.code });
        metrics.increment("http.errors_by_code", { code: mapped.code });
        const errorRequestId = error && typeof error.request_id === "string" ? error.request_id : requestId;
        logger.error({
          event: "request_error",
          route: "/api/v1/execute",
          status_code: mapped.statusCode,
          code: mapped.code,
          message: mapped.message,
          request_id: errorRequestId,
          duration_ms: Date.now() - startedAt,
          timestamp: nowIso(),
        });
        logger.info({
          event: "execution_audit",
          decision: "deny",
          phase: "execution",
          route: "/api/v1/execute",
          request_id: errorRequestId,
          principal_id: principalId,
          slug: parsed.slug,
          method: parsed.method,
          reason: mapped.code,
          timestamp: nowIso(),
        });
        writeJson(
          res,
          mapped.statusCode,
          makeErrorEnvelope({
            code: mapped.code,
            message: mapped.message,
            requestId: errorRequestId,
            apiVersion,
          }),
        );
        return;
      }

      metrics.increment("http.requests.success", { route: "/api/v1/execute" });
      logger.info({
        event: "execution_audit",
        decision: "allow",
        phase: "execution",
        route: "/api/v1/execute",
        request_id: requestId,
        principal_id: principalId,
        slug: parsed.slug,
        method: parsed.method,
        timestamp: nowIso(),
      });
      logger.info({
        event: "egress_audit",
        route: "/api/v1/execute",
        request_id: requestId,
        principal_id: principalId,
        slug: parsed.slug,
        method: parsed.method,
        timestamp: nowIso(),
      });
      writeJson(res, 200, {
        ok: true,
        data: {
          result,
          request_id: requestId,
        },
        api_version: apiVersion,
        timestamp: nowIso(),
      });
    } finally {
      metrics.observe("http.request.duration_ms", Date.now() - startedAt, { route: "/api/v1/execute" });
      logger.info({
        event: "response_exit",
        route: "/api/v1/execute",
        status_code: res.statusCode,
        duration_ms: Date.now() - startedAt,
        request_id: requestId,
        timestamp: nowIso(),
      });
    }
  }

  async function handleHealth(req, res) {
    if (req.method !== "GET") {
      writeJson(
        res,
        405,
        makeErrorEnvelope({
          code: "INVALID_REQUEST",
          message: "Method not allowed",
          requestId: resolveRequestId(req.headers["x-request-id"]),
          apiVersion: getApiVersion(req.headers["x-api-version"]),
        }),
      );
      return;
    }

    try {
      const status = await supervisor.getStatus();
      const supervisorMetrics = supervisor.getMetrics();
      const queueLength = extractQueueLength(supervisorMetrics);
      const activeInstances = Array.isArray(status.skills)
        ? status.skills.reduce((sum, skill) => sum + Number((skill && skill.counts && skill.counts.total) || 0), 0)
        : 0;
      const hasOpenCircuit = Array.isArray(supervisorMetrics.gauges)
        ? supervisorMetrics.gauges.some((entry) => entry && entry.name === "supervisor.circuit_breaker.state" && Number(entry.value) === 0)
        : false;
      const supervisorReady = Boolean(status && status.ok === true && status.isShuttingDown !== true);
      const healthState = supervisorReady && !hasOpenCircuit ? "healthy" : "degraded";
      const executionMetadata = status && status.executionMetadata && typeof status.executionMetadata === "object" ? status.executionMetadata : {};

      writeJson(res, 200, {
        status: healthState,
        timestamp: nowIso(),
        supervisor_ready: supervisorReady,
        queue_length: queueLength,
        active_instances: activeInstances,
        node_id: typeof executionMetadata.nodeId === "string" ? executionMetadata.nodeId : "node-unknown",
        scope: typeof executionMetadata.thresholdScope === "string" ? executionMetadata.thresholdScope : "node",
        execution_policy_hash:
          typeof executionMetadata.executionPolicyHash === "string" ? executionMetadata.executionPolicyHash : "",
        secret_manifest_hash:
          typeof executionMetadata.secretManifestHash === "string" ? executionMetadata.secretManifestHash : "",
        workload_manifest_hash:
          typeof executionMetadata.workloadManifestHash === "string" ? executionMetadata.workloadManifestHash : "",
        execution_policy_version:
          Number.isFinite(Number(executionMetadata.executionPolicyVersion)) && Number(executionMetadata.executionPolicyVersion) > 0
            ? Number(executionMetadata.executionPolicyVersion)
            : 0,
        execution_config_hash:
          typeof executionMetadata.executionConfigHash === "string" ? executionMetadata.executionConfigHash : "",
        execution_config_version:
          typeof executionMetadata.executionConfigVersion === "string" ? executionMetadata.executionConfigVersion : "",
        expected_execution_config_version:
          typeof executionMetadata.expectedExecutionConfigVersion === "string"
            ? executionMetadata.expectedExecutionConfigVersion
            : "",
      });
    } catch (error) {
      writeJson(res, 503, {
        status: "unhealthy",
        reason: error && typeof error.message === "string" ? error.message : "Supervisor status unavailable",
      });
    }
  }

  async function handleMetrics(req, res) {
    if (req.method !== "GET") {
      writeJson(
        res,
        405,
        makeErrorEnvelope({
          code: "INVALID_REQUEST",
          message: "Method not allowed",
          requestId: resolveRequestId(req.headers["x-request-id"]),
          apiVersion: getApiVersion(req.headers["x-api-version"]),
        }),
      );
      return;
    }

    const merged = mergeMetricSnapshots(supervisor.getMetrics(), metrics.snapshot());
    writeJson(res, 200, {
      metrics: merged,
      timestamp: nowIso(),
    });
  }

  async function handle(req, res) {
    const path = new URL(req.url || "/", "http://localhost").pathname;
    if (path === "/api/v1/execute") {
      await handleExecute(req, res);
      return;
    }
    if (path === "/health") {
      await handleHealth(req, res);
      return;
    }
    if (path === "/metrics") {
      await handleMetrics(req, res);
      return;
    }

    writeJson(
      res,
      404,
      makeErrorEnvelope({
        code: "INVALID_REQUEST",
        message: "Route not found",
        requestId: resolveRequestId(req.headers["x-request-id"]),
        apiVersion: getApiVersion(req.headers["x-api-version"]),
      }),
    );
  }

  return {
    handle,
  };
}

module.exports = {
  createHttpHandlers,
};
