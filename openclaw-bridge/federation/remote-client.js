const http = require("node:http");
const https = require("node:https");

const DEFAULT_TIMEOUT_MS = 30000;

function isPlainObject(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function normalizeTimeoutMs(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return DEFAULT_TIMEOUT_MS;
  }
  return Math.floor(parsed);
}

function extractReplayResult(parsed) {
  if (!isPlainObject(parsed)) {
    return { ok: false };
  }

  if (isPlainObject(parsed.data) && Object.prototype.hasOwnProperty.call(parsed.data, "result")) {
    return { ok: true, result: parsed.data.result };
  }

  if (Object.prototype.hasOwnProperty.call(parsed, "result")) {
    return { ok: true, result: parsed.result };
  }

  const error = isPlainObject(parsed.error) ? parsed.error : null;
  const details = error && isPlainObject(error.details) ? error.details : null;
  if (details) {
    if (Object.prototype.hasOwnProperty.call(details, "result")) {
      return { ok: true, result: details.result };
    }
    if (Object.prototype.hasOwnProperty.call(details, "replayResult")) {
      return { ok: true, result: details.replayResult };
    }
    if (Object.prototype.hasOwnProperty.call(details, "replay_result")) {
      return { ok: true, result: details.replay_result };
    }
  }

  if (error && Object.prototype.hasOwnProperty.call(error, "result")) {
    return { ok: true, result: error.result };
  }

  return { ok: false };
}

function makeFailure(code, message, details = undefined) {
  const error = {
    code,
    message,
  };
  if (typeof details !== "undefined") {
    error.details = details;
  }
  return {
    ok: false,
    error,
  };
}

function createRemoteExecutionClient(options = {}) {
  const timeoutMs = normalizeTimeoutMs(options.timeoutMs);

  async function executeRemote(peer, payload = {}) {
    if (!isPlainObject(peer)) {
      return makeFailure("INVALID_PEER", "peer must be an object");
    }

    const peerUrl = typeof peer.url === "string" ? peer.url.trim() : "";
    const authToken = typeof peer.authToken === "string" ? peer.authToken.trim() : "";
    const peerId = typeof peer.peerId === "string" ? peer.peerId : "";
    const principalId = typeof payload.principalId === "string" ? payload.principalId.trim() : "";

    if (!peerUrl) {
      return makeFailure("INVALID_PEER", "peer.url is required");
    }
    if (!authToken) {
      return makeFailure("INVALID_PEER", "peer.authToken is required");
    }

    let endpoint;
    try {
      endpoint = new URL("/api/v1/execute", peerUrl);
    } catch {
      return makeFailure("INVALID_PEER", "peer.url is invalid");
    }

    const requestBody = {
      slug: payload.slug,
      method: payload.method,
      params: isPlainObject(payload.params) ? payload.params : {},
    };

    if (typeof payload.idempotencyKey === "string" && payload.idempotencyKey.trim()) {
      requestBody.idempotencyKey = payload.idempotencyKey;
    }

    if (isPlainObject(payload.retryPolicy)) {
      requestBody.retryPolicy = payload.retryPolicy;
    }

    const requestId =
      typeof payload.request_id === "string"
        ? payload.request_id
        : typeof payload.requestId === "string"
        ? payload.requestId
        : "";

    if (requestId) {
      requestBody.request_id = requestId;
    }

    const body = JSON.stringify(requestBody);
    const transport = endpoint.protocol === "https:" ? https : http;
    const startedAt = Date.now();

    return await new Promise((resolve) => {
      let done = false;

      const finalize = (result) => {
        if (done) {
          return;
        }
        done = true;
        resolve(result);
      };

      const req = transport.request(
        {
          protocol: endpoint.protocol,
          hostname: endpoint.hostname,
          port: endpoint.port || (endpoint.protocol === "https:" ? 443 : 80),
          path: `${endpoint.pathname}${endpoint.search}`,
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${authToken}`,
            "content-length": Buffer.byteLength(body, "utf8"),
            ...(requestId ? { "x-request-id": requestId } : {}),
            ...(principalId ? { "x-principal-id": principalId } : {}),
          },
        },
        (res) => {
          let raw = "";

          res.setEncoding("utf8");
          res.on("data", (chunk) => {
            raw += chunk;
          });

          res.on("end", () => {
            const latencyMs = Date.now() - startedAt;
            let parsed;
            try {
              parsed = raw ? JSON.parse(raw) : {};
            } catch {
              finalize(
                makeFailure("REMOTE_INVALID_RESPONSE", "Remote response was not valid JSON", {
                  peerId,
                  statusCode: res.statusCode,
                  latencyMs,
                }),
              );
              return;
            }

            if (res.statusCode >= 200 && res.statusCode < 300) {
              finalize({
                ok: true,
                peerId,
                statusCode: res.statusCode,
                latencyMs,
                response: parsed,
              });
              return;
            }

            const remoteCode = parsed && parsed.error && typeof parsed.error.code === "string" ? parsed.error.code : "REMOTE_ERROR";
            const remoteMessage = parsed && parsed.error && typeof parsed.error.message === "string" ? parsed.error.message : `Remote returned HTTP ${res.statusCode}`;

            if (res.statusCode === 409 && remoteCode === "DUPLICATE_EXECUTION") {
              const replay = extractReplayResult(parsed);
              if (replay.ok) {
                finalize({
                  ok: true,
                  peerId,
                  statusCode: res.statusCode,
                  latencyMs,
                  replayed: true,
                  idempotentReplay: true,
                  response: {
                    ok: true,
                    data: {
                      result: replay.result,
                    },
                  },
                });
                return;
              }

              finalize(
                makeFailure("REMOTE_DUPLICATE_MISSING_RESULT", "Remote duplicate replay did not include a result payload", {
                  peerId,
                  statusCode: res.statusCode,
                  latencyMs,
                }),
              );
              return;
            }

            finalize(
              makeFailure(remoteCode, remoteMessage, {
                peerId,
                statusCode: res.statusCode,
                latencyMs,
              }),
            );
          });
        },
      );

      req.setTimeout(timeoutMs, () => {
        req.destroy(new Error("Remote transport timeout"));
      });

      req.on("error", (error) => {
        const latencyMs = Date.now() - startedAt;
        finalize(
          makeFailure("REMOTE_TRANSPORT_ERROR", "Remote transport failed", {
            peerId,
            latencyMs,
            message: error && typeof error.message === "string" ? error.message : "transport error",
          }),
        );
      });

      req.write(body);
      req.end();
    });
  }

  return {
    executeRemote,
  };
}

module.exports = {
  createRemoteExecutionClient,
};
