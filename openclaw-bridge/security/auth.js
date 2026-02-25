const crypto = require("node:crypto");

function makeAuthError(requestId) {
  const error = new Error("Authentication failed");
  error.code = "UNAUTHORIZED";
  if (requestId) {
    error.request_id = requestId;
    error.details = { request_id: requestId };
  }
  return error;
}

function readAuthHeader(requestContext) {
  if (!requestContext || typeof requestContext !== "object") {
    return "";
  }

  if (typeof requestContext.authHeader === "string") {
    return requestContext.authHeader.trim();
  }

  if (requestContext.authContext && typeof requestContext.authContext === "object" && typeof requestContext.authContext.authHeader === "string") {
    return requestContext.authContext.authHeader.trim();
  }

  return "";
}

function parseBearerToken(authHeader) {
  if (typeof authHeader !== "string" || authHeader.length === 0) {
    return "";
  }
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    return "";
  }
  return String(match[1] || "").trim();
}

function timingSafeEqualUtf8(left, right) {
  const leftBuffer = Buffer.from(String(left || ""), "utf8");
  const rightBuffer = Buffer.from(String(right || ""), "utf8");

  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  try {
    return crypto.timingSafeEqual(leftBuffer, rightBuffer);
  } catch {
    return false;
  }
}

function createAuthGuard(config = {}) {
  const enabled = Boolean(config && config.enabled);
  const mode = config && typeof config.mode === "string" ? config.mode : "bearer";
  const fallbackToken = config && typeof config.bearerToken === "string" ? config.bearerToken : "";

  function resolveExpectedToken() {
    if (typeof process.env.SUPERVISOR_AUTH_TOKEN === "string" && process.env.SUPERVISOR_AUTH_TOKEN.length > 0) {
      return process.env.SUPERVISOR_AUTH_TOKEN;
    }
    return fallbackToken;
  }

  function validate(requestContext = {}, requestId) {
    if (!enabled) {
      return { ok: true, authType: "disabled" };
    }

    if (mode !== "bearer") {
      throw makeAuthError(requestId);
    }

    const expectedToken = resolveExpectedToken();
    if (!expectedToken) {
      throw makeAuthError(requestId);
    }

    const authHeader = readAuthHeader(requestContext);
    const providedToken = parseBearerToken(authHeader);

    if (!providedToken || !timingSafeEqualUtf8(providedToken, expectedToken)) {
      throw makeAuthError(requestId);
    }

    return { ok: true, authType: "bearer" };
  }

  return {
    validate,
  };
}

module.exports = {
  createAuthGuard,
};
