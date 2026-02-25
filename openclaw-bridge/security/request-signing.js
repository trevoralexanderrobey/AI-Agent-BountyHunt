const crypto = require("node:crypto");

function stableCanonicalize(value) {
  if (Array.isArray(value)) {
    return value.map((item) => stableCanonicalize(item));
  }
  if (value && typeof value === "object") {
    const ordered = {};
    for (const key of Object.keys(value).sort()) {
      ordered[key] = stableCanonicalize(value[key]);
    }
    return ordered;
  }
  return value;
}

function stableStringify(value) {
  return JSON.stringify(stableCanonicalize(value));
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

function toBuffer(value) {
  return Buffer.from(String(value || ""), "utf8");
}

function createRequestSigner(config = {}) {
  const enabled = parseBoolean(config.enabled, parseBoolean(process.env.REQUEST_SIGNING_ENABLED, false));
  const secret = (config.secret || process.env.REQUEST_SIGNING_SECRET || "").trim();

  function signPayload(payload) {
    if (!enabled) {
      return "";
    }
    if (!secret) {
      throw new Error("Request signing secret is not configured");
    }
    const canonicalPayload = stableStringify(payload);
    return crypto.createHmac("sha256", secret).update(canonicalPayload, "utf8").digest("base64");
  }

  function verifyPayload(payload, providedSignature) {
    if (!enabled) {
      return { ok: true };
    }
    if (!secret) {
      return {
        ok: false,
        code: "INVALID_SIGNATURE",
        message: "Request signature is not configured",
      };
    }
    if (typeof providedSignature !== "string" || providedSignature.trim().length === 0) {
      return {
        ok: false,
        code: "INVALID_SIGNATURE",
        message: "Missing request signature",
      };
    }

    let expected;
    try {
      expected = signPayload(payload);
    } catch {
      return {
        ok: false,
        code: "INVALID_SIGNATURE",
        message: "Invalid request signature",
      };
    }

    const expectedBuf = toBuffer(expected);
    const providedBuf = toBuffer(providedSignature.trim());
    if (expectedBuf.length !== providedBuf.length) {
      return {
        ok: false,
        code: "INVALID_SIGNATURE",
        message: "Invalid request signature",
      };
    }

    const valid = crypto.timingSafeEqual(expectedBuf, providedBuf);
    if (!valid) {
      return {
        ok: false,
        code: "INVALID_SIGNATURE",
        message: "Invalid request signature",
      };
    }

    return { ok: true };
  }

  function parseAndVerify(rawBody, providedSignature) {
    if (!enabled) {
      return {
        ok: true,
        payload: null,
      };
    }

    let payload;
    try {
      payload = rawBody && rawBody.length > 0 ? JSON.parse(rawBody) : {};
    } catch {
      return {
        ok: false,
        code: "INVALID_REQUEST",
        message: "Invalid JSON body",
      };
    }

    const verification = verifyPayload(payload, providedSignature);
    if (!verification.ok) {
      return verification;
    }

    return {
      ok: true,
      payload,
    };
  }

  return {
    enabled,
    ready: !enabled || Boolean(secret),
    signPayload,
    verifyPayload,
    parseAndVerify,
    stableStringify,
  };
}

module.exports = {
  createRequestSigner,
};
