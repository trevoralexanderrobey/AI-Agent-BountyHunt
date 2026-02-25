const fs = require("node:fs");
const path = require("node:path");

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

function parsePositiveInt(value, fallback) {
  const parsed = Number.parseInt(String(value ?? "").trim(), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
}

function todayKey(date = new Date()) {
  return date.toISOString().slice(0, 10);
}

function sanitizeValue(key, value) {
  const sensitive = /(token|secret|password|authorization|authheader|signature|privatekey)/i;
  if (sensitive.test(String(key || ""))) {
    return "[redacted]";
  }
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeValue(key, item));
  }
  if (value && typeof value === "object") {
    const output = {};
    for (const childKey of Object.keys(value)) {
      output[childKey] = sanitizeValue(childKey, value[childKey]);
    }
    return output;
  }
  return value;
}

function createAuditLogger(config = {}) {
  const enabled = parseBoolean(config.enabled, true);
  const logPath = config.path || process.env.AUDIT_LOG_PATH || path.resolve(process.cwd(), "logs", "audit.log");
  const rotationPolicy = config.rotationPolicy && typeof config.rotationPolicy === "object" ? config.rotationPolicy : {};
  const rotateDaily = parseBoolean(rotationPolicy.daily, true);
  const maxBytes = parsePositiveInt(rotationPolicy.maxBytes, 100 * 1024 * 1024);
  const state = {
    currentDay: todayKey(),
  };

  function ensureDirectory() {
    const dir = path.dirname(logPath);
    fs.mkdirSync(dir, { recursive: true });
  }

  function rotateIfNeeded() {
    if (!enabled) {
      return;
    }
    ensureDirectory();
    const now = new Date();
    const shouldRotateByDay = rotateDaily && state.currentDay !== todayKey(now);
    const shouldRotateBySize = (() => {
      try {
        const stats = fs.statSync(logPath);
        return stats.size >= maxBytes;
      } catch {
        return false;
      }
    })();

    if (!shouldRotateByDay && !shouldRotateBySize) {
      return;
    }

    if (fs.existsSync(logPath)) {
      const stamp = now.toISOString().replace(/[:.]/g, "-");
      const rotatedPath = `${logPath}.${stamp}`;
      fs.renameSync(logPath, rotatedPath);
    }
    state.currentDay = todayKey(now);
  }

  function log(event) {
    if (!enabled || !event || typeof event !== "object") {
      return;
    }

    try {
      rotateIfNeeded();
      const normalized = {
        timestamp: new Date().toISOString(),
        event: typeof event.event === "string" ? event.event : "unknown",
        principal_id: typeof event.principal_id === "string" ? event.principal_id : "anonymous",
        slug: typeof event.slug === "string" ? event.slug : "",
        request_id: typeof event.request_id === "string" ? event.request_id : "",
        status: event.status === "failure" ? "failure" : "success",
        details: sanitizeValue("details", event.details || {}),
      };

      const line = `${JSON.stringify(normalized)}\n`;
      fs.appendFileSync(logPath, line, "utf8");
    } catch {}
  }

  return {
    enabled,
    path: logPath,
    log,
  };
}

module.exports = {
  createAuditLogger,
};
