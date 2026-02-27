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

function sanitizeImage(image) {
  if (typeof image !== "string") {
    return "";
  }
  const trimmed = image.trim();
  if (!trimmed) {
    return "";
  }
  return trimmed.replace(/^([^/]+):([^/@]+)@/, "[redacted]@");
}

function sanitizeValue(key, value) {
  const sensitive = /(token|secret|password|authorization|authheader|signature|privatekey|env|args|headers?)/i;
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

function createContainerAudit(options = {}) {
  const metrics = createSafeMetrics(options.metrics);
  const logger = options.logger;

  function write(eventName, payload) {
    const safePayload = payload && typeof payload === "object" ? payload : {};

    const event = {
      event: eventName,
      containerId: typeof safePayload.containerId === "string" ? safePayload.containerId : "",
      image: sanitizeImage(safePayload.image),
      startTime: Number.isFinite(safePayload.startTime) ? safePayload.startTime : null,
      stopTime: Number.isFinite(safePayload.stopTime) ? safePayload.stopTime : null,
      exitCode: Number.isFinite(safePayload.exitCode) ? safePayload.exitCode : null,
      resourceUsage: sanitizeValue("resourceUsage", safePayload.resourceUsage || {}),
      executionArgs: Array.isArray(safePayload.args) ? "[redacted]" : undefined,
      env: safePayload.env ? "[redacted]" : undefined,
      authHeaders: safePayload.authHeaders ? "[redacted]" : undefined,
    };

    try {
      if (typeof logger === "function") {
        logger(event);
      } else if (logger && typeof logger.log === "function") {
        logger.log(event);
      }
    } catch {}
  }

  function recordStart(payload) {
    write("container.start", payload || {});
    metrics.increment("tool.container.start", {
      image: sanitizeImage(payload && payload.image),
    });
  }

  function recordStop(payload) {
    write("container.stop", payload || {});
    metrics.increment("tool.container.stop", {
      image: sanitizeImage(payload && payload.image),
    });
  }

  function recordCrash(payload) {
    write("container.crash", payload || {});
    metrics.increment("tool.container.crash", {
      image: sanitizeImage(payload && payload.image),
    });
  }

  function recordTimeout(payload) {
    write("container.timeout", payload || {});
    metrics.increment("tool.container.timeout", {
      image: sanitizeImage(payload && payload.image),
    });
  }

  return {
    recordStart,
    recordStop,
    recordCrash,
    recordTimeout,
  };
}

module.exports = {
  createContainerAudit,
};
