function createNoopMetrics() {
  return {
    increment: () => {},
    observe: () => {},
    gauge: () => {},
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
    observe: (...args) => {
      try {
        if (typeof source.observe === "function") {
          source.observe(...args);
        }
      } catch {}
    },
    gauge: (...args) => {
      try {
        if (typeof source.gauge === "function") {
          source.gauge(...args);
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
  const sensitive = /(token|secret|password|authorization|authheader|signature|privatekey|env|args|headers?|apikey|key)/i;
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
      tool: payload && payload.toolSlug ? String(payload.toolSlug) : "",
    });
  }

  function recordStop(payload) {
    const safe = payload && typeof payload === "object" ? payload : {};
    write("container.stop", safe);
    metrics.increment("tool.container.stop", {
      image: sanitizeImage(safe.image),
      tool: safe && safe.toolSlug ? String(safe.toolSlug) : "",
    });

    const durationMs =
      Number.isFinite(Number(safe.stopTime)) && Number.isFinite(Number(safe.startTime))
        ? Math.max(0, Number(safe.stopTime) - Number(safe.startTime))
        : 0;
    const memoryUsage = Number.isFinite(Number(safe.resourceUsage && safe.resourceUsage.memoryUsageBytes))
      ? Number(safe.resourceUsage.memoryUsageBytes)
      : 0;
    const cpuUsage = Number.isFinite(Number(safe.resourceUsage && safe.resourceUsage.cpuUsageNano))
      ? Number(safe.resourceUsage.cpuUsageNano)
      : 0;
    const exitCode = Number.isFinite(Number(safe.exitCode)) ? Number(safe.exitCode) : 0;

    metrics.observe("tool.container.duration", durationMs, {
      tool: safe && safe.toolSlug ? String(safe.toolSlug) : "",
    });
    metrics.observe("tool.container.memory_usage", Math.max(0, memoryUsage), {
      tool: safe && safe.toolSlug ? String(safe.toolSlug) : "",
    });
    metrics.observe("tool.container.cpu_usage", Math.max(0, cpuUsage), {
      tool: safe && safe.toolSlug ? String(safe.toolSlug) : "",
    });
    metrics.gauge("tool.container.exit_code", exitCode, {
      tool: safe && safe.toolSlug ? String(safe.toolSlug) : "",
    });
  }

  function recordCrash(payload) {
    write("container.crash", payload || {});
    metrics.increment("tool.container.crash", {
      image: sanitizeImage(payload && payload.image),
      tool: payload && payload.toolSlug ? String(payload.toolSlug) : "",
    });
  }

  function recordTimeout(payload) {
    write("container.timeout", payload || {});
    metrics.increment("tool.container.timeout", {
      image: sanitizeImage(payload && payload.image),
      tool: payload && payload.toolSlug ? String(payload.toolSlug) : "",
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
