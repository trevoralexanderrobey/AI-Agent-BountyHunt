const crypto = require("node:crypto");

const SENSITIVE_KEY_PATTERN = /(token|secret|password|authorization|authheader|signature|privatekey|apikey|api_key|credential|cookie)/i;

function isPlainObject(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function normalizeString(value) {
  return typeof value === "string" ? value.trim() : "";
}

function parseBoolean(value, fallback = false) {
  if (typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    return value !== 0;
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

  function forward(level, args) {
    if (typeof source[level] === "function") {
      source[level](...args);
      return;
    }

    if (typeof source.log !== "function") {
      return;
    }

    const first = args.length > 0 ? args[0] : null;
    if (isPlainObject(first)) {
      source.log({
        ...first,
        status:
          typeof first.status === "string"
            ? first.status
            : level === "error"
            ? "failure"
            : "success",
      });
      return;
    }

    source.log({
      event: "secret_manager_log",
      principal_id: "system",
      slug: "",
      request_id: "",
      status: level === "error" ? "failure" : "success",
      details: {
        level,
        message: normalizeString(first),
      },
    });
  }

  return {
    info: (...args) => {
      try {
        forward("info", args);
      } catch {}
    },
    error: (...args) => {
      try {
        forward("error", args);
      } catch {}
    },
  };
}

function hashKeyName(key) {
  return crypto.createHash("sha256").update(String(key || ""), "utf8").digest("hex").slice(0, 16);
}

function hashPrincipal(principalId) {
  return crypto
    .createHash("sha256")
    .update(normalizeString(principalId) || "anonymous", "utf8")
    .digest("hex")
    .slice(0, 16);
}

function isSensitiveKey(key) {
  return SENSITIVE_KEY_PATTERN.test(String(key || ""));
}

function shannonEntropy(text) {
  if (!text) {
    return 0;
  }
  const counts = new Map();
  for (const ch of text) {
    counts.set(ch, (counts.get(ch) || 0) + 1);
  }
  const length = text.length;
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function getSecretVariants(secret) {
  const raw = String(secret || "");
  if (!raw) {
    return [];
  }
  const base64 = Buffer.from(raw, "utf8").toString("base64");
  const base64Trimmed = base64.replace(/=+$/g, "");
  const encoded = encodeURIComponent(raw);

  return Array.from(new Set([raw, base64, base64Trimmed, encoded].filter((item) => item.length >= 4)));
}

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function redactString(text, secrets) {
  let output = String(text || "");
  let redactionCount = 0;

  const variants = Array.from(
    new Set(
      secrets
        .filter((secret) => typeof secret === "string" && secret.length >= 4)
        .flatMap((secret) => getSecretVariants(secret)),
    ),
  ).sort((a, b) => b.length - a.length);

  for (const variant of variants) {
    if (!output.includes(variant)) {
      continue;
    }
    const regex = new RegExp(escapeRegExp(variant), "g");
    output = output.replace(regex, "[redacted]");
    redactionCount += 1;
  }

  const secretLengths = secrets
    .filter((secret) => typeof secret === "string" && secret.length >= 8)
    .map((secret) => secret.length);
  if (secretLengths.length > 0) {
    const minLen = Math.max(8, Math.min(...secretLengths));
    const maxLen = Math.min(512, Math.max(...secretLengths) + 8);
    const tokenPattern = new RegExp(`[A-Za-z0-9+/_=%-]{${minLen},${maxLen}}`, "g");
    const candidates = output.match(tokenPattern) || [];
    for (const token of candidates) {
      if (token.length < minLen || token.length > maxLen) {
        continue;
      }
      if (token === "[redacted]") {
        continue;
      }
      const entropy = shannonEntropy(token);
      if (entropy < 3.6) {
        continue;
      }
      const regex = new RegExp(escapeRegExp(token), "g");
      output = output.replace(regex, "[redacted]");
      redactionCount += 1;
    }
  }

  return {
    value: output,
    redactionCount,
  };
}

function redactPayload(value, secrets) {
  if (typeof value === "string") {
    return redactString(value, secrets);
  }

  if (Array.isArray(value)) {
    let redactionCount = 0;
    const output = value.map((item) => {
      const result = redactPayload(item, secrets);
      redactionCount += result.redactionCount;
      return result.value;
    });
    return { value: output, redactionCount };
  }

  if (isPlainObject(value)) {
    let redactionCount = 0;
    const output = {};
    for (const [key, entryValue] of Object.entries(value)) {
      const result = redactPayload(entryValue, secrets);
      output[key] = result.value;
      redactionCount += result.redactionCount;
    }
    return { value: output, redactionCount };
  }

  return { value, redactionCount: 0 };
}

function createSecretManager(options = {}) {
  const metrics = createSafeMetrics(options.metrics);
  const logger = createSafeLogger(options.logger);
  const production = parseBoolean(options.production, normalizeString(process.env.NODE_ENV).toLowerCase() === "production");
  const leakFailClosedInProduction = parseBoolean(options.leakFailClosedInProduction, true);

  const executionScopedSecrets = new Map();

  function registerExecutionSecretValues(executionId, values) {
    const normalizedExecutionId = normalizeString(executionId);
    if (!normalizedExecutionId) {
      return;
    }

    const normalizedValues = Array.from(
      new Set(
        (Array.isArray(values) ? values : [])
          .map((item) => (typeof item === "string" ? item : String(item ?? "")))
          .filter((item) => item.length > 0),
      ),
    );

    if (normalizedValues.length === 0) {
      return;
    }

    const buffers = normalizedValues.map((value) => Buffer.from(value, "utf8"));
    executionScopedSecrets.set(normalizedExecutionId, {
      values: normalizedValues,
      buffers,
    });
  }

  function getExecutionSecretValues(executionId, fallbackValues = []) {
    const normalizedExecutionId = normalizeString(executionId);
    const scoped = executionScopedSecrets.get(normalizedExecutionId);
    const scopedValues = scoped && Array.isArray(scoped.values) ? scoped.values : [];
    const fallback = Array.isArray(fallbackValues)
      ? fallbackValues.filter((item) => typeof item === "string" && item.length > 0)
      : [];
    return Array.from(new Set([...scopedValues, ...fallback]));
  }

  function finalizeExecutionSecrets(executionId) {
    const normalizedExecutionId = normalizeString(executionId);
    if (!normalizedExecutionId) {
      return {
        ok: true,
        released: false,
      };
    }

    const state = executionScopedSecrets.get(normalizedExecutionId);
    if (!state) {
      return {
        ok: true,
        released: false,
      };
    }

    if (Array.isArray(state.buffers)) {
      for (const buffer of state.buffers) {
        try {
          if (Buffer.isBuffer(buffer)) {
            buffer.fill(0);
          }
        } catch {}
      }
    }
    state.values = [];
    state.buffers = [];
    executionScopedSecrets.delete(normalizedExecutionId);

    return {
      ok: true,
      released: true,
    };
  }

  function prepareExecutionSecrets(runtimeSecrets, context = {}) {
    if (!isPlainObject(runtimeSecrets)) {
      return {
        env: {},
        secretValues: [],
        keyHashes: [],
      };
    }

    const env = {};
    const secretValues = [];
    const keyHashes = [];

    const toolSlug = normalizeString(context.toolSlug).toLowerCase() || "unknown";
    const principalHash = normalizeString(context.principalHash) || hashPrincipal(context.principalId);
    const executionId = normalizeString(context.executionId || context.requestId);

    for (const [key, rawValue] of Object.entries(runtimeSecrets)) {
      const normalizedKey = normalizeString(key);
      if (!normalizedKey) {
        continue;
      }

      const value = typeof rawValue === "string" ? rawValue : String(rawValue ?? "");
      if (value.length === 0) {
        continue;
      }

      const keyHash = hashKeyName(normalizedKey);
      keyHashes.push(keyHash);
      secretValues.push(value);
      env[normalizedKey] = value;

      metrics.increment("secret.access", {
        key_hash: keyHash,
        tool: toolSlug,
        principal_hash: principalHash || "anonymous",
      });
    }

    const uniqueValues = Array.from(new Set(secretValues));
    if (executionId) {
      registerExecutionSecretValues(executionId, uniqueValues);
    }
    metrics.increment("secret.injection", {
      tool: toolSlug,
      principal_hash: principalHash || "anonymous",
      secret_count: String(uniqueValues.length),
    });

    return {
      env,
      secretValues: uniqueValues,
      keyHashes,
    };
  }

  function redactEnvForLogs(rawEnv) {
    if (!isPlainObject(rawEnv)) {
      return {};
    }

    const output = {};
    for (const [key, value] of Object.entries(rawEnv)) {
      if (isSensitiveKey(key)) {
        output[`secret_${hashKeyName(key)}`] = "[redacted]";
        continue;
      }
      output[key] = typeof value === "string" ? value : String(value ?? "");
    }
    return output;
  }

  function sanitizeLogContext(context) {
    if (!isPlainObject(context)) {
      return {};
    }

    const output = {};
    const secretContextKeyHashes = [];
    for (const [key, value] of Object.entries(context)) {
      if (isSensitiveKey(key)) {
        secretContextKeyHashes.push(hashKeyName(key));
        continue;
      }
      output[key] = value;
    }
    if (secretContextKeyHashes.length > 0) {
      output.secret_context_key_hashes = secretContextKeyHashes.sort((a, b) => a.localeCompare(b));
    }
    return output;
  }

  function assertNoFilesystemSecretArtifacts(inputArtifacts, secretValues = []) {
    if (!Array.isArray(inputArtifacts) || inputArtifacts.length === 0) {
      return { ok: true };
    }

    const secrets = Array.isArray(secretValues)
      ? secretValues.filter((value) => typeof value === "string" && value.length > 0)
      : [];
    if (secrets.length === 0) {
      return { ok: true };
    }

    for (const artifact of inputArtifacts) {
      if (!isPlainObject(artifact)) {
        continue;
      }

      const kind = normalizeString(artifact.kind).toLowerCase();
      if (kind !== "inlinetext") {
        continue;
      }
      const contents = typeof artifact.contents === "string" ? artifact.contents : String(artifact.contents ?? "");
      for (const secret of secrets) {
        if (secret.length < 4) {
          continue;
        }
        if (contents.includes(secret)) {
          const error = new Error("Secret material must not be written to filesystem artifacts");
          error.code = "SECRET_FILESYSTEM_WRITE_FORBIDDEN";
          throw error;
        }
      }
    }

    return { ok: true };
  }

  function redactToolOutput(rawPayload, secretValues, context = {}) {
    const executionId = normalizeString(context.executionId || context.requestId);
    const toolSlug = normalizeString(context.toolSlug).toLowerCase() || "unknown";
    const principalHash = normalizeString(context.principalHash) || hashPrincipal(context.principalId);
    const secrets = getExecutionSecretValues(executionId, secretValues);

    if (secrets.length === 0) {
      return {
        payload: rawPayload,
        redacted: false,
        redactionCount: 0,
      };
    }

    const result = redactPayload(rawPayload, secrets);
    if (result.redactionCount > 0) {
      metrics.increment("secret.leak.detected", {
        tool: toolSlug,
        principal_hash: principalHash || "anonymous",
      });
      logger.info({
        event: "secret_leak_detected",
        principal_id: normalizeString(context.principalId) || "anonymous",
        slug: toolSlug,
        request_id: normalizeString(context.requestId || executionId),
        status: "failure",
        details: {
          redaction_count: result.redactionCount,
          context: sanitizeLogContext(context),
        },
      });
      if (production && leakFailClosedInProduction) {
        const error = new Error("Secret leak detected in tool output");
        error.code = "SECRET_LEAK_DETECTED";
        error.details = {
          redactionCount: result.redactionCount,
          tool: toolSlug,
        };
        throw error;
      }
    }

    return {
      payload: result.value,
      redacted: result.redactionCount > 0,
      redactionCount: result.redactionCount,
    };
  }

  return {
    isSensitiveKey,
    hashKeyName,
    prepareExecutionSecrets,
    registerExecutionSecretValues,
    getExecutionSecretValues,
    finalizeExecutionSecrets,
    redactEnvForLogs,
    assertNoFilesystemSecretArtifacts,
    redactToolOutput,
  };
}

module.exports = {
  SENSITIVE_KEY_PATTERN,
  createSecretManager,
};
