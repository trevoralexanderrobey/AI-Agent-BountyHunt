const crypto = require("node:crypto");

const SENSITIVE_KEY_PATTERN = /(token|secret|password|authorization|authheader|signature|privatekey|apikey|api_key|credential|cookie)/i;

function isPlainObject(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function normalizeString(value) {
  return typeof value === "string" ? value.trim() : "";
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

function hashKeyName(key) {
  return crypto.createHash("sha256").update(String(key || ""), "utf8").digest("hex").slice(0, 16);
}

function isSensitiveKey(key) {
  return SENSITIVE_KEY_PATTERN.test(String(key || ""));
}

function redactString(text, secrets) {
  let output = String(text || "");
  let redactionCount = 0;

  for (const secret of secrets) {
    if (!secret || secret.length < 4) {
      continue;
    }
    if (!output.includes(secret)) {
      continue;
    }
    output = output.split(secret).join("[redacted]");
    redactionCount += 1;
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
        tool: normalizeString(context.toolSlug).toLowerCase() || "unknown",
        principal_hash: normalizeString(context.principalHash) || "anonymous",
      });
    }

    return {
      env,
      secretValues: Array.from(new Set(secretValues)),
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
    const secrets = Array.isArray(secretValues)
      ? secretValues.filter((value) => typeof value === "string" && value.length > 0)
      : [];
    if (secrets.length === 0) {
      return {
        payload: rawPayload,
        redacted: false,
        redactionCount: 0,
      };
    }

    const result = redactPayload(rawPayload, secrets);
    if (result.redactionCount > 0) {
      logger.info({
        event: "secret_output_redaction",
        tool: normalizeString(context.toolSlug).toLowerCase() || "unknown",
        request_id: normalizeString(context.requestId),
        redaction_count: result.redactionCount,
        context: sanitizeLogContext(context),
        timestamp: new Date().toISOString(),
      });
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
    redactEnvForLogs,
    assertNoFilesystemSecretArtifacts,
    redactToolOutput,
  };
}

module.exports = {
  SENSITIVE_KEY_PATTERN,
  createSecretManager,
};
