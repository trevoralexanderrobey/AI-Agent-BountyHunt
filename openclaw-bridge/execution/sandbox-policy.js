const SANDBOX_POLICY_KEYS = Object.freeze([
  "runAsNonRoot",
  "dropCapabilities",
  "privileged",
  "hostPID",
  "hostNetwork",
  "hostMounts",
  "readOnlyRootFilesystem",
  "writableVolumes",
  "seccompProfile",
  "appArmorProfile",
]);

function deepFreeze(value) {
  if (!value || typeof value !== "object") {
    return value;
  }
  Object.freeze(value);
  for (const key of Object.keys(value)) {
    const child = value[key];
    if (child && typeof child === "object" && !Object.isFrozen(child)) {
      deepFreeze(child);
    }
  }
  return value;
}

const DEFAULT_SANDBOX_POLICY = deepFreeze({
  runAsNonRoot: true,
  dropCapabilities: ["ALL"],
  privileged: false,
  hostPID: false,
  hostNetwork: false,
  hostMounts: false,
  readOnlyRootFilesystem: true,
  writableVolumes: ["scratch"],
  seccompProfile: "runtime/default",
  appArmorProfile: "openclaw-default",
});

function isPlainObject(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function normalizeStringArray(value) {
  if (!Array.isArray(value)) {
    return null;
  }
  const normalized = [];
  for (const item of value) {
    if (typeof item !== "string" || item.trim().length === 0) {
      return null;
    }
    normalized.push(item.trim());
  }
  return normalized;
}

function validateSandboxConfig(config) {
  const errors = [];

  if (!isPlainObject(config)) {
    return {
      valid: false,
      errors: ["sandbox policy must be an object"],
      policy: null,
    };
  }

  for (const key of Object.keys(config)) {
    if (!SANDBOX_POLICY_KEYS.includes(key)) {
      errors.push(`sandbox policy contains unknown field '${key}'`);
    }
  }

  const missing = SANDBOX_POLICY_KEYS.filter((key) => !Object.prototype.hasOwnProperty.call(config, key));
  for (const key of missing) {
    errors.push(`sandbox policy field '${key}' is required`);
  }

  const dropCapabilities = normalizeStringArray(config.dropCapabilities);
  const writableVolumes = normalizeStringArray(config.writableVolumes);

  if (config.runAsNonRoot !== true) {
    errors.push("runAsNonRoot must be true");
  }
  if (config.privileged !== false) {
    errors.push("privileged must be false");
  }
  if (config.hostPID !== false) {
    errors.push("hostPID must be false");
  }
  if (config.hostNetwork !== false) {
    errors.push("hostNetwork must be false");
  }
  if (config.hostMounts !== false) {
    errors.push("hostMounts must be false");
  }
  if (config.readOnlyRootFilesystem !== true) {
    errors.push("readOnlyRootFilesystem must be true");
  }
  if (!dropCapabilities || dropCapabilities.length !== 1 || dropCapabilities[0] !== "ALL") {
    errors.push("dropCapabilities must contain exactly ['ALL']");
  }
  if (!writableVolumes || writableVolumes.length !== 1 || writableVolumes[0] !== "scratch") {
    errors.push("writableVolumes must contain exactly ['scratch']");
  }
  if (typeof config.seccompProfile !== "string" || config.seccompProfile.trim().length === 0) {
    errors.push("seccompProfile must be a non-empty string");
  }
  if (typeof config.appArmorProfile !== "string" || config.appArmorProfile.trim().length === 0) {
    errors.push("appArmorProfile must be a non-empty string");
  }

  if (errors.length > 0) {
    return {
      valid: false,
      errors,
      policy: null,
    };
  }

  return {
    valid: true,
    errors: [],
    policy: {
      runAsNonRoot: true,
      dropCapabilities,
      privileged: false,
      hostPID: false,
      hostNetwork: false,
      hostMounts: false,
      readOnlyRootFilesystem: true,
      writableVolumes,
      seccompProfile: config.seccompProfile.trim(),
      appArmorProfile: config.appArmorProfile.trim(),
    },
  };
}

module.exports = {
  DEFAULT_SANDBOX_POLICY,
  SANDBOX_POLICY_KEYS,
  validateSandboxConfig,
};
