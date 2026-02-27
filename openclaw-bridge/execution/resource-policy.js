const RESOURCE_LIMIT_KEYS = Object.freeze([
  "cpuShares",
  "memoryLimitMb",
  "maxRuntimeSeconds",
  "maxOutputBytes",
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

const DEFAULT_RESOURCE_LIMITS = deepFreeze({
  cpuShares: 256,
  memoryLimitMb: 256,
  maxRuntimeSeconds: 30,
  maxOutputBytes: 5 * 1024 * 1024,
});

const TOOL_RESOURCE_POLICIES = deepFreeze({
  nmap: {
    cpuShares: 512,
    memoryLimitMb: 512,
    maxRuntimeSeconds: 60,
    maxOutputBytes: 10 * 1024 * 1024,
  },
});

function normalizeSlug(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function isStrictPositiveInteger(value) {
  return typeof value === "number" && Number.isFinite(value) && Number.isInteger(value) && value > 0;
}

function isPlainObject(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function cloneLimits(limits) {
  return {
    cpuShares: limits.cpuShares,
    memoryLimitMb: limits.memoryLimitMb,
    maxRuntimeSeconds: limits.maxRuntimeSeconds,
    maxOutputBytes: limits.maxOutputBytes,
  };
}

function makeError(code, message, details) {
  const error = new Error(String(message || "Invalid resource policy"));
  error.code = String(code || "RESOURCE_POLICY_INVALID");
  if (typeof details !== "undefined") {
    error.details = details;
  }
  return error;
}

function validateResourceLimitsObject(raw, options = {}) {
  const errors = [];
  const rejectUnknown = Object.prototype.hasOwnProperty.call(options, "rejectUnknown")
    ? Boolean(options.rejectUnknown)
    : true;
  const label = typeof options.label === "string" && options.label.trim() ? options.label.trim() : "resourceLimits";

  if (!isPlainObject(raw)) {
    return {
      valid: false,
      errors: [`${label} must be an object`],
      limits: null,
    };
  }

  if (rejectUnknown) {
    for (const key of Object.keys(raw)) {
      if (!RESOURCE_LIMIT_KEYS.includes(key)) {
        errors.push(`${label} contains unknown field '${key}'`);
      }
    }
  }

  const limits = {};
  for (const key of RESOURCE_LIMIT_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(raw, key)) {
      errors.push(`${label}.${key} is required`);
      continue;
    }

    const value = raw[key];
    if (!isStrictPositiveInteger(value)) {
      errors.push(`${label}.${key} must be a positive integer number`);
      continue;
    }

    limits[key] = value;
  }

  if (errors.length > 0) {
    return {
      valid: false,
      errors,
      limits: null,
    };
  }

  return {
    valid: true,
    errors: [],
    limits: cloneLimits(limits),
  };
}

function resolveResourceLimits(toolSlug, options = {}) {
  const slug = normalizeSlug(toolSlug);
  const policySet = isPlainObject(options.policies) ? options.policies : TOOL_RESOURCE_POLICIES;
  const allowDefault = Object.prototype.hasOwnProperty.call(options, "allowDefault")
    ? Boolean(options.allowDefault)
    : true;

  const candidate = slug && Object.prototype.hasOwnProperty.call(policySet, slug) ? policySet[slug] : null;
  if (candidate) {
    const validation = validateResourceLimitsObject(candidate, {
      rejectUnknown: true,
      label: `resourcePolicies.${slug}`,
    });
    if (!validation.valid) {
      throw makeError("RESOURCE_POLICY_INVALID", "Resource policy is invalid", {
        toolSlug: slug,
        errors: validation.errors,
      });
    }
    return {
      ...validation.limits,
      source: slug,
      usedDefault: false,
    };
  }

  if (!allowDefault) {
    throw makeError("RESOURCE_POLICY_UNDEFINED", `Resource policy is undefined for tool '${slug || "unknown"}'`, {
      toolSlug: slug || "",
    });
  }

  const defaultValidation = validateResourceLimitsObject(DEFAULT_RESOURCE_LIMITS, {
    rejectUnknown: true,
    label: "defaultResourcePolicy",
  });
  if (!defaultValidation.valid) {
    throw makeError("RESOURCE_POLICY_INVALID", "Default resource policy is invalid", {
      errors: defaultValidation.errors,
    });
  }

  return {
    ...defaultValidation.limits,
    source: "default",
    usedDefault: true,
  };
}

module.exports = {
  DEFAULT_RESOURCE_LIMITS,
  TOOL_RESOURCE_POLICIES,
  RESOURCE_LIMIT_KEYS,
  validateResourceLimitsObject,
  resolveResourceLimits,
};
