const EGRESS_POLICY_KEYS = Object.freeze([
  "allowedExternalNetwork",
  "allowedCIDR",
  "rateLimitPerSecond",
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

const DEFAULT_EGRESS_POLICY = deepFreeze({
  allowedExternalNetwork: false,
  allowedCIDR: [],
  rateLimitPerSecond: 10,
});

const TOOL_EGRESS_POLICIES = deepFreeze({
  nmap: {
    allowedExternalNetwork: true,
    allowedCIDR: [],
    rateLimitPerSecond: 5,
  },
});

function normalizeSlug(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function isPlainObject(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function isPositiveInteger(value) {
  return typeof value === "number" && Number.isFinite(value) && Number.isInteger(value) && value > 0;
}

function isCidr(value) {
  if (typeof value !== "string" || value.trim().length === 0) {
    return false;
  }
  const normalized = value.trim();
  return /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(normalized);
}

function validatePolicyObject(policy, label) {
  const errors = [];

  if (!isPlainObject(policy)) {
    return { valid: false, errors: [`${label} must be an object`], policy: null };
  }

  for (const key of Object.keys(policy)) {
    if (!EGRESS_POLICY_KEYS.includes(key)) {
      errors.push(`${label} contains unknown field '${key}'`);
    }
  }

  for (const key of EGRESS_POLICY_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(policy, key)) {
      errors.push(`${label}.${key} is required`);
    }
  }

  if (typeof policy.allowedExternalNetwork !== "boolean") {
    errors.push(`${label}.allowedExternalNetwork must be a boolean`);
  }

  if (!Array.isArray(policy.allowedCIDR)) {
    errors.push(`${label}.allowedCIDR must be an array`);
  } else {
    for (const cidr of policy.allowedCIDR) {
      if (!isCidr(cidr)) {
        errors.push(`${label}.allowedCIDR entries must be CIDR strings`);
        break;
      }
    }
  }

  if (!isPositiveInteger(policy.rateLimitPerSecond)) {
    errors.push(`${label}.rateLimitPerSecond must be a positive integer number`);
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
      allowedExternalNetwork: policy.allowedExternalNetwork,
      allowedCIDR: policy.allowedCIDR.slice(),
      rateLimitPerSecond: policy.rateLimitPerSecond,
    },
  };
}

function validateEgressPolicy(toolSlug, policySet, options = {}) {
  const slug = normalizeSlug(toolSlug);
  const policies = isPlainObject(policySet) ? policySet : TOOL_EGRESS_POLICIES;
  const allowDefault = Object.prototype.hasOwnProperty.call(options, "allowDefault") ? Boolean(options.allowDefault) : true;

  const directPolicy = slug && Object.prototype.hasOwnProperty.call(policies, slug) ? policies[slug] : null;
  if (directPolicy) {
    const validation = validatePolicyObject(directPolicy, `egressPolicies.${slug}`);
    return {
      ...validation,
      usedDefault: false,
    };
  }

  if (!allowDefault) {
    return {
      valid: false,
      errors: [`Egress policy is undefined for tool '${slug || "unknown"}'`],
      policy: null,
      usedDefault: false,
    };
  }

  const defaultPolicy = Object.prototype.hasOwnProperty.call(policies, "default") ? policies.default : DEFAULT_EGRESS_POLICY;
  const validation = validatePolicyObject(defaultPolicy, "egressPolicies.default");
  return {
    ...validation,
    usedDefault: true,
  };
}

module.exports = {
  DEFAULT_EGRESS_POLICY,
  TOOL_EGRESS_POLICIES,
  EGRESS_POLICY_KEYS,
  validateEgressPolicy,
};
