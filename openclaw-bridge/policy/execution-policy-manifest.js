const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const REQUIRED_ROOT_KEYS = Object.freeze([
  "policyVersion",
  "executionMode",
  "containerRuntimeEnabled",
  "resourceCaps",
  "perToolConcurrencyLimits",
  "nodeConcurrencyCaps",
  "registryAllowlist",
  "signatureEnforcement",
  "quotaConfig",
  "arbitrationThresholds",
  "observabilityThresholds",
  "policy",
]);

const OPTIONAL_ROOT_KEYS = Object.freeze(["metadata"]);
const ALLOWED_ROOT_KEYS = Object.freeze([...REQUIRED_ROOT_KEYS, ...OPTIONAL_ROOT_KEYS]);

const REQUIRED_NODE_CONCURRENCY_KEYS = Object.freeze([
  "maxConcurrentContainersPerNode",
  "nodeMemoryHardCapMb",
  "nodeCpuHardCapShares",
]);

const REQUIRED_SIGNATURE_KEYS = Object.freeze([
  "requireInProduction",
  "requireInNonProduction",
]);

const REQUIRED_QUOTA_KEYS = Object.freeze([
  "executionQuotaPerHour",
  "executionBurstLimitPerMinute",
  "quotaRedisUrl",
  "quotaRedisPrefix",
]);

const REQUIRED_ARBITRATION_KEYS = Object.freeze(["arbiterRebuildFailClosed"]);
const REQUIRED_POLICY_KEYS = Object.freeze(["allowedUpgradeWindowMinutes"]);
const REQUIRED_OBSERVABILITY_KEYS = Object.freeze([
  "circuitOpenRate",
  "executionRejectRate",
  "memoryPressureRate",
]);
const ALLOWED_METADATA_KEYS = Object.freeze([
  "allowDowngradeFromVersions",
  "allowDowngradeFromHashes",
]);

function isPlainObject(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function normalizeString(value) {
  return typeof value === "string" ? value.trim() : "";
}

function isPositiveInteger(value) {
  return Number.isInteger(value) && value > 0;
}

function isNonNegativeInteger(value) {
  return Number.isInteger(value) && value >= 0;
}

function hasUnknownKeys(obj, allowedKeys) {
  const allowed = new Set(allowedKeys);
  return Object.keys(obj).filter((key) => !allowed.has(key));
}

function validateLimitsObject(rawLimits, fieldPath, errors) {
  if (!isPlainObject(rawLimits)) {
    errors.push(`${fieldPath} must be an object`);
    return;
  }

  const required = ["cpuShares", "memoryLimitMb", "maxRuntimeSeconds", "maxOutputBytes"];
  const unknown = hasUnknownKeys(rawLimits, required);
  if (unknown.length > 0) {
    errors.push(`${fieldPath} contains unknown keys: ${unknown.join(",")}`);
  }

  for (const key of required) {
    if (!Object.prototype.hasOwnProperty.call(rawLimits, key)) {
      errors.push(`${fieldPath}.${key} is required`);
      continue;
    }
    if (!isPositiveInteger(rawLimits[key])) {
      errors.push(`${fieldPath}.${key} must be a positive integer`);
    }
  }
}

function validateIntegerMap(rawMap, fieldPath, errors) {
  if (!isPlainObject(rawMap)) {
    errors.push(`${fieldPath} must be an object`);
    return;
  }
  if (Object.keys(rawMap).length === 0) {
    errors.push(`${fieldPath} must include at least one entry`);
  }

  for (const [rawKey, rawValue] of Object.entries(rawMap)) {
    const key = normalizeString(rawKey).toLowerCase();
    if (!key) {
      errors.push(`${fieldPath} contains an empty key`);
      continue;
    }
    if (!isPositiveInteger(rawValue)) {
      errors.push(`${fieldPath}.${key} must be a positive integer`);
    }
  }
}

function validateRate(rawValue, fieldPath, errors) {
  const parsed = Number(rawValue);
  if (!Number.isFinite(parsed) || parsed < 0) {
    errors.push(`${fieldPath} must be a non-negative number`);
  }
}

function validatePolicySchema(policy) {
  const errors = [];
  if (!isPlainObject(policy)) {
    return {
      valid: false,
      errors: ["policy must be an object"],
    };
  }

  for (const key of REQUIRED_ROOT_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(policy, key)) {
      errors.push(`missing required field '${key}'`);
    }
  }

  const rootUnknown = hasUnknownKeys(policy, ALLOWED_ROOT_KEYS);
  if (rootUnknown.length > 0) {
    errors.push(`unknown root fields: ${rootUnknown.join(",")}`);
  }

  if (!isPositiveInteger(policy.policyVersion)) {
    errors.push("policyVersion must be a positive integer");
  }

  if (!normalizeString(policy.executionMode)) {
    errors.push("executionMode must be a non-empty string");
  }

  if (typeof policy.containerRuntimeEnabled !== "boolean") {
    errors.push("containerRuntimeEnabled must be a boolean");
  }

  if (!isPlainObject(policy.resourceCaps)) {
    errors.push("resourceCaps must be an object");
  } else {
    if (Object.keys(policy.resourceCaps).length === 0) {
      errors.push("resourceCaps must include at least one tool policy");
    }
    for (const [rawSlug, rawLimits] of Object.entries(policy.resourceCaps)) {
      const slug = normalizeString(rawSlug).toLowerCase();
      if (!slug) {
        errors.push("resourceCaps contains an empty tool slug");
        continue;
      }
      validateLimitsObject(rawLimits, `resourceCaps.${slug}`, errors);
    }
  }

  validateIntegerMap(policy.perToolConcurrencyLimits, "perToolConcurrencyLimits", errors);

  if (!isPlainObject(policy.nodeConcurrencyCaps)) {
    errors.push("nodeConcurrencyCaps must be an object");
  } else {
    const unknown = hasUnknownKeys(policy.nodeConcurrencyCaps, REQUIRED_NODE_CONCURRENCY_KEYS);
    if (unknown.length > 0) {
      errors.push(`nodeConcurrencyCaps contains unknown keys: ${unknown.join(",")}`);
    }
    for (const key of REQUIRED_NODE_CONCURRENCY_KEYS) {
      if (!Object.prototype.hasOwnProperty.call(policy.nodeConcurrencyCaps, key)) {
        errors.push(`nodeConcurrencyCaps.${key} is required`);
        continue;
      }
      if (!isPositiveInteger(policy.nodeConcurrencyCaps[key])) {
        errors.push(`nodeConcurrencyCaps.${key} must be a positive integer`);
      }
    }
  }

  if (!Array.isArray(policy.registryAllowlist) || policy.registryAllowlist.length === 0) {
    errors.push("registryAllowlist must be a non-empty array");
  } else {
    for (const value of policy.registryAllowlist) {
      if (!normalizeString(value)) {
        errors.push("registryAllowlist entries must be non-empty strings");
      }
    }
  }

  if (!isPlainObject(policy.signatureEnforcement)) {
    errors.push("signatureEnforcement must be an object");
  } else {
    const unknown = hasUnknownKeys(policy.signatureEnforcement, REQUIRED_SIGNATURE_KEYS);
    if (unknown.length > 0) {
      errors.push(`signatureEnforcement contains unknown keys: ${unknown.join(",")}`);
    }
    for (const key of REQUIRED_SIGNATURE_KEYS) {
      if (!Object.prototype.hasOwnProperty.call(policy.signatureEnforcement, key)) {
        errors.push(`signatureEnforcement.${key} is required`);
        continue;
      }
      if (typeof policy.signatureEnforcement[key] !== "boolean") {
        errors.push(`signatureEnforcement.${key} must be a boolean`);
      }
    }
  }

  if (!isPlainObject(policy.quotaConfig)) {
    errors.push("quotaConfig must be an object");
  } else {
    const unknown = hasUnknownKeys(policy.quotaConfig, REQUIRED_QUOTA_KEYS);
    if (unknown.length > 0) {
      errors.push(`quotaConfig contains unknown keys: ${unknown.join(",")}`);
    }
    for (const key of REQUIRED_QUOTA_KEYS) {
      if (!Object.prototype.hasOwnProperty.call(policy.quotaConfig, key)) {
        errors.push(`quotaConfig.${key} is required`);
      }
    }

    if (Object.prototype.hasOwnProperty.call(policy.quotaConfig, "executionQuotaPerHour") && !isNonNegativeInteger(policy.quotaConfig.executionQuotaPerHour)) {
      errors.push("quotaConfig.executionQuotaPerHour must be a non-negative integer");
    }

    if (
      Object.prototype.hasOwnProperty.call(policy.quotaConfig, "executionBurstLimitPerMinute") &&
      !isNonNegativeInteger(policy.quotaConfig.executionBurstLimitPerMinute)
    ) {
      errors.push("quotaConfig.executionBurstLimitPerMinute must be a non-negative integer");
    }

    if (Object.prototype.hasOwnProperty.call(policy.quotaConfig, "quotaRedisUrl") && !normalizeString(policy.quotaConfig.quotaRedisUrl)) {
      errors.push("quotaConfig.quotaRedisUrl must be a non-empty string");
    }

    if (Object.prototype.hasOwnProperty.call(policy.quotaConfig, "quotaRedisPrefix") && !normalizeString(policy.quotaConfig.quotaRedisPrefix)) {
      errors.push("quotaConfig.quotaRedisPrefix must be a non-empty string");
    }
  }

  if (!isPlainObject(policy.arbitrationThresholds)) {
    errors.push("arbitrationThresholds must be an object");
  } else {
    const unknown = hasUnknownKeys(policy.arbitrationThresholds, REQUIRED_ARBITRATION_KEYS);
    if (unknown.length > 0) {
      errors.push(`arbitrationThresholds contains unknown keys: ${unknown.join(",")}`);
    }
    for (const key of REQUIRED_ARBITRATION_KEYS) {
      if (!Object.prototype.hasOwnProperty.call(policy.arbitrationThresholds, key)) {
        errors.push(`arbitrationThresholds.${key} is required`);
        continue;
      }
      if (typeof policy.arbitrationThresholds[key] !== "boolean") {
        errors.push(`arbitrationThresholds.${key} must be a boolean`);
      }
    }
  }

  if (!isPlainObject(policy.observabilityThresholds)) {
    errors.push("observabilityThresholds must be an object");
  } else {
    const unknown = hasUnknownKeys(policy.observabilityThresholds, REQUIRED_OBSERVABILITY_KEYS);
    if (unknown.length > 0) {
      errors.push(`observabilityThresholds contains unknown keys: ${unknown.join(",")}`);
    }
    for (const key of REQUIRED_OBSERVABILITY_KEYS) {
      if (!Object.prototype.hasOwnProperty.call(policy.observabilityThresholds, key)) {
        errors.push(`observabilityThresholds.${key} is required`);
        continue;
      }
      validateRate(policy.observabilityThresholds[key], `observabilityThresholds.${key}`, errors);
    }
  }

  if (!isPlainObject(policy.policy)) {
    errors.push("policy must be an object");
  } else {
    const unknown = hasUnknownKeys(policy.policy, REQUIRED_POLICY_KEYS);
    if (unknown.length > 0) {
      errors.push(`policy contains unknown keys: ${unknown.join(",")}`);
    }
    for (const key of REQUIRED_POLICY_KEYS) {
      if (!Object.prototype.hasOwnProperty.call(policy.policy, key)) {
        errors.push(`policy.${key} is required`);
        continue;
      }
      if (!isNonNegativeInteger(policy.policy[key])) {
        errors.push(`policy.${key} must be a non-negative integer`);
      }
    }
  }

  if (typeof policy.metadata !== "undefined") {
    if (!isPlainObject(policy.metadata)) {
      errors.push("metadata must be an object when provided");
    } else {
      const unknown = hasUnknownKeys(policy.metadata, ALLOWED_METADATA_KEYS);
      if (unknown.length > 0) {
        errors.push(`metadata contains unknown keys: ${unknown.join(",")}`);
      }

      if (Object.prototype.hasOwnProperty.call(policy.metadata, "allowDowngradeFromVersions")) {
        if (!Array.isArray(policy.metadata.allowDowngradeFromVersions)) {
          errors.push("metadata.allowDowngradeFromVersions must be an array");
        } else {
          for (const version of policy.metadata.allowDowngradeFromVersions) {
            if (!isPositiveInteger(version)) {
              errors.push("metadata.allowDowngradeFromVersions must contain positive integers");
              break;
            }
          }
        }
      }

      if (Object.prototype.hasOwnProperty.call(policy.metadata, "allowDowngradeFromHashes")) {
        if (!Array.isArray(policy.metadata.allowDowngradeFromHashes)) {
          errors.push("metadata.allowDowngradeFromHashes must be an array");
        } else {
          for (const hash of policy.metadata.allowDowngradeFromHashes) {
            const normalized = normalizeString(hash).toLowerCase();
            if (!/^[a-f0-9]{64}$/.test(normalized)) {
              errors.push("metadata.allowDowngradeFromHashes must contain sha256 hex strings");
              break;
            }
          }
        }
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

function stableSortArray(values) {
  return values
    .slice()
    .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
}

function canonicalize(value) {
  if (Array.isArray(value)) {
    return stableSortArray(value.map((item) => canonicalize(item)));
  }

  if (!isPlainObject(value)) {
    return value;
  }

  const ordered = {};
  for (const key of Object.keys(value).sort((a, b) => a.localeCompare(b))) {
    ordered[key] = canonicalize(value[key]);
  }
  return ordered;
}

function serializeCanonical(policy) {
  const validation = validatePolicySchema(policy);
  if (!validation.valid) {
    const error = new Error(`Policy schema validation failed: ${validation.errors.join("; ")}`);
    error.code = "POLICY_SCHEMA_INVALID";
    error.details = {
      errors: validation.errors,
    };
    throw error;
  }
  return JSON.stringify(canonicalize(policy));
}

function computePolicyHash(policy) {
  const canonicalJson = serializeCanonical(policy);
  return crypto.createHash("sha256").update(canonicalJson, "utf8").digest("hex");
}

function getCanonicalPolicy(options = {}) {
  let rawPolicy = null;
  if (isPlainObject(options.policy)) {
    rawPolicy = options.policy;
  } else {
    const manifestPath =
      normalizeString(options.manifestPath) ||
      normalizeString(process.env.EXECUTION_POLICY_MANIFEST_PATH) ||
      path.resolve(__dirname, "execution-policy.json");

    const fileContents = fs.readFileSync(manifestPath, "utf8");
    rawPolicy = JSON.parse(fileContents);
  }

  const canonicalJson = serializeCanonical(rawPolicy);
  return JSON.parse(canonicalJson);
}

module.exports = {
  validatePolicySchema,
  serializeCanonical,
  computePolicyHash,
  getCanonicalPolicy,
};
