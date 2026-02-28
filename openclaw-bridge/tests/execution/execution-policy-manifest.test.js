const test = require("node:test");
const assert = require("node:assert/strict");

const {
  validatePolicySchema,
  serializeCanonical,
  computePolicyHash,
} = require("../../policy/execution-policy-manifest.js");

function basePolicy(overrides = {}) {
  return {
    policyVersion: 10,
    executionMode: "container",
    containerRuntimeEnabled: true,
    resourceCaps: {
      curl: {
        cpuShares: 256,
        memoryLimitMb: 256,
        maxRuntimeSeconds: 30,
        maxOutputBytes: 1024 * 1024,
      },
    },
    perToolConcurrencyLimits: {
      curl: 4,
    },
    nodeConcurrencyCaps: {
      maxConcurrentContainersPerNode: 16,
      nodeMemoryHardCapMb: 8192,
      nodeCpuHardCapShares: 8192,
    },
    registryAllowlist: ["ghcr.io"],
    signatureEnforcement: {
      requireInProduction: true,
      requireInNonProduction: false,
    },
    quotaConfig: {
      executionQuotaPerHour: 120,
      executionBurstLimitPerMinute: 20,
      quotaRedisUrl: "redis://127.0.0.1:6379",
      quotaRedisPrefix: "openclaw:quota",
    },
    arbitrationThresholds: {
      arbiterRebuildFailClosed: true,
    },
    observabilityThresholds: {
      circuitOpenRate: 0.2,
      executionRejectRate: 0.15,
      memoryPressureRate: 0.1,
    },
    policy: {
      allowedUpgradeWindowMinutes: 15,
    },
    metadata: {
      allowDowngradeFromVersions: [],
      allowDowngradeFromHashes: [],
    },
    ...overrides,
  };
}

test("canonical serialization and hash are deterministic", () => {
  const policy = basePolicy();
  const canonicalA = serializeCanonical(policy);
  const canonicalB = serializeCanonical(JSON.parse(canonicalA));
  const hashA = computePolicyHash(policy);
  const hashB = computePolicyHash(JSON.parse(canonicalA));

  assert.equal(canonicalA, canonicalB);
  assert.equal(hashA, hashB);
});

test("policy hash changes when required field changes", () => {
  const policyA = basePolicy();
  const policyB = basePolicy({
    nodeConcurrencyCaps: {
      maxConcurrentContainersPerNode: 32,
      nodeMemoryHardCapMb: 8192,
      nodeCpuHardCapShares: 8192,
    },
  });

  assert.notEqual(computePolicyHash(policyA), computePolicyHash(policyB));
});

test("schema validation fails when required field is missing", () => {
  const policy = basePolicy();
  delete policy.signatureEnforcement;

  const validation = validatePolicySchema(policy);
  assert.equal(validation.valid, false);
  assert.equal(validation.errors.some((entry) => entry.includes("signatureEnforcement")), true);
});
