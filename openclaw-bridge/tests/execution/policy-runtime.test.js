const test = require("node:test");
const assert = require("node:assert/strict");

const { createPolicyRuntime } = require("../../policy/policy-runtime.js");

function makePolicy(version, hashSeed, allowedUpgradeWindowMinutes = 15, metadata = {}) {
  return {
    policyVersion: version,
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
      allowedUpgradeWindowMinutes,
    },
    metadata: {
      allowDowngradeFromVersions: [],
      allowDowngradeFromHashes: [],
      ...metadata,
    },
    __hashSeed: hashSeed,
  };
}

function makeBundle(version, hash, windowMinutes = 15, metadata = {}) {
  return {
    policy: makePolicy(version, hash, windowMinutes, metadata),
    policyVersion: version,
    policyHash: hash,
    signatureVerified: true,
    source: "test",
  };
}

test("policy runtime classifies hash mismatch and version skew", () => {
  const runtime = createPolicyRuntime({
    production: true,
    nodeId: "node-a",
  });

  runtime.activatePolicy(makeBundle(5, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0));

  const summary = runtime.evaluate([
    {
      peerId: "node-b",
      status: "UP",
      executionPolicyVersion: 5,
      executionPolicyHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    },
    {
      peerId: "node-c",
      status: "UP",
      executionPolicyVersion: 6,
      executionPolicyHash: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    },
  ]);

  assert.equal(summary.ok, false);
  assert.equal(summary.criticalMismatches.some((entry) => entry.classification === "HASH_MISMATCH_SAME_VERSION"), true);
  assert.equal(summary.criticalMismatches.some((entry) => entry.classification === "VERSION_SKEW"), true);
});

test("policy runtime allows version skew only during upgrade window", async () => {
  const runtime = createPolicyRuntime({
    production: true,
    nodeId: "node-a",
  });

  runtime.activatePolicy(makeBundle(10, "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", 1));

  const inWindow = runtime.evaluate([
    {
      peerId: "node-b",
      status: "UP",
      executionPolicyVersion: 11,
      executionPolicyHash: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    },
  ]);
  assert.equal(inWindow.ok, true);

  await new Promise((resolve) => setTimeout(resolve, 10));
  runtime.activatePolicy(makeBundle(10, "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", 0));

  const outOfWindow = runtime.evaluate([
    {
      peerId: "node-b",
      status: "UP",
      executionPolicyVersion: 11,
      executionPolicyHash: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    },
  ]);
  assert.equal(outOfWindow.ok, false);
});

test("in-flight policy snapshot remains stable across later activation", () => {
  const runtime = createPolicyRuntime({
    production: true,
    nodeId: "node-a",
  });

  runtime.activatePolicy(makeBundle(1, "1111111111111111111111111111111111111111111111111111111111111111", 15));
  const snapshotAtStart = runtime.captureExecutionSnapshot();

  runtime.activatePolicy(makeBundle(2, "2222222222222222222222222222222222222222222222222222222222222222", 15));
  const snapshotNow = runtime.captureExecutionSnapshot();

  assert.equal(snapshotAtStart.policyVersion, 1);
  assert.equal(snapshotNow.policyVersion, 2);
});
