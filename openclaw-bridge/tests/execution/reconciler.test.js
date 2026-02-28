const test = require("node:test");
const assert = require("node:assert/strict");

const { createExecutionConfigReconciler } = require("../../config/reconciler.js");

function baseExecution(overrides = {}) {
  return {
    executionMode: "container",
    containerRuntimeEnabled: true,
    backend: "docker",
    allowedImageRegistries: ["ghcr.io"],
    requireSignatureVerificationInProduction: true,
    externalNetworkName: "openclaw-execution-net",
    internalNetworkName: "openclaw-execution-internal",
    nonRootUser: "openclaw",
    maxConcurrentContainersPerNode: 16,
    nodeMemoryHardCapMb: 8192,
    nodeCpuHardCapShares: 8192,
    toolConcurrencyLimits: { nmap: 4 },
    resourcePolicies: {},
    sandboxPolicies: {},
    egressPolicies: {},
    imagePolicies: {},
    images: {},
    ...overrides,
  };
}

test("reconciler blocks production execution when expected version is missing", () => {
  const reconciler = createExecutionConfigReconciler({
    production: true,
    nodeId: "node-a",
    execution: baseExecution({
      configVersion: "v1",
      expectedExecutionConfigVersion: "",
      rollingUpgradeWindowMinutes: 15,
      rolloutWindowStartedAt: new Date().toISOString(),
      allowedConfigHashesByVersion: {},
    }),
  });

  assert.throws(
    () => reconciler.assertExecutionAllowed([]),
    (error) => {
      assert.equal(error.code, "EXECUTION_CONFIG_MISMATCH");
      return true;
    },
  );
});

test("reconciler allows known version mismatch during rolling window", () => {
  const nodeA = createExecutionConfigReconciler({
    production: true,
    nodeId: "node-a",
    execution: baseExecution({
      configVersion: "v1",
      expectedExecutionConfigVersion: "v2",
      rollingUpgradeWindowMinutes: 30,
      rolloutWindowStartedAt: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
      allowedConfigHashesByVersion: {
        v1: [],
        v2: [],
      },
    }),
  });
  const nodeB = createExecutionConfigReconciler({
    production: true,
    nodeId: "node-b",
    execution: baseExecution({
      configVersion: "v2",
      expectedExecutionConfigVersion: "v2",
      rollingUpgradeWindowMinutes: 30,
      rolloutWindowStartedAt: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
      allowedConfigHashesByVersion: {
        v1: [],
        v2: [],
      },
      maxConcurrentContainersPerNode: 24,
    }),
  });

  const hashA = nodeA.localMetadata().executionConfigHash;
  const hashB = nodeB.localMetadata().executionConfigHash;

  const reconciler = createExecutionConfigReconciler({
    production: true,
    nodeId: "node-a",
    execution: baseExecution({
      configVersion: "v1",
      expectedExecutionConfigVersion: "v2",
      rollingUpgradeWindowMinutes: 30,
      rolloutWindowStartedAt: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
      allowedConfigHashesByVersion: {
        v1: [hashA],
        v2: [hashB],
      },
    }),
  });

  const summary = reconciler.evaluate([
    {
      peerId: "node-b",
      status: "UP",
      executionConfigVersion: "v2",
      executionConfigHash: hashB,
    },
  ]);

  assert.equal(summary.ok, true);
  assert.equal(summary.warnings.length > 0, true);
});

test("reconciler blocks unknown hash/version mismatch in production", () => {
  const reconciler = createExecutionConfigReconciler({
    production: true,
    nodeId: "node-a",
    execution: baseExecution({
      configVersion: "v1",
      expectedExecutionConfigVersion: "v1",
      rollingUpgradeWindowMinutes: 5,
      rolloutWindowStartedAt: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
      allowedConfigHashesByVersion: {
        v1: ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
      },
    }),
  });

  assert.throws(
    () =>
      reconciler.assertExecutionAllowed([
        {
          peerId: "node-b",
          status: "UP",
          executionConfigVersion: "v2",
          executionConfigHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        },
      ]),
    (error) => {
      assert.equal(error.code, "EXECUTION_CONFIG_MISMATCH");
      return true;
    },
  );
});
