const test = require("node:test");
const assert = require("node:assert/strict");

const { createSupervisorV1 } = require("../../supervisor/supervisor-v1.js");
const { BaseToolAdapter } = require("../../tools/base-adapter.js");

class DummySupervisorAdapter extends BaseToolAdapter {
  constructor() {
    super({
      name: "dummy-supervisor",
      slug: "dummy-supervisor",
      description: "dummy supervisor adapter",
    });
  }

  async validateInput() {
    return { valid: true, errors: [] };
  }

  async executeImpl(input) {
    return {
      mode: "host",
      params: input.params,
    };
  }

  async normalizeOutput(rawOutput) {
    return rawOutput;
  }
}

function validSandboxConfig() {
  return {
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
  };
}

function validLimits() {
  return {
    cpuShares: 128,
    memoryLimitMb: 128,
    maxRuntimeSeconds: 15,
    maxOutputBytes: 65536,
  };
}

function createMockSpawnerFactory() {
  return () => ({
    initialize: async () => ({ ok: true }),
    spawnSkill: async () => ({
      ok: false,
      error: {
        code: "NOT_USED",
        message: "spawn not used in adapter execution tests",
      },
    }),
    terminateSkill: async () => ({ ok: true }),
  });
}

function createMockSecretAuthority(overrides = {}) {
  return {
    initialize: async () => ({ ok: true }),
    getExecutionSecrets: async () => ({
      env: {},
      executionSecretRef: { executionId: "mock" },
    }),
    releaseExecutionSecrets: () => ({ ok: true }),
    evaluatePeerSecretPosture: () => ({ ok: true, status: "aligned", criticalMismatches: [], warnings: [] }),
    getActiveMetadata: () => ({
      secretManifestHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    }),
    close: async () => {},
    ...overrides,
  };
}

test("supervisor returns container runtime disabled error when container mode is configured but flag is false", async () => {
  const supervisor = createSupervisorV1({
    spawnerFactory: createMockSpawnerFactory(),
    execution: {
      executionMode: "container",
      containerRuntimeEnabled: false,
      backend: "mock",
      tools: {
        "dummy-supervisor": {
          resourceLimits: validLimits(),
          signatureVerified: true,
        },
      },
      resourcePolicies: {
        "dummy-supervisor": {
          cpuShares: 256,
          memoryLimitMb: 256,
          maxRuntimeSeconds: 30,
          maxOutputBytes: 1024 * 1024,
        },
      },
      sandboxPolicies: {
        "dummy-supervisor": validSandboxConfig(),
      },
      egressPolicies: {
        "dummy-supervisor": {
          allowedExternalNetwork: false,
          allowedCIDR: [],
          rateLimitPerSecond: 1,
        },
      },
      imagePolicies: {
        "dummy-supervisor": {
          signatureVerified: true,
        },
      },
      images: {
        "dummy-supervisor": "ghcr.io/openclaw-bridge/dummy-supervisor@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      },
    },
    toolAdapters: [
      {
        slug: "dummy-supervisor",
        adapter: new DummySupervisorAdapter(),
      },
    ],
  });

  try {
    const result = await supervisor.execute("dummy-supervisor", "run", { x: 1 }, {});
    assert.equal(result.ok, false);
    assert.equal(result.error.code, "CONTAINER_RUNTIME_DISABLED");
  } finally {
    await supervisor.shutdown();
  }
});

test("supervisor delegates to container runtime when enabled and configured", async () => {
  const runtimeCalls = [];
  const supervisor = createSupervisorV1({
    spawnerFactory: createMockSpawnerFactory(),
    execution: {
      executionMode: "container",
      containerRuntimeEnabled: true,
      backend: "mock",
      tools: {
        "dummy-supervisor": {
          resourceLimits: validLimits(),
          signatureVerified: true,
        },
      },
      resourcePolicies: {
        "dummy-supervisor": {
          cpuShares: 256,
          memoryLimitMb: 256,
          maxRuntimeSeconds: 30,
          maxOutputBytes: 1024 * 1024,
        },
      },
      sandboxPolicies: {
        "dummy-supervisor": validSandboxConfig(),
      },
      egressPolicies: {
        "dummy-supervisor": {
          allowedExternalNetwork: false,
          allowedCIDR: [],
          rateLimitPerSecond: 1,
        },
      },
      imagePolicies: {
        "dummy-supervisor": {
          signatureVerified: true,
        },
      },
      images: {
        "dummy-supervisor": "ghcr.io/openclaw-bridge/dummy-supervisor@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      },
    },
    containerRuntime: {
      runContainer: async (payload) => {
        runtimeCalls.push(payload);
        return {
          delegated: true,
          paramsEcho: payload.inputArtifacts.length,
        };
      },
    },
    toolAdapters: [
      {
        slug: "dummy-supervisor",
        adapter: new DummySupervisorAdapter(),
      },
    ],
  });

  try {
    const result = await supervisor.execute("dummy-supervisor", "run", { x: 2 }, {});
    assert.equal(result.ok, true);
    assert.equal(result.result.delegated, true);
    assert.equal(runtimeCalls.length, 1);
    assert.equal(runtimeCalls[0].toolSlug, "dummy-supervisor");
  } finally {
    await supervisor.shutdown();
  }
});

test("supervisor acquires and releases arbiter leases around container execution", async () => {
  const calls = [];
  const releases = [];
  const supervisor = createSupervisorV1({
    spawnerFactory: createMockSpawnerFactory(),
    execution: {
      executionMode: "container",
      containerRuntimeEnabled: true,
      backend: "mock",
      maxConcurrentContainersPerNode: 4,
      toolConcurrencyLimits: {
        "dummy-supervisor": 2,
      },
      nodeMemoryHardCapMb: 4096,
      nodeCpuHardCapShares: 4096,
      configVersion: "v1",
      expectedExecutionConfigVersion: "v1",
      rollingUpgradeWindowMinutes: 15,
      rolloutWindowStartedAt: "2026-02-27T00:00:00.000Z",
      allowedConfigHashesByVersion: {
        v1: ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
      },
      tools: {
        "dummy-supervisor": {
          resourceLimits: validLimits(),
          signatureVerified: true,
        },
      },
      resourcePolicies: {
        "dummy-supervisor": {
          cpuShares: 256,
          memoryLimitMb: 256,
          maxRuntimeSeconds: 30,
          maxOutputBytes: 1024 * 1024,
        },
      },
      sandboxPolicies: {
        "dummy-supervisor": validSandboxConfig(),
      },
      egressPolicies: {
        "dummy-supervisor": {
          allowedExternalNetwork: false,
          allowedCIDR: [],
          rateLimitPerSecond: 1,
        },
      },
      imagePolicies: {
        "dummy-supervisor": {
          signatureVerified: true,
        },
      },
      images: {
        "dummy-supervisor": "ghcr.io/openclaw-bridge/dummy-supervisor@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
      },
    },
    security: {
      executionQuotaPerHour: 0,
      executionBurstLimitPerMinute: 0,
    },
    executionQuotaStore: {
      consume: async () => ({ ok: true, code: "OK", details: {} }),
      close: async () => {},
    },
    resourceArbiter: {
      tryAcquire: (input) => {
        calls.push(input);
        return { leaseId: `lease-${input.requestId}` };
      },
      release: (leaseId) => {
        releases.push(leaseId);
        return { ok: true, released: true };
      },
      reconstructFromActiveExecutions: async () => ({ ok: true }),
    },
    containerRuntime: {
      runContainer: async () => ({ delegated: true }),
    },
    toolAdapters: [
      {
        slug: "dummy-supervisor",
        adapter: new DummySupervisorAdapter(),
      },
    ],
  });

  try {
    const result = await supervisor.execute(
      "dummy-supervisor",
      "run",
      {
        resourceLimits: validLimits(),
      },
      { principalId: "user-a" },
    );
    assert.equal(result.ok, true);
    assert.equal(calls.length, 1);
    assert.equal(releases.length, 1);
  } finally {
    await supervisor.shutdown();
  }
});

test("supervisor fails closed in production when arbiter reconstruction fails at startup", async () => {
  const supervisor = createSupervisorV1({
    spawnerFactory: createMockSpawnerFactory(),
    execution: {
      executionMode: "container",
      containerRuntimeEnabled: true,
      backend: "mock",
      production: true,
    },
    executionQuotaStore: {
      consume: async () => ({ ok: true, code: "OK", details: {} }),
      close: async () => {},
    },
    resourceArbiter: {
      reconstructFromActiveExecutions: async () => ({
        ok: false,
        reason: "mock_rebuild_failure",
      }),
      tryAcquire: () => ({ leaseId: "unused" }),
      release: () => ({ ok: true, released: false }),
    },
    secretAuthority: createMockSecretAuthority(),
  });

  try {
    await assert.rejects(
      supervisor.initialize(),
      (error) => {
        assert.equal(error.code, "NODE_CAPACITY_EXCEEDED");
        return true;
      },
    );
  } finally {
    await supervisor.shutdown();
  }
});

test("secret injection occurs only after arbitration and before container runtime start", async () => {
  const order = [];
  const runtimeCalls = [];
  const supervisor = createSupervisorV1({
    spawnerFactory: createMockSpawnerFactory(),
    execution: {
      executionMode: "container",
      containerRuntimeEnabled: true,
      backend: "mock",
      tools: {
        "dummy-supervisor": {
          resourceLimits: validLimits(),
          signatureVerified: true,
        },
      },
      resourcePolicies: {
        "dummy-supervisor": {
          cpuShares: 256,
          memoryLimitMb: 256,
          maxRuntimeSeconds: 30,
          maxOutputBytes: 1024 * 1024,
        },
      },
      sandboxPolicies: {
        "dummy-supervisor": validSandboxConfig(),
      },
      egressPolicies: {
        "dummy-supervisor": {
          allowedExternalNetwork: false,
          allowedCIDR: [],
          rateLimitPerSecond: 1,
        },
      },
      imagePolicies: {
        "dummy-supervisor": {
          signatureVerified: true,
        },
      },
      images: {
        "dummy-supervisor": "ghcr.io/openclaw-bridge/dummy-supervisor@sha256:1212121212121212121212121212121212121212121212121212121212121212",
      },
    },
    resourceArbiter: {
      reconstructFromActiveExecutions: async () => ({ ok: true }),
      tryAcquire: (input) => {
        order.push(`arbiter:${input.requestId}`);
        return { leaseId: `lease-${input.requestId}` };
      },
      release: () => ({ ok: true, released: true }),
    },
    secretAuthority: createMockSecretAuthority({
      getExecutionSecrets: async ({ executionId }) => {
        order.push(`secret:${executionId}`);
        return {
          env: {
            OPENCLAW_API_TOKEN: "injected-value",
          },
          executionSecretRef: {
            executionId,
          },
        };
      },
      releaseExecutionSecrets: ({ executionId }) => {
        order.push(`release:${executionId}`);
        return { ok: true };
      },
    }),
    containerRuntime: {
      runContainer: async (payload) => {
        order.push(`runtime:${payload.requestId}`);
        runtimeCalls.push(payload);
        return { delegated: true };
      },
    },
    toolAdapters: [
      {
        slug: "dummy-supervisor",
        adapter: new DummySupervisorAdapter(),
      },
    ],
  });

  try {
    const result = await supervisor.execute(
      "dummy-supervisor",
      "run",
      {
        resourceLimits: validLimits(),
      },
      { principalId: "alice" },
    );

    assert.equal(result.ok, true);
    assert.equal(runtimeCalls.length, 1);
    assert.equal(runtimeCalls[0].env.OPENCLAW_API_TOKEN, "injected-value");
    const arbiterIndex = order.findIndex((entry) => entry.startsWith("arbiter:"));
    const secretIndex = order.findIndex((entry) => entry.startsWith("secret:"));
    const runtimeIndex = order.findIndex((entry) => entry.startsWith("runtime:"));
    assert.equal(arbiterIndex >= 0, true);
    assert.equal(secretIndex > arbiterIndex, true);
    assert.equal(runtimeIndex > secretIndex, true);
  } finally {
    await supervisor.shutdown();
  }
});

test("secret rotation applies to new executions while in-flight execution keeps its snapshot", async () => {
  let currentSecretValue = "token-v1";
  let runtimeCallCount = 0;
  const runtimePayloads = [];
  let notifyFirstRuntimeEntered = null;
  let releaseFirstRuntime = null;
  const firstRuntimeEntered = new Promise((resolve) => {
    notifyFirstRuntimeEntered = resolve;
  });
  const firstRuntimeGate = new Promise((resolve) => {
    releaseFirstRuntime = resolve;
  });

  const supervisor = createSupervisorV1({
    spawnerFactory: createMockSpawnerFactory(),
    execution: {
      executionMode: "container",
      containerRuntimeEnabled: true,
      backend: "mock",
      tools: {
        "dummy-supervisor": {
          resourceLimits: validLimits(),
          signatureVerified: true,
        },
      },
      resourcePolicies: {
        "dummy-supervisor": {
          cpuShares: 256,
          memoryLimitMb: 256,
          maxRuntimeSeconds: 30,
          maxOutputBytes: 1024 * 1024,
        },
      },
      sandboxPolicies: {
        "dummy-supervisor": validSandboxConfig(),
      },
      egressPolicies: {
        "dummy-supervisor": {
          allowedExternalNetwork: false,
          allowedCIDR: [],
          rateLimitPerSecond: 1,
        },
      },
      imagePolicies: {
        "dummy-supervisor": {
          signatureVerified: true,
        },
      },
      images: {
        "dummy-supervisor": "ghcr.io/openclaw-bridge/dummy-supervisor@sha256:5656565656565656565656565656565656565656565656565656565656565656",
      },
    },
    executionQuotaStore: {
      consume: async () => ({ ok: true, code: "OK", details: {} }),
      close: async () => {},
    },
    resourceArbiter: {
      reconstructFromActiveExecutions: async () => ({ ok: true }),
      tryAcquire: (input) => ({ leaseId: `lease-${input.requestId}` }),
      release: () => ({ ok: true, released: true }),
    },
    secretAuthority: createMockSecretAuthority({
      getExecutionSecrets: async ({ executionId }) => ({
        env: {
          OPENCLAW_API_TOKEN: currentSecretValue,
        },
        executionSecretRef: {
          executionId,
        },
      }),
    }),
    containerRuntime: {
      runContainer: async (payload) => {
        runtimeCallCount += 1;
        runtimePayloads.push(payload);
        if (runtimeCallCount === 1) {
          notifyFirstRuntimeEntered();
          await firstRuntimeGate;
        }
        return {
          delegated: true,
          tokenSeen: payload && payload.env ? payload.env.OPENCLAW_API_TOKEN : "",
        };
      },
    },
    toolAdapters: [
      {
        slug: "dummy-supervisor",
        adapter: new DummySupervisorAdapter(),
      },
    ],
  });

  try {
    const firstExecution = supervisor.execute(
      "dummy-supervisor",
      "run",
      {
        resourceLimits: validLimits(),
      },
      { principalId: "alice" },
    );

    await firstRuntimeEntered;
    currentSecretValue = "token-v2";
    releaseFirstRuntime();

    const firstResult = await firstExecution;
    assert.equal(firstResult.ok, true);
    assert.equal(runtimePayloads[0].env.OPENCLAW_API_TOKEN, "token-v1");

    const secondResult = await supervisor.execute(
      "dummy-supervisor",
      "run",
      {
        resourceLimits: validLimits(),
      },
      { principalId: "alice" },
    );

    assert.equal(secondResult.ok, true);
    assert.equal(runtimePayloads[1].env.OPENCLAW_API_TOKEN, "token-v2");
  } finally {
    await supervisor.shutdown();
  }
});

test("secret manifest mismatch blocks execution before runtime dispatch", async () => {
  let runtimeCalls = 0;
  const supervisor = createSupervisorV1({
    spawnerFactory: createMockSpawnerFactory(),
    execution: {
      executionMode: "container",
      containerRuntimeEnabled: true,
      backend: "mock",
      production: true,
      tools: {
        "dummy-supervisor": {
          resourceLimits: validLimits(),
          signatureVerified: true,
        },
      },
      resourcePolicies: {
        "dummy-supervisor": {
          cpuShares: 256,
          memoryLimitMb: 256,
          maxRuntimeSeconds: 30,
          maxOutputBytes: 1024 * 1024,
        },
      },
      sandboxPolicies: {
        "dummy-supervisor": validSandboxConfig(),
      },
      egressPolicies: {
        "dummy-supervisor": {
          allowedExternalNetwork: false,
          allowedCIDR: [],
          rateLimitPerSecond: 1,
        },
      },
      imagePolicies: {
        "dummy-supervisor": {
          signatureVerified: true,
        },
      },
      images: {
        "dummy-supervisor": "ghcr.io/openclaw-bridge/dummy-supervisor@sha256:3434343434343434343434343434343434343434343434343434343434343434",
      },
    },
    executionQuotaStore: {
      consume: async () => ({ ok: true, code: "OK", details: {} }),
      close: async () => {},
    },
    resourceArbiter: {
      reconstructFromActiveExecutions: async () => ({ ok: true }),
      tryAcquire: (input) => ({ leaseId: `lease-${input.requestId}` }),
      release: () => ({ ok: true, released: true }),
    },
    secretAuthority: createMockSecretAuthority({
      evaluatePeerSecretPosture: () => ({
        ok: false,
        status: "mismatch",
        criticalMismatches: [{ classification: "SECRET_MANIFEST_MISMATCH", peerId: "node-b" }],
        warnings: [],
      }),
    }),
    containerRuntime: {
      runContainer: async () => {
        runtimeCalls += 1;
        return { delegated: true };
      },
    },
    toolAdapters: [
      {
        slug: "dummy-supervisor",
        adapter: new DummySupervisorAdapter(),
      },
    ],
  });

  try {
    await assert.rejects(
      supervisor.execute(
        "dummy-supervisor",
        "run",
        {
          resourceLimits: validLimits(),
        },
        { principalId: "alice" },
      ),
      (error) => {
        assert.equal(error.code, "SECRET_MANIFEST_MISMATCH");
        return true;
      },
    );
    assert.equal(runtimeCalls, 0);
  } finally {
    await supervisor.shutdown();
  }
});

test("reconciliation mismatch blocks execution but does not block heartbeat", async () => {
  let heartbeatRunOnceCount = 0;
  let runtimeCalls = 0;
  const supervisor = createSupervisorV1({
    spawnerFactory: createMockSpawnerFactory(),
    federation: {
      enabled: true,
      heartbeat: {
        runOnce: async () => {
          heartbeatRunOnceCount += 1;
        },
        start: () => {},
        stop: () => {},
      },
    },
    execution: {
      executionMode: "container",
      containerRuntimeEnabled: true,
      backend: "mock",
      maxConcurrentContainersPerNode: 4,
      toolConcurrencyLimits: {
        "dummy-supervisor": 2,
      },
      nodeMemoryHardCapMb: 4096,
      nodeCpuHardCapShares: 4096,
      configVersion: "v1",
      expectedExecutionConfigVersion: "v1",
      rollingUpgradeWindowMinutes: 15,
      rolloutWindowStartedAt: "2026-02-27T00:00:00.000Z",
      allowedConfigHashesByVersion: {
        v1: ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
      },
      tools: {
        "dummy-supervisor": {
          resourceLimits: validLimits(),
          signatureVerified: true,
        },
      },
      resourcePolicies: {
        "dummy-supervisor": {
          cpuShares: 256,
          memoryLimitMb: 256,
          maxRuntimeSeconds: 30,
          maxOutputBytes: 1024 * 1024,
        },
      },
      sandboxPolicies: {
        "dummy-supervisor": validSandboxConfig(),
      },
      egressPolicies: {
        "dummy-supervisor": {
          allowedExternalNetwork: false,
          allowedCIDR: [],
          rateLimitPerSecond: 1,
        },
      },
      imagePolicies: {
        "dummy-supervisor": {
          signatureVerified: true,
        },
      },
      images: {
        "dummy-supervisor": "ghcr.io/openclaw-bridge/dummy-supervisor@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      },
    },
    executionQuotaStore: {
      consume: async () => ({ ok: true, code: "OK", details: {} }),
      close: async () => {},
    },
    resourceArbiter: {
      reconstructFromActiveExecutions: async () => ({ ok: true }),
      tryAcquire: (input) => ({ leaseId: `lease-${input.requestId}` }),
      release: () => ({ ok: true, released: true }),
    },
    executionConfigReconciler: {
      localMetadata: () => ({
        executionConfigHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        executionConfigVersion: "v1",
        expectedExecutionConfigVersion: "v1",
        nodeId: "node-a",
      }),
      evaluate: () => ({ ok: false, status: "mismatch", warnings: [], criticalMismatches: [] }),
      assertExecutionAllowed: () => {
        const error = new Error("mismatch");
        error.code = "EXECUTION_CONFIG_MISMATCH";
        throw error;
      },
      getLastSummary: () => ({ ok: false }),
    },
    containerRuntime: {
      runContainer: async () => {
        runtimeCalls += 1;
        return { delegated: true };
      },
    },
    toolAdapters: [
      {
        slug: "dummy-supervisor",
        adapter: new DummySupervisorAdapter(),
      },
    ],
  });

  try {
    await supervisor.initialize();
    assert.equal(heartbeatRunOnceCount > 0, true);

    await assert.rejects(
      supervisor.execute(
        "dummy-supervisor",
        "run",
        {
          resourceLimits: validLimits(),
        },
        { principalId: "user-a" },
      ),
      (error) => {
        assert.equal(error.code, "EXECUTION_CONFIG_MISMATCH");
        return true;
      },
    );
    assert.equal(runtimeCalls, 0);
  } finally {
    await supervisor.shutdown();
  }
});

test("supervisor surfaces centralized quota rejection before execution dispatch", async () => {
  let runtimeCalls = 0;
  const supervisor = createSupervisorV1({
    spawnerFactory: createMockSpawnerFactory(),
    execution: {
      executionMode: "container",
      containerRuntimeEnabled: true,
      backend: "mock",
      tools: {
        "dummy-supervisor": {
          resourceLimits: validLimits(),
          signatureVerified: true,
        },
      },
      resourcePolicies: {
        "dummy-supervisor": {
          cpuShares: 256,
          memoryLimitMb: 256,
          maxRuntimeSeconds: 30,
          maxOutputBytes: 1024 * 1024,
        },
      },
      sandboxPolicies: {
        "dummy-supervisor": validSandboxConfig(),
      },
      egressPolicies: {
        "dummy-supervisor": {
          allowedExternalNetwork: false,
          allowedCIDR: [],
          rateLimitPerSecond: 1,
        },
      },
      imagePolicies: {
        "dummy-supervisor": {
          signatureVerified: true,
        },
      },
      images: {
        "dummy-supervisor": "ghcr.io/openclaw-bridge/dummy-supervisor@sha256:abababababababababababababababababababababababababababababababab",
      },
    },
    executionQuotaStore: {
      consume: async () => ({
        ok: false,
        code: "EXECUTION_QUOTA_EXCEEDED",
        message: "quota blocked",
        details: {},
      }),
      close: async () => {},
    },
    containerRuntime: {
      runContainer: async () => {
        runtimeCalls += 1;
        return { delegated: true };
      },
    },
    toolAdapters: [
      {
        slug: "dummy-supervisor",
        adapter: new DummySupervisorAdapter(),
      },
    ],
  });

  try {
    await assert.rejects(
      supervisor.execute(
        "dummy-supervisor",
        "run",
        {
          resourceLimits: validLimits(),
        },
        { principalId: "user-a" },
      ),
      (error) => {
        assert.equal(error.code, "EXECUTION_QUOTA_EXCEEDED");
        return true;
      },
    );
    assert.equal(runtimeCalls, 0);
  } finally {
    await supervisor.shutdown();
  }
});
