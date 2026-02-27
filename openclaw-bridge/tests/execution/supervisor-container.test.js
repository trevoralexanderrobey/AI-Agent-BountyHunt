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
