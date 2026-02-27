const test = require("node:test");
const assert = require("node:assert/strict");

const { BaseToolAdapter } = require("../../tools/base-adapter.js");

class DummyAdapter extends BaseToolAdapter {
  constructor(config = {}) {
    super({
      name: "dummy",
      slug: "dummy-tool",
      description: "dummy adapter",
      ...config,
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

function validResourceLimits(overrides = {}) {
  return {
    cpuShares: 128,
    memoryLimitMb: 128,
    maxRuntimeSeconds: 15,
    maxOutputBytes: 65536,
    ...overrides,
  };
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

test("host mode remains functional", async () => {
  const adapter = new DummyAdapter();
  const result = await adapter.execute({
    params: { a: 1 },
    timeout: 1000,
    requestId: "req-host-1",
  });

  assert.equal(result.ok, true);
  assert.equal(result.result.mode, "host");
  assert.equal(result.metadata.requestId, "req-host-1");
});

test("container mode fails when runtime is disabled", async () => {
  const adapter = new DummyAdapter({
    executionMode: "container",
    containerRuntimeEnabled: false,
  });

  const result = await adapter.execute({
    params: {},
    timeout: 1000,
    requestId: "req-container-disabled",
    resourceLimits: validResourceLimits(),
  });

  assert.equal(result.ok, false);
  assert.equal(result.error.code, "CONTAINER_RUNTIME_DISABLED");
});

test("container mode fails when runtime is missing", async () => {
  const adapter = new DummyAdapter({
    executionMode: "container",
    containerRuntimeEnabled: true,
    resourcePolicies: {
      "dummy-tool": validResourceLimits(),
    },
  });

  const result = await adapter.execute({
    params: {},
    timeout: 1000,
    requestId: "req-container-missing-runtime",
    resourceLimits: validResourceLimits(),
  });

  assert.equal(result.ok, false);
  assert.equal(result.error.code, "CONTAINER_RUNTIME_REQUIRED");
});

test("container mode fails when explicit resourceLimits are missing", async () => {
  const adapter = new DummyAdapter({
    executionMode: "container",
    containerRuntimeEnabled: true,
    containerRuntime: {
      runContainer: async () => ({ ok: true }),
    },
  });

  const result = await adapter.execute({
    params: {},
    timeout: 1000,
    requestId: "req-container-missing-limits",
  });

  assert.equal(result.ok, false);
  assert.equal(result.error.code, "RESOURCE_LIMITS_REQUIRED");
});

test("container mode fails when resource policy is unresolved", async () => {
  const adapter = new DummyAdapter({
    executionMode: "container",
    containerRuntimeEnabled: true,
    containerRuntime: {
      runContainer: async () => ({ ok: true }),
    },
    resourcePolicies: {},
  });

  const result = await adapter.execute({
    params: {},
    timeout: 1000,
    requestId: "req-container-no-policy",
    resourceLimits: validResourceLimits(),
  });

  assert.equal(result.ok, false);
  assert.equal(result.error.code, "RESOURCE_POLICY_UNDEFINED");
});

test("container mode fails when requested limits exceed policy", async () => {
  const adapter = new DummyAdapter({
    executionMode: "container",
    containerRuntimeEnabled: true,
    containerRuntime: {
      runContainer: async () => ({ ok: true }),
    },
    resourcePolicies: {
      "dummy-tool": validResourceLimits(),
    },
  });

  const result = await adapter.execute({
    params: {},
    timeout: 1000,
    requestId: "req-container-over-policy",
    resourceLimits: validResourceLimits({ memoryLimitMb: 1024 }),
  });

  assert.equal(result.ok, false);
  assert.equal(result.error.code, "RESOURCE_LIMIT_EXCEEDED");
});

test("container mode delegates when limits are valid", async () => {
  const calls = [];
  const adapter = new DummyAdapter({
    executionMode: "container",
    containerRuntimeEnabled: true,
    containerRuntime: {
      runContainer: async (payload) => {
        calls.push(payload);
        return {
          delegated: true,
          image: payload.image,
        };
      },
    },
    resourcePolicies: {
      "dummy-tool": validResourceLimits(),
    },
    sandboxPolicies: {
      "dummy-tool": validSandboxConfig(),
    },
    imagePolicies: {
      "dummy-tool": {
        signatureVerified: true,
      },
    },
    containerImages: {
      "dummy-tool": "ghcr.io/openclaw-bridge/dummy-tool@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    },
  });

  const requestedLimits = validResourceLimits({
    cpuShares: 64,
    memoryLimitMb: 64,
    maxRuntimeSeconds: 10,
    maxOutputBytes: 1024,
  });

  const result = await adapter.execute({
    params: { hello: "world" },
    timeout: 1000,
    requestId: "req-container-valid",
    resourceLimits: requestedLimits,
  });

  assert.equal(result.ok, true);
  assert.equal(result.result.delegated, true);
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].resourceLimits, requestedLimits);
  assert.equal(calls[0].toolSlug, "dummy-tool");
});
