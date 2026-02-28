const test = require("node:test");
const assert = require("node:assert/strict");

const { createContainerRuntime } = require("../../execution/container-runtime.js");

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

function validRunContainerPayload(overrides = {}) {
  return {
    image: "ghcr.io/openclaw-bridge/curl@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    args: [],
    env: {
      OPENCLAW_REQUEST_PATH: "/scratch/request.json",
    },
    resourceLimits: {
      cpuShares: 128,
      memoryLimitMb: 128,
      maxRuntimeSeconds: 10,
      maxOutputBytes: 65536,
    },
    toolSlug: "curl",
    sandboxConfig: validSandboxConfig(),
    signatureVerified: false,
    ...overrides,
  };
}

test("runtime rejects invalid backend without silent fallback", () => {
  assert.throws(
    () =>
      createContainerRuntime({
        backend: "invalid-backend",
      }),
    (error) => {
      assert.equal(error.code, "CONTAINER_BACKEND_INVALID");
      return true;
    },
  );
});

test("runtime enforces feature flag", async () => {
  const runtime = createContainerRuntime({
    backend: "mock",
    containerRuntimeEnabled: false,
    execution: {
      resourcePolicies: {
        curl: {
          cpuShares: 256,
          memoryLimitMb: 256,
          maxRuntimeSeconds: 30,
          maxOutputBytes: 1024 * 1024,
        },
      },
      egressPolicies: {
        curl: {
          allowedExternalNetwork: true,
          allowedCIDR: [],
          rateLimitPerSecond: 10,
        },
      },
    },
  });

  await assert.rejects(
    runtime.runContainer(validRunContainerPayload()),
    (error) => {
      assert.equal(error.code, "CONTAINER_RUNTIME_DISABLED");
      return true;
    },
  );
});

test("runtime rejects invalid payload keys", async () => {
  const runtime = createContainerRuntime({
    backend: "mock",
    containerRuntimeEnabled: true,
    execution: {
      resourcePolicies: {
        curl: {
          cpuShares: 256,
          memoryLimitMb: 256,
          maxRuntimeSeconds: 30,
          maxOutputBytes: 1024 * 1024,
        },
      },
      egressPolicies: {
        curl: {
          allowedExternalNetwork: true,
          allowedCIDR: [],
          rateLimitPerSecond: 10,
        },
      },
    },
  });

  await assert.rejects(
    runtime.runContainer({
      ...validRunContainerPayload(),
      unknownField: true,
    }),
    (error) => {
      assert.equal(error.code, "INVALID_CONTAINER_REQUEST");
      return true;
    },
  );
});

test("runtime rejects over-policy resource requests", async () => {
  const runtime = createContainerRuntime({
    backend: "mock",
    containerRuntimeEnabled: true,
    execution: {
      resourcePolicies: {
        curl: {
          cpuShares: 128,
          memoryLimitMb: 128,
          maxRuntimeSeconds: 10,
          maxOutputBytes: 65536,
        },
      },
      egressPolicies: {
        curl: {
          allowedExternalNetwork: true,
          allowedCIDR: [],
          rateLimitPerSecond: 10,
        },
      },
    },
  });

  await assert.rejects(
    runtime.runContainer(
      validRunContainerPayload({
        resourceLimits: {
          cpuShares: 512,
          memoryLimitMb: 128,
          maxRuntimeSeconds: 10,
          maxOutputBytes: 65536,
        },
      }),
    ),
    (error) => {
      assert.equal(error.code, "RESOURCE_LIMIT_EXCEEDED");
      return true;
    },
  );
});

test("runtime returns tool payload in mock backend when validation passes", async () => {
  const runtime = createContainerRuntime({
    backend: "mock",
    containerRuntimeEnabled: true,
    execution: {
      resourcePolicies: {
        curl: {
          cpuShares: 256,
          memoryLimitMb: 256,
          maxRuntimeSeconds: 30,
          maxOutputBytes: 1024 * 1024,
        },
      },
      egressPolicies: {
        curl: {
          allowedExternalNetwork: true,
          allowedCIDR: [],
          rateLimitPerSecond: 10,
        },
      },
      nonRootUser: "openclaw",
      allowedImageRegistries: ["ghcr.io"],
    },
  });

  const result = await runtime.runContainer(validRunContainerPayload());
  assert.equal(result.backend, "mock");
  assert.equal(result.toolSlug, "curl");
  assert.equal(result.mocked, true);

  const active = await runtime.listActiveExecutions();
  assert.equal(Array.isArray(active), true);
});
