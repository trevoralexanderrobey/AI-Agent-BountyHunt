const test = require("node:test");
const assert = require("node:assert/strict");

const pkg = require("../../package.json");
const { runPreflightValidation } = require("../../deployment/preflight-validator.js");

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

function baseProductionOptions(overrides = {}) {
  return {
    env: "production",
    cluster: { enabled: false },
    federation: { enabled: false },
    deployment: {
      softwareVersion: pkg.version,
      versionTargets: [pkg.version],
    },
    execution: {
      executionMode: "container",
      containerRuntimeEnabled: true,
      backend: "mock",
      tools: {
        curl: {
          signatureVerified: true,
        },
      },
      resourcePolicies: {
        curl: {
          cpuShares: 256,
          memoryLimitMb: 256,
          maxRuntimeSeconds: 30,
          maxOutputBytes: 1024 * 1024,
        },
      },
      sandboxPolicies: {
        curl: validSandboxConfig(),
      },
      egressPolicies: {
        curl: {
          allowedExternalNetwork: true,
          allowedCIDR: [],
          rateLimitPerSecond: 10,
        },
      },
      imagePolicies: {
        curl: {
          signatureVerified: true,
          requireSignatureVerification: true,
        },
      },
      images: {
        curl: "ghcr.io/openclaw-bridge/curl@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      },
      allowedImageRegistries: ["ghcr.io"],
    },
    ...overrides,
  };
}

function errorCodes(result) {
  return new Set((result.errors || []).map((entry) => entry.code));
}

function warningCodes(result) {
  return new Set((result.warnings || []).map((entry) => entry.code));
}

test("production container mode fails when runtime flag is disabled", async () => {
  const result = await runPreflightValidation(
    baseProductionOptions({
      execution: {
        ...baseProductionOptions().execution,
        containerRuntimeEnabled: false,
      },
    }),
  );

  assert.equal(errorCodes(result).has("CONTAINER_RUNTIME_DISABLED"), true);
});

test("production host mode warns but does not error from execution plane", async () => {
  const result = await runPreflightValidation(
    baseProductionOptions({
      execution: {
        executionMode: "host",
        containerRuntimeEnabled: false,
        backend: "mock",
      },
    }),
  );

  assert.equal(errorCodes(result).has("EXECUTION_CONTAINER_REQUIRED_PROD"), false);
  assert.equal(errorCodes(result).has("CONTAINER_RUNTIME_DISABLED"), false);
  assert.equal(warningCodes(result).has("HOST_EXECUTION_TRANSITIONAL_PROD"), true);
});

test("production container mode reports missing sandbox and egress policies", async () => {
  const result = await runPreflightValidation(
    baseProductionOptions({
      execution: {
        executionMode: "container",
        containerRuntimeEnabled: true,
        backend: "mock",
        tools: {
          curl: {
            signatureVerified: false,
          },
        },
        resourcePolicies: {
          curl: {
            cpuShares: 128,
            memoryLimitMb: 128,
            maxRuntimeSeconds: 15,
            maxOutputBytes: 65536,
          },
        },
        sandboxPolicies: {},
        egressPolicies: {},
        imagePolicies: {
          curl: {
            signatureVerified: false,
            requireSignatureVerification: true,
          },
        },
        images: {
          curl: "ghcr.io/openclaw-bridge/curl@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        },
      },
    }),
  );

  const codes = errorCodes(result);
  assert.equal(codes.has("SANDBOX_POLICY_MISSING"), true);
  assert.equal(codes.has("EGRESS_POLICY_UNDEFINED"), true);
  assert.equal(codes.has("IMAGE_POLICY_VIOLATION"), true);
});

test("production container mode fails for unknown tool slug with undefined resource policy", async () => {
  const result = await runPreflightValidation(
    baseProductionOptions({
      execution: {
        executionMode: "container",
        containerRuntimeEnabled: true,
        backend: "mock",
        tools: {
          "unknown-tool": {
            image: "ghcr.io/openclaw-bridge/unknown@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            signatureVerified: true,
          },
        },
        resourcePolicies: {},
        sandboxPolicies: {
          "unknown-tool": validSandboxConfig(),
        },
        egressPolicies: {
          "unknown-tool": {
            allowedExternalNetwork: false,
            allowedCIDR: [],
            rateLimitPerSecond: 1,
          },
        },
      },
    }),
  );

  const codes = errorCodes(result);
  assert.equal(codes.has("RESOURCE_POLICY_UNDEFINED"), true);
});

test("production container mode passes when execution policies are complete", async () => {
  const result = await runPreflightValidation(baseProductionOptions());
  assert.equal(result.ready_for_production, true);
  assert.equal((result.errors || []).length, 0);
});
