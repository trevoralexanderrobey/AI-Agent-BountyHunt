const test = require("node:test");
const assert = require("node:assert/strict");
const os = require("node:os");
const path = require("node:path");
const fs = require("node:fs");

const pkg = require("../../package.json");
const { runPreflightValidation } = require("../../deployment/preflight-validator.js");
const { computePolicyHash } = require("../../policy/execution-policy-manifest.js");
const { computeSecretManifestHash } = require("../../security/secret-manifest.js");
const { computeWorkloadManifestHash } = require("../../security/workload-manifest.js");

const POLICY_MANIFEST_PATH = path.resolve(__dirname, "../../policy/execution-policy.json");
const POLICY_SIGNATURE_PATH = path.resolve(__dirname, "../../policy/execution-policy.json.sig");
const POLICY_PUBLIC_KEY_PATH = path.resolve(__dirname, "../../policy/execution-policy.pub.pem");
const POLICY_EXPECTED_HASH = computePolicyHash(JSON.parse(fs.readFileSync(POLICY_MANIFEST_PATH, "utf8")));
const SECRET_MANIFEST_PATH = path.resolve(__dirname, "../../security/secret-manifest.json");
const SECRET_MANIFEST_EXPECTED_HASH = computeSecretManifestHash(JSON.parse(fs.readFileSync(SECRET_MANIFEST_PATH, "utf8")));
const WORKLOAD_MANIFEST_PATH = path.resolve(__dirname, "../../security/workload-manifest.json");
const WORKLOAD_MANIFEST_EXPECTED_HASH = computeWorkloadManifestHash(
  JSON.parse(fs.readFileSync(WORKLOAD_MANIFEST_PATH, "utf8")),
);
const ATTESTATION_REFERENCE_PATH = path.resolve(__dirname, "../../security/workload-attestation-reference.json");
const ATTESTATION_REFERENCE_HASH_PATH = path.resolve(__dirname, "../../security/workload-attestation-reference.hash");
const ATTESTATION_REFERENCE_EXPECTED_HASH = fs
  .readFileSync(ATTESTATION_REFERENCE_HASH_PATH, "utf8")
  .trim()
  .toLowerCase();
const BUILD_PROVENANCE_PATH = path.resolve(__dirname, "../../security/build-provenance.json");
const BUILD_PROVENANCE_HASH_PATH = path.resolve(__dirname, "../../security/build-provenance.hash");
const BUILD_PROVENANCE_PUBLIC_KEY_PATH = path.resolve(__dirname, "../../security/build-provenance.pub");
const BUILD_PROVENANCE_EXPECTED_HASH = fs.readFileSync(BUILD_PROVENANCE_HASH_PATH, "utf8").trim().toLowerCase();

function healthySecretStoreProvider() {
  return {
    ping: async () => true,
    fetchSecret: async () => ({ found: true, value: "secret-value" }),
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
      maxConcurrentContainersPerNode: 16,
      toolConcurrencyLimits: {
        curl: 4,
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
      policyManifestPath: POLICY_MANIFEST_PATH,
      policySignaturePath: POLICY_SIGNATURE_PATH,
      policyPublicKeyPath: POLICY_PUBLIC_KEY_PATH,
      policyExpectedHash: POLICY_EXPECTED_HASH,
      secretManifestPath: SECRET_MANIFEST_PATH,
      secretManifestExpectedHash: SECRET_MANIFEST_EXPECTED_HASH,
      workloadManifestPath: WORKLOAD_MANIFEST_PATH,
      workloadManifestExpectedHash: WORKLOAD_MANIFEST_EXPECTED_HASH,
      buildProvenancePath: BUILD_PROVENANCE_PATH,
      buildProvenanceHashPath: BUILD_PROVENANCE_HASH_PATH,
      buildProvenancePublicKeyPath: BUILD_PROVENANCE_PUBLIC_KEY_PATH,
      buildProvenanceExpectedHash: BUILD_PROVENANCE_EXPECTED_HASH,
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
    security: {
      executionQuotaPerHour: 120,
      executionBurstLimitPerMinute: 20,
      quotaRedisUrl: "redis://127.0.0.1:6379",
      quotaRedisPrefix: "openclaw:quota",
      secretStoreProvider: "redis",
      secretStoreProviderImpl: healthySecretStoreProvider(),
      secretStoreUrl: "redis://127.0.0.1:6379",
      secretStorePrefix: "openclaw:secrets",
      secretStoreConnectTimeoutMs: 3000,
      secretFetchTimeoutMs: 3000,
      secretFetchMaxAttempts: 2,
      allowEnvSecretFallbackNonProd: false,
    },
    observability: {
      thresholdScope: "node",
      alertThresholds: {
        circuitOpenRate: 0.2,
        executionRejectRate: 0.15,
        memoryPressureRate: 0.1,
      },
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
  assert.equal(errorCodes(result).has("EXECUTION_QUOTA_PER_HOUR_REQUIRED"), false);
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
  const previousMode = fs.statSync(WORKLOAD_MANIFEST_PATH).mode & 0o777;
  const previousAttestationMode = fs.statSync(ATTESTATION_REFERENCE_PATH).mode & 0o777;
  const previousAttestationHashMode = fs.statSync(ATTESTATION_REFERENCE_HASH_PATH).mode & 0o777;
  fs.chmodSync(WORKLOAD_MANIFEST_PATH, 0o444);
  fs.chmodSync(ATTESTATION_REFERENCE_PATH, 0o444);
  fs.chmodSync(ATTESTATION_REFERENCE_HASH_PATH, 0o444);
  try {
    const result = await runPreflightValidation(baseProductionOptions());
    assert.equal(result.ready_for_production, true);
    assert.equal((result.errors || []).length, 0);
  } finally {
    fs.chmodSync(WORKLOAD_MANIFEST_PATH, previousMode);
    fs.chmodSync(ATTESTATION_REFERENCE_PATH, previousAttestationMode);
    fs.chmodSync(ATTESTATION_REFERENCE_HASH_PATH, previousAttestationHashMode);
  }
});

test("production container mode fails when phase 21 governance settings are missing", async () => {
  const base = baseProductionOptions();
  const result = await runPreflightValidation(
    baseProductionOptions({
      execution: {
        ...base.execution,
        maxConcurrentContainersPerNode: undefined,
        toolConcurrencyLimits: undefined,
        nodeMemoryHardCapMb: undefined,
        nodeCpuHardCapShares: undefined,
        expectedExecutionConfigVersion: "",
      },
      security: {
        executionQuotaPerHour: 0,
        executionBurstLimitPerMinute: 0,
        quotaRedisUrl: "",
      },
      observability: {
        thresholdScope: "cluster",
        alertThresholds: {
          circuitOpenRate: -1,
          executionRejectRate: -1,
          memoryPressureRate: -1,
        },
      },
    }),
  );

  const codes = errorCodes(result);
  assert.equal(codes.has("EXECUTION_NODE_CONCURRENCY_CAP_REQUIRED"), true);
  assert.equal(codes.has("EXECUTION_TOOL_CONCURRENCY_LIMITS_INVALID"), true);
  assert.equal(codes.has("EXECUTION_NODE_MEMORY_CAP_REQUIRED"), true);
  assert.equal(codes.has("EXECUTION_NODE_CPU_CAP_REQUIRED"), true);
  assert.equal(codes.has("EXPECTED_EXECUTION_CONFIG_VERSION_REQUIRED"), true);
  assert.equal(codes.has("EXECUTION_QUOTA_PER_HOUR_REQUIRED"), true);
  assert.equal(codes.has("EXECUTION_BURST_LIMIT_PER_MINUTE_REQUIRED"), true);
  assert.equal(codes.has("EXECUTION_QUOTA_REDIS_URL_REQUIRED"), true);
  assert.equal(codes.has("OBSERVABILITY_THRESHOLD_SCOPE_INVALID"), true);
  assert.equal(codes.has("OBSERVABILITY_ALERT_THRESHOLDS_INVALID"), true);
});

test("production container mode fails when signature path is overridden", async () => {
  const result = await runPreflightValidation(
    baseProductionOptions({
      execution: {
        ...baseProductionOptions().execution,
        policySignaturePath: path.resolve(__dirname, "../../policy/does-not-exist.sig"),
      },
    }),
  );

  const codes = errorCodes(result);
  assert.equal(codes.has("POLICY_PATH_OVERRIDE_FORBIDDEN"), true);
});

test("production container mode fails when policy artifact paths are overridden", async () => {
  const result = await runPreflightValidation(
    baseProductionOptions({
      execution: {
        ...baseProductionOptions().execution,
        policyManifestPath: path.resolve(__dirname, "./tmp-policy.json"),
      },
    }),
  );

  const codes = errorCodes(result);
  assert.equal(codes.has("POLICY_PATH_OVERRIDE_FORBIDDEN"), true);
});

test("production container mode fails when secret manifest path is overridden", async () => {
  const result = await runPreflightValidation(
    baseProductionOptions({
      execution: {
        ...baseProductionOptions().execution,
        secretManifestPath: path.resolve(__dirname, "./tmp-secret-manifest.json"),
      },
    }),
  );

  const codes = errorCodes(result);
  assert.equal(codes.has("SECRET_MANIFEST_PATH_OVERRIDE_FORBIDDEN"), true);
});

test("production container mode fails when secret store is unreachable", async () => {
  const result = await runPreflightValidation(
    baseProductionOptions({
      security: {
        ...baseProductionOptions().security,
        secretStoreProvider: "none",
        secretStoreProviderImpl: null,
      },
    }),
  );

  const codes = errorCodes(result);
  assert.equal(codes.has("SECRET_STORE_UNREACHABLE"), true);
});

test("production container mode fails when secret manifest hash does not match expected hash", async () => {
  const result = await runPreflightValidation(
    baseProductionOptions({
      execution: {
        ...baseProductionOptions().execution,
        secretManifestExpectedHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      },
    }),
  );

  const codes = errorCodes(result);
  assert.equal(codes.has("SECRET_MANIFEST_MISMATCH"), true);
});

test("production container mode fails when workload manifest path is overridden", async () => {
  const result = await runPreflightValidation(
    baseProductionOptions({
      execution: {
        ...baseProductionOptions().execution,
        workloadManifestPath: path.resolve(__dirname, "./tmp-workload-manifest.json"),
      },
    }),
  );

  const codes = errorCodes(result);
  assert.equal(codes.has("WORKLOAD_MANIFEST_PATH_OVERRIDE_FORBIDDEN"), true);
});

test("production container mode fails when attestation reference path is overridden", async () => {
  const result = await runPreflightValidation(
    baseProductionOptions({
      execution: {
        ...baseProductionOptions().execution,
        workloadAttestationReferencePath: path.resolve(__dirname, "./tmp-attestation-reference.json"),
      },
    }),
  );

  const codes = errorCodes(result);
  assert.equal(codes.has("WORKLOAD_ATTESTATION_REFERENCE_PATH_OVERRIDE_FORBIDDEN"), true);
});

test("production container mode fails when attestation expected hash is overridden", async () => {
  const result = await runPreflightValidation(
    baseProductionOptions({
      execution: {
        ...baseProductionOptions().execution,
        workloadAttestationReferenceExpectedHash: ATTESTATION_REFERENCE_EXPECTED_HASH,
      },
    }),
  );

  const codes = errorCodes(result);
  assert.equal(codes.has("WORKLOAD_ATTESTATION_REFERENCE_PATH_OVERRIDE_FORBIDDEN"), true);
});

test("production container mode fails when build provenance path is overridden", async () => {
  const result = await runPreflightValidation(
    baseProductionOptions({
      execution: {
        ...baseProductionOptions().execution,
        buildProvenancePath: path.resolve(__dirname, "./tmp-build-provenance.json"),
      },
    }),
  );

  const codes = errorCodes(result);
  assert.equal(codes.has("WORKLOAD_PROVENANCE_PATH_OVERRIDE_FORBIDDEN"), true);
});

test("production container mode fails when build provenance public key path is overridden", async () => {
  const result = await runPreflightValidation(
    baseProductionOptions({
      execution: {
        ...baseProductionOptions().execution,
        buildProvenancePublicKeyPath: path.resolve(__dirname, "./tmp-build-provenance.pub"),
      },
    }),
  );

  const codes = errorCodes(result);
  assert.equal(codes.has("WORKLOAD_PROVENANCE_KEY_PATH_OVERRIDE_FORBIDDEN"), true);
});

test("production container mode fails when inline build provenance public key override is present", async () => {
  const previousInline = process.env.WORKLOAD_PROVENANCE_PUBLIC_KEY;
  process.env.WORKLOAD_PROVENANCE_PUBLIC_KEY = "override-not-allowed";
  try {
    const result = await runPreflightValidation(baseProductionOptions());
    const codes = errorCodes(result);
    assert.equal(codes.has("WORKLOAD_PROVENANCE_KEY_OVERRIDE_FORBIDDEN"), true);
  } finally {
    if (typeof previousInline === "undefined") {
      delete process.env.WORKLOAD_PROVENANCE_PUBLIC_KEY;
    } else {
      process.env.WORKLOAD_PROVENANCE_PUBLIC_KEY = previousInline;
    }
  }
});

test("production container mode fails when workload manifest hash does not match expected hash", async () => {
  const result = await runPreflightValidation(
    baseProductionOptions({
      execution: {
        ...baseProductionOptions().execution,
        workloadManifestExpectedHash: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      },
    }),
  );

  const codes = errorCodes(result);
  assert.equal(codes.has("WORKLOAD_MANIFEST_MISMATCH"), true);
});

test("production container mode fails when workload manifest is missing", async () => {
  const missingPath = path.resolve(__dirname, "./missing-workload-manifest.json");
  try {
    fs.unlinkSync(missingPath);
  } catch {}

  const result = await runPreflightValidation(
    baseProductionOptions({
      execution: {
        ...baseProductionOptions().execution,
        workloadManifestPath: missingPath,
      },
    }),
  );

  const codes = errorCodes(result);
  assert.equal(codes.has("WORKLOAD_MANIFEST_MISSING"), true);
});

test("production container mode fails when workload manifest schema is invalid", async () => {
  const invalidManifestPath = path.join(
    fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-preflight-workload-invalid-")),
    "workload-manifest.json",
  );
  fs.writeFileSync(
    invalidManifestPath,
    `${JSON.stringify(
      {
        workloads: [
          {
            workloadID: "invalid.tool",
            adapterHash: "not-a-hash",
            entrypointHash: "also-not-a-hash",
            runtimeConfigHash: "nope",
            workloadVersion: 1,
            productionRequired: true,
          },
        ],
      },
      null,
      2,
    )}\n`,
    "utf8",
  );

  const result = await runPreflightValidation(
    baseProductionOptions({
      execution: {
        ...baseProductionOptions().execution,
        workloadManifestPath: invalidManifestPath,
        workloadManifestExpectedHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      },
    }),
  );

  const codes = errorCodes(result);
  assert.equal(codes.has("WORKLOAD_MANIFEST_SCHEMA_INVALID"), true);
});

test("production container mode rejects production workload entries without digest pinning", async () => {
  const invalidDigestManifestPath = path.join(
    fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-preflight-workload-digest-")),
    "workload-manifest.json",
  );
  const manifest = {
    workloads: [
      {
        workloadID: "prod.tool",
        adapterHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        entrypointHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        runtimeConfigHash: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        workloadVersion: 1,
        productionRequired: true,
      },
    ],
  };
  fs.writeFileSync(invalidDigestManifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");

  const result = await runPreflightValidation(
    baseProductionOptions({
      execution: {
        ...baseProductionOptions().execution,
        workloadManifestPath: invalidDigestManifestPath,
        workloadManifestExpectedHash: computeWorkloadManifestHash(manifest),
      },
    }),
  );

  const codes = errorCodes(result);
  assert.equal(codes.has("WORKLOAD_IMAGE_MISMATCH"), true);
});
