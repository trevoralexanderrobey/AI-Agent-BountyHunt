const test = require("node:test");
const assert = require("node:assert/strict");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const { serializeCanonical, computePolicyHash } = require("../../policy/execution-policy-manifest.js");
const {
  loadAndPublishPolicy,
  getDefaultPolicyArtifactPaths,
  getActiveAuthorityState,
} = require("../../policy/policy-authority.js");

function basePolicy(overrides = {}) {
  return {
    policyVersion: 21,
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

function writeSignedPolicyBundle(dirPath, policy) {
  const manifestPath = path.join(dirPath, "execution-policy.json");
  const signaturePath = path.join(dirPath, "execution-policy.json.sig");
  const publicKeyPath = path.join(dirPath, "execution-policy.pub.pem");

  fs.writeFileSync(manifestPath, `${JSON.stringify(policy, null, 2)}\n`, "utf8");

  const canonical = serializeCanonical(policy);
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const signature = crypto.sign(null, Buffer.from(canonical, "utf8"), privateKey).toString("base64");

  fs.writeFileSync(signaturePath, `${signature}\n`, "utf8");
  fs.writeFileSync(publicKeyPath, publicKey.export({ type: "spki", format: "pem" }), "utf8");

  return {
    manifestPath,
    signaturePath,
    publicKeyPath,
  };
}

test("policy authority loads, verifies, hashes, and publishes policy bundle", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "policy-authority-test-"));
  const policy = basePolicy();
  const files = writeSignedPolicyBundle(tempDir, policy);

  let activated = null;
  const bundle = loadAndPublishPolicy({
    production: true,
    allowProductionPathOverride: true,
    manifestPath: files.manifestPath,
    signaturePath: files.signaturePath,
    publicKeyPath: files.publicKeyPath,
    expectedHash: computePolicyHash(policy),
    policyRuntime: {
      activatePolicy: (value) => {
        activated = value;
      },
    },
  });

  assert.equal(bundle.policyVersion, 21);
  assert.equal(typeof bundle.policyHash, "string");
  assert.equal(bundle.policyHash.length, 64);
  assert.equal(bundle.signatureVerified, true);
  assert.ok(activated);
});

test("production signature verification failure blocks activation", () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "policy-authority-test-"));
  const policy = basePolicy();
  const files = writeSignedPolicyBundle(tempDir, policy);

  fs.writeFileSync(files.signaturePath, "invalid-signature\n", "utf8");

  assert.throws(
    () =>
      loadAndPublishPolicy({
        production: true,
        allowProductionPathOverride: true,
        manifestPath: files.manifestPath,
        signaturePath: files.signaturePath,
        publicKeyPath: files.publicKeyPath,
      }),
    (error) => {
      assert.equal(error.code, "POLICY_SIGNATURE_INVALID");
      return true;
    },
  );
});

test("production rejects env path overrides and enforces bundled policy artifact paths", () => {
  const defaults = getDefaultPolicyArtifactPaths();
  const defaultPolicy = JSON.parse(fs.readFileSync(defaults.manifestPath, "utf8"));
  const previousManifest = process.env.EXECUTION_POLICY_MANIFEST_PATH;
  const previousSignature = process.env.EXECUTION_POLICY_SIGNATURE_PATH;
  const previousPublicKey = process.env.EXECUTION_POLICY_PUBLIC_KEY_PATH;

  process.env.EXECUTION_POLICY_MANIFEST_PATH = path.join(os.tmpdir(), "override-policy.json");
  process.env.EXECUTION_POLICY_SIGNATURE_PATH = path.join(os.tmpdir(), "override-policy.sig");
  process.env.EXECUTION_POLICY_PUBLIC_KEY_PATH = path.join(os.tmpdir(), "override-policy.pub.pem");

  try {
    assert.throws(
      () =>
        loadAndPublishPolicy({
          production: true,
          expectedHash: computePolicyHash(defaultPolicy),
        }),
      (error) => {
        assert.equal(error.code, "POLICY_PATH_OVERRIDE_FORBIDDEN");
        return true;
      },
    );
  } finally {
    if (previousManifest === undefined) {
      delete process.env.EXECUTION_POLICY_MANIFEST_PATH;
    } else {
      process.env.EXECUTION_POLICY_MANIFEST_PATH = previousManifest;
    }
    if (previousSignature === undefined) {
      delete process.env.EXECUTION_POLICY_SIGNATURE_PATH;
    } else {
      process.env.EXECUTION_POLICY_SIGNATURE_PATH = previousSignature;
    }
    if (previousPublicKey === undefined) {
      delete process.env.EXECUTION_POLICY_PUBLIC_KEY_PATH;
    } else {
      process.env.EXECUTION_POLICY_PUBLIC_KEY_PATH = previousPublicKey;
    }
  }

  const bundle = loadAndPublishPolicy({
    production: true,
    expectedHash: computePolicyHash(defaultPolicy),
  });
  const state = getActiveAuthorityState();

  assert.equal(bundle.policyHash, computePolicyHash(defaultPolicy));
  assert.equal(state.manifestPath, defaults.manifestPath);
});
