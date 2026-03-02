const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const { createWorkloadIntegrityVerifier } = require("../../security/workload-integrity.js");
const { computeWorkloadManifestHash } = require("../../security/workload-manifest.js");

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function stableCanonical(value) {
  if (Array.isArray(value)) {
    return value
      .map((item) => stableCanonical(item))
      .sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
  }
  if (!value || typeof value !== "object") {
    return value;
  }
  const ordered = {};
  for (const key of Object.keys(value).sort((a, b) => a.localeCompare(b))) {
    ordered[key] = stableCanonical(value[key]);
  }
  return ordered;
}

function sha256Object(value) {
  return crypto.createHash("sha256").update(JSON.stringify(stableCanonical(value)), "utf8").digest("hex");
}

function makeFixture({ imageDigestInManifest = "", runtimeConfig = { mode: "test" } } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-workload-integrity-"));
  const adapterPath = path.join(root, "adapter.js");
  const entrypointPath = path.join(root, "entrypoint.js");
  const manifestPath = path.join(root, "workload-manifest.json");

  fs.writeFileSync(adapterPath, "module.exports = async () => 'ok';\n", "utf8");
  fs.writeFileSync(entrypointPath, "require('./adapter.js');\n", "utf8");

  const manifest = {
    workloads: [
      {
        workloadID: "phase24.test.tool",
        adapterHash: sha256File(adapterPath),
        entrypointHash: sha256File(entrypointPath),
        runtimeConfigHash: sha256Object(runtimeConfig),
        workloadVersion: 1,
        productionRequired: false,
        ...(imageDigestInManifest ? { containerImageDigest: imageDigestInManifest } : {}),
      },
    ],
  };

  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  fs.chmodSync(manifestPath, 0o444);

  const expectedHash = computeWorkloadManifestHash(manifest);

  return {
    root,
    adapterPath,
    entrypointPath,
    manifestPath,
    expectedHash,
    runtimeConfig,
  };
}

function createVerifier(fixture, descriptorOverrides = {}) {
  return createWorkloadIntegrityVerifier({
    production: true,
    manifestPath: fixture.manifestPath,
    expectedHash: fixture.expectedHash,
    allowProductionPathOverride: true,
    runtimeDescriptorResolver: () => ({
      adapterPath: fixture.adapterPath,
      entrypointPath: fixture.entrypointPath,
      runtimeConfig: fixture.runtimeConfig,
      containerImageDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      runtimeMutated: false,
      ...descriptorOverrides,
    }),
  });
}

test("adapter hash mismatch blocks execution in production", () => {
  const fixture = makeFixture();
  const verifier = createVerifier(fixture);
  const startup = verifier.initialize();
  assert.equal(startup.ok, true);

  fs.writeFileSync(fixture.adapterPath, "module.exports = async () => 'tampered';\n", "utf8");

  const result = verifier.verifyExecution({
    tool: "phase24.test.tool",
    context: { source: "test", caller: "adapter-mismatch" },
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "WORKLOAD_HASH_MISMATCH");

  const blocked = verifier.verifyExecution({
    tool: "phase24.test.tool",
    context: { source: "test", caller: "adapter-mismatch" },
  });
  assert.equal(blocked.code, "WORKLOAD_NOT_VERIFIED");
});

test("entrypoint hash mismatch blocks execution in production", () => {
  const fixture = makeFixture();
  const verifier = createVerifier(fixture);
  assert.equal(verifier.initialize().ok, true);

  fs.writeFileSync(fixture.entrypointPath, "require('./adapter.js');\nrequire('./extra.js');\n", "utf8");

  const result = verifier.verifyExecution({
    tool: "phase24.test.tool",
    context: { source: "test", caller: "entrypoint-mismatch" },
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "WORKLOAD_HASH_MISMATCH");
});

test("runtime config hash mismatch blocks execution in production", () => {
  const fixture = makeFixture({ runtimeConfig: { mode: "baseline", retries: 1 } });
  let runtimeConfig = fixture.runtimeConfig;
  const verifier = createWorkloadIntegrityVerifier({
    production: true,
    manifestPath: fixture.manifestPath,
    expectedHash: fixture.expectedHash,
    allowProductionPathOverride: true,
    runtimeDescriptorResolver: () => ({
      adapterPath: fixture.adapterPath,
      entrypointPath: fixture.entrypointPath,
      runtimeConfig,
      runtimeMutated: false,
    }),
  });

  assert.equal(verifier.initialize().ok, true);
  runtimeConfig = { mode: "baseline", retries: 2 };

  const result = verifier.verifyExecution({
    tool: "phase24.test.tool",
    context: { source: "test", caller: "runtime-config-mismatch" },
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "WORKLOAD_HASH_MISMATCH");
});

test("image digest mismatch blocks execution in production", () => {
  const fixture = makeFixture({
    imageDigestInManifest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  });

  const verifier = createWorkloadIntegrityVerifier({
    production: true,
    manifestPath: fixture.manifestPath,
    expectedHash: fixture.expectedHash,
    allowProductionPathOverride: true,
    runtimeDescriptorResolver: () => ({
      adapterPath: fixture.adapterPath,
      entrypointPath: fixture.entrypointPath,
      runtimeConfig: fixture.runtimeConfig,
      containerImageDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      runtimeMutated: false,
    }),
  });

  assert.equal(verifier.initialize().ok, true);

  const result = verifier.verifyExecution({
    tool: "phase24.test.tool",
    context: { source: "test", caller: "image-mismatch" },
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "WORKLOAD_IMAGE_MISMATCH");
});
