const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  computeOffensiveToolRuntimeConfigHash,
  loadOffensiveManifestFromDisk,
  verifyOffensiveManifest,
} = require("../../security/offensive-workload-manifest.js");

const OFFENSIVE_MANIFEST_DIR = path.resolve(__dirname, "../../security/offensive-workloads");

function copyFixtureTree() {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "offensive-manifest-test-"));
  const manifestPath = path.join(tmpRoot, "manifest.json");
  const hashPath = path.join(tmpRoot, "manifest.hash");
  const signaturePath = path.join(tmpRoot, "manifest.sig");
  const publicKeyPath = path.join(tmpRoot, "manifest.pub");
  fs.copyFileSync(path.join(OFFENSIVE_MANIFEST_DIR, "manifest.json"), manifestPath);
  fs.copyFileSync(path.join(OFFENSIVE_MANIFEST_DIR, "manifest.hash"), hashPath);
  fs.copyFileSync(path.join(OFFENSIVE_MANIFEST_DIR, "manifest.sig"), signaturePath);
  fs.copyFileSync(path.join(OFFENSIVE_MANIFEST_DIR, "manifest.pub"), publicKeyPath);
  return { tmpRoot, manifestPath, hashPath, signaturePath, publicKeyPath };
}

test("offensive manifest verifies with detached hash + signature", () => {
  const verified = verifyOffensiveManifest({
    production: false,
    allowProductionPathOverride: true,
    productionContainerMode: false,
  });
  assert.equal(verified.ok, true);

  const loaded = loadOffensiveManifestFromDisk({
    production: false,
    allowProductionPathOverride: true,
    productionContainerMode: false,
  });
  assert.ok(/^[a-f0-9]{64}$/.test(loaded.canonicalPayloadHash));
  assert.equal(Array.isArray(loaded.manifest.tools), true);
  assert.equal(loaded.manifest.tools.length > 0, true);
});

test("offensive manifest tampering invalidates detached signature/hash verification", () => {
  const fixture = copyFixtureTree();
  const original = JSON.parse(fs.readFileSync(fixture.manifestPath, "utf8"));
  original.tools[0].toolVersion = "tampered-version";
  fs.writeFileSync(fixture.manifestPath, `${JSON.stringify(original, null, 2)}\n`, "utf8");

  const result = verifyOffensiveManifest({
    production: false,
    manifestPath: fixture.manifestPath,
    hashPath: fixture.hashPath,
    signaturePath: fixture.signaturePath,
    publicKeyPath: fixture.publicKeyPath,
    allowProductionPathOverride: true,
    productionContainerMode: false,
  });
  assert.equal(result.ok, false);
  assert.equal(
    result.code === "OFFENSIVE_MANIFEST_HASH_MISMATCH" ||
      result.code === "OFFENSIVE_MANIFEST_SIGNATURE_INVALID" ||
      result.code === "OFFENSIVE_MANIFEST_SCHEMA_INVALID",
    true,
  );
});

test("offensive manifest runtimeConfigHash is deterministic and bound to isolation/runtime profile", () => {
  const loaded = loadOffensiveManifestFromDisk({
    production: false,
    allowProductionPathOverride: true,
    productionContainerMode: false,
  });

  for (const tool of loaded.manifest.tools) {
    const computed = computeOffensiveToolRuntimeConfigHash(tool);
    assert.equal(tool.runtimeConfigHash, computed, `runtimeConfigHash mismatch for ${tool.toolName}`);
  }
});

test("production path override is forbidden for offensive manifest artifacts", () => {
  const fixture = copyFixtureTree();
  const result = verifyOffensiveManifest({
    production: true,
    manifestPath: fixture.manifestPath,
    hashPath: fixture.hashPath,
    signaturePath: fixture.signaturePath,
    publicKeyPath: fixture.publicKeyPath,
    allowProductionPathOverride: false,
    productionContainerMode: false,
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "OFFENSIVE_MANIFEST_PATH_OVERRIDE_FORBIDDEN");
});
