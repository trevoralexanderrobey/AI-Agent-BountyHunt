const test = require("node:test");
const assert = require("node:assert/strict");

const {
  computeWorkloadManifestHash,
  validateWorkloadManifest,
  getCanonicalWorkloadManifest,
} = require("../../security/workload-manifest.js");

function sampleManifest() {
  return {
    workloads: [
      {
        workloadID: "supervisor.read_file",
        adapterHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        entrypointHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        runtimeConfigHash: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        workloadVersion: 1,
        productionRequired: true,
        containerImageDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      },
      {
        workloadID: "supervisor.write_file",
        adapterHash: "1111111111111111111111111111111111111111111111111111111111111111",
        entrypointHash: "2222222222222222222222222222222222222222222222222222222222222222",
        runtimeConfigHash: "3333333333333333333333333333333333333333333333333333333333333333",
        workloadVersion: 1,
        productionRequired: false,
      },
    ],
  };
}

test("workload manifest hash is deterministic", () => {
  const manifest = sampleManifest();
  const hashA = computeWorkloadManifestHash(manifest);
  const hashB = computeWorkloadManifestHash(JSON.parse(JSON.stringify(manifest)));
  assert.equal(hashA, hashB);

  const canonical = getCanonicalWorkloadManifest(manifest);
  assert.deepEqual(canonical.workloads.map((entry) => entry.workloadID), [
    "supervisor.read_file",
    "supervisor.write_file",
  ]);
});

test("workload manifest hash changes when metadata changes", () => {
  const manifest = sampleManifest();
  const baseline = computeWorkloadManifestHash(manifest);

  const modified = JSON.parse(JSON.stringify(manifest));
  modified.workloads[0].runtimeConfigHash = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

  const next = computeWorkloadManifestHash(modified);
  assert.notEqual(baseline, next);
});

test("workload manifest validation rejects missing required fields", () => {
  const invalid = {
    workloads: [
      {
        workloadID: "supervisor.read_file",
        adapterHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        runtimeConfigHash: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        workloadVersion: 1,
        productionRequired: true,
      },
    ],
  };

  const result = validateWorkloadManifest(invalid);
  assert.equal(result.valid, false);
  assert.equal(result.errors.some((entry) => entry.includes("entrypointHash")), true);
});
