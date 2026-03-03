const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");
const { execSync } = require("node:child_process");

test("phase 24 does not modify cluster-manager control-plane file", () => {
  const repoRoot = path.resolve(__dirname, "../../..");
  const output = execSync(`git -C ${JSON.stringify(repoRoot)} diff --name-only`, {
    encoding: "utf8",
  });

  const changedFiles = output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  assert.equal(changedFiles.includes("openclaw-bridge/cluster/cluster-manager.js"), false);
});

test("phase validation utilities are not imported by runtime authority paths", () => {
  const runtimeFiles = [
    path.resolve(__dirname, "../../supervisor/supervisor-v1.js"),
    path.resolve(__dirname, "../../http/server.js"),
    path.resolve(__dirname, "../../http/handlers.js"),
    path.resolve(__dirname, "../../policy/policy-authority.js"),
    path.resolve(__dirname, "../../policy/policy-runtime.js"),
  ];

  for (const filePath of runtimeFiles) {
    const content = fs.readFileSync(filePath, "utf8");
    assert.equal(content.includes("validate-phase22"), false, `unexpected validate-phase22 reference in ${filePath}`);
    assert.equal(content.includes("validate-phase23"), false, `unexpected validate-phase23 reference in ${filePath}`);
    assert.equal(content.includes("validate-phase24"), false, `unexpected validate-phase24 reference in ${filePath}`);
    assert.equal(content.includes("validate-phase25"), false, `unexpected validate-phase25 reference in ${filePath}`);
    assert.equal(content.includes("validate-phase26"), false, `unexpected validate-phase26 reference in ${filePath}`);
    assert.equal(
      content.includes("verify-workload-attestation"),
      false,
      `unexpected verify-workload-attestation reference in ${filePath}`,
    );
    assert.equal(
      content.includes("verify-build-provenance"),
      false,
      `unexpected verify-build-provenance reference in ${filePath}`,
    );
  }
});
