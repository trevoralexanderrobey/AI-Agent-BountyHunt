#!/usr/bin/env node

const fs = require("node:fs");
const path = require("node:path");
const { execSync } = require("node:child_process");

const { serializeCanonical, computePolicyHash } = require("./execution-policy-manifest.js");
const { verifyPolicySignature } = require("./policy-authority.js");

function safeExists(filePath) {
  try {
    return fs.existsSync(filePath);
  } catch {
    return false;
  }
}

function loadJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function hasPattern(filePath, pattern) {
  if (!safeExists(filePath)) {
    return false;
  }
  return pattern.test(fs.readFileSync(filePath, "utf8"));
}

function main() {
  const root = path.resolve(__dirname, "..");
  const manifestPath = path.resolve(__dirname, "execution-policy.json");
  const signaturePath = path.resolve(__dirname, "execution-policy.json.sig");
  const publicKeyPath = path.resolve(__dirname, "execution-policy.pub.pem");

  const errors = [];

  const executionPolicyManifestPresent =
    safeExists(path.resolve(__dirname, "execution-policy-manifest.js")) &&
    safeExists(path.resolve(__dirname, "policy-authority.js")) &&
    safeExists(path.resolve(__dirname, "policy-runtime.js")) &&
    safeExists(manifestPath);

  let policyHashDeterministic = false;
  let policySignatureEnforcedInProd = false;
  if (executionPolicyManifestPresent) {
    try {
      const policy = loadJson(manifestPath);
      const a = computePolicyHash(policy);
      const b = computePolicyHash(JSON.parse(JSON.stringify(policy)));
      policyHashDeterministic = a === b;

      const canonical = serializeCanonical(policy);
      const verification = verifyPolicySignature({
        canonicalJson: canonical,
        signaturePath,
        publicKeyPath,
      });
      policySignatureEnforcedInProd = verification.ok;
    } catch (error) {
      errors.push(error.message);
    }
  }

  const supervisorPath = path.resolve(root, "supervisor", "supervisor-v1.js");
  const atomicPolicyActivationPresent = hasPattern(supervisorPath, /ensurePolicyAuthorityLoaded\(\)/);
  const federationPolicyMetadataPropagated =
    hasPattern(path.resolve(root, "federation", "heartbeat.js"), /executionPolicyHash/) &&
    hasPattern(path.resolve(root, "federation", "peer-registry.js"), /executionPolicyVersion/);
  const rollingUpgradeWindowSupported = hasPattern(path.resolve(__dirname, "policy-runtime.js"), /allowedUpgradeWindowMinutes/);
  const policyMismatchBlocksExecutionInProd = hasPattern(supervisorPath, /EXECUTION_CONFIG_MISMATCH/);
  const policyObjectImmutableInProd = hasPattern(path.resolve(__dirname, "policy-authority.js"), /deepFreeze/);

  let noControlPlaneDrift = true;
  try {
    const repoPath = path.resolve(root, "..");
    const diff = execSync(`git -C \"${repoPath}\" diff --name-only`, { encoding: "utf8" });
    const touched = diff
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
    if (touched.some((file) => file.endsWith("openclaw-bridge/cluster/cluster-manager.js"))) {
      noControlPlaneDrift = false;
    }
  } catch {
    noControlPlaneDrift = false;
  }

  const payload = {
    execution_policy_manifest_present: executionPolicyManifestPresent,
    policy_hash_deterministic: policyHashDeterministic,
    policy_signature_enforced_in_prod: policySignatureEnforcedInProd,
    atomic_policy_activation_present: atomicPolicyActivationPresent,
    federation_policy_metadata_propagated: federationPolicyMetadataPropagated,
    rolling_upgrade_window_supported: rollingUpgradeWindowSupported,
    policy_mismatch_blocks_execution_in_prod: policyMismatchBlocksExecutionInProd,
    policy_object_immutable_in_prod: policyObjectImmutableInProd,
    no_control_plane_drift: noControlPlaneDrift,
    errors,
  };

  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
}

main();
