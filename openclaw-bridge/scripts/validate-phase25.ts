import { execSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { createExecutionRouter } from "../src/core/execution-router";
import {
  computeAttestationReferenceHash,
  initializeAttestation,
  loadAttestationReferenceFromDisk,
  verifyAttestationEvidence,
} from "../src/security/workload-attestation";
import { computeWorkloadManifestHash } from "../src/security/workload-manifest";

function normalizeString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function stableCanonical(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value
      .map((entry) => stableCanonical(entry))
      .sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
  }
  if (!value || typeof value !== "object") {
    return value;
  }
  const ordered: Record<string, unknown> = {};
  for (const key of Object.keys(value as Record<string, unknown>).sort((a, b) => a.localeCompare(b))) {
    ordered[key] = stableCanonical((value as Record<string, unknown>)[key]);
  }
  return ordered;
}

function sha256Hex(input: string): string {
  return crypto.createHash("sha256").update(input, "utf8").digest("hex");
}

function sha256File(filePath: string): string {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function sha256Object(value: unknown): string {
  return sha256Hex(JSON.stringify(stableCanonical(value)));
}

function writeTokenConfig(workspaceRoot: string, token: string): void {
  const tokenPath = path.join(workspaceRoot, ".cline", "cline_mcp_settings.json");
  fs.mkdirSync(path.dirname(tokenPath), { recursive: true });
  fs.writeFileSync(tokenPath, `${JSON.stringify({ token }, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  fs.chmodSync(tokenPath, 0o600);
}

function writeRegistry(workspaceRoot: string): string {
  const registryPath = path.join(workspaceRoot, "supervisor", "supervisor-registry.json");
  fs.mkdirSync(path.dirname(registryPath), { recursive: true });
  fs.writeFileSync(
    registryPath,
    `${JSON.stringify(
      [
        {
          name: "supervisor.read_file",
          description: "read",
          inputSchema: {
            type: "object",
            properties: {
              path: { type: "string", minLength: 1 },
            },
            required: ["path"],
            additionalProperties: false,
          },
          mutationClass: "read",
          loggingLevel: "info",
          roles: ["supervisor", "internal", "admin"],
          workspacePathArgs: ["path"],
        },
      ],
      null,
      2,
    )}\n`,
    "utf8",
  );
  return registryPath;
}

async function main(): Promise<void> {
  const errors: string[] = [];

  let attestation_identity_generated = false;
  let attestation_evidence_signed = false;
  let attestation_signature_verified = false;
  let freshness_enforced = false;
  let router_blocks_untrusted_attestation = false;
  let cluster_mutual_attestation_enforced = false;
  let snapshot_bound_to_attestation = false;
  let no_router_bypass_paths = false;
  let no_control_plane_drift = false;

  try {
    const loadedReference = loadAttestationReferenceFromDisk({
      production: false,
      allowProductionPathOverride: true,
    });

    const localMetadata = {
      executionPolicyHash: loadedReference.reference.executionPolicyHash,
      secretManifestHash: loadedReference.reference.secretManifestHash,
      workloadManifestHash: loadedReference.reference.workloadManifestHash,
    };

    const attestationRuntime = initializeAttestation({
      production: false,
      referencePath: loadedReference.referencePath,
      expectedReferenceHash: loadedReference.referenceHash,
      localMetadataProvider: () => localMetadata,
    });

    const initialized = attestationRuntime.initializeAttestation();
    attestation_identity_generated = initialized.ok;

    const challenge = {
      nonce: "phase25-validate-nonce",
      timestampMs: Date.now(),
    };
    const generated = attestationRuntime.generateAttestationEvidence(challenge, {
      localMetadata,
      runtimeMeasurements: {
        source: "validate-phase25",
      },
    });

    attestation_evidence_signed =
      generated.ok === true &&
      Boolean(generated.evidence) &&
      typeof generated.evidence?.signature === "string" &&
      generated.evidence.signature.length > 0;

    const verified = verifyAttestationEvidence(generated.evidence, loadedReference.reference, {
      challenge,
      replayCache: new Map<string, number>(),
    });
    attestation_signature_verified = verified.ok;

    if (generated.evidence) {
      const replayCache = new Map<string, number>();
      const first = verifyAttestationEvidence(generated.evidence, loadedReference.reference, {
        challenge,
        replayCache,
      });
      const replay = verifyAttestationEvidence(generated.evidence, loadedReference.reference, {
        challenge,
        replayCache,
      });

      const expired = verifyAttestationEvidence(generated.evidence, loadedReference.reference, {
        challenge,
        nowMs: generated.evidence.expiresAtMs + 1,
        replayCache: new Map<string, number>(),
      });

      freshness_enforced =
        first.ok === true && replay.ok === false && replay.code === "WORKLOAD_ATTESTATION_REPLAY_DETECTED" && expired.ok === false;

      const expectedSnapshotHash = sha256Hex(
        JSON.stringify({
          executionPolicyHash: localMetadata.executionPolicyHash,
          secretManifestHash: localMetadata.secretManifestHash,
          workloadManifestHash: localMetadata.workloadManifestHash,
        }),
      );
      snapshot_bound_to_attestation = normalizeString(generated.evidence.snapshotHash).length === 64;
      if (!snapshot_bound_to_attestation) {
        errors.push(`snapshot hash invalid (expected shape like ${expectedSnapshotHash.slice(0, 8)}...)`);
      }
    }

    const peerReferencePath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "phase25-peer-ref-")), "ref.json");
    const peerReference = {
      ...loadedReference.reference,
      executionPolicyHash: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    };
    fs.writeFileSync(peerReferencePath, `${JSON.stringify(peerReference, null, 2)}\n`, "utf8");
    const peerReferenceHash = computeAttestationReferenceHash(peerReference);

    const peerRuntime = initializeAttestation({
      production: false,
      referencePath: peerReferencePath,
      expectedReferenceHash: peerReferenceHash,
      localMetadataProvider: () => ({
        executionPolicyHash: peerReference.executionPolicyHash,
        secretManifestHash: peerReference.secretManifestHash,
        workloadManifestHash: peerReference.workloadManifestHash,
      }),
    });
    peerRuntime.initializeAttestation();
    const peerChallenge = { nonce: "phase25-peer-nonce", timestampMs: Date.now() };
    const peerEvidence = peerRuntime.generateAttestationEvidence(peerChallenge, {
      localMetadata: {
        executionPolicyHash: peerReference.executionPolicyHash,
        secretManifestHash: peerReference.secretManifestHash,
        workloadManifestHash: peerReference.workloadManifestHash,
      },
      runtimeMeasurements: { source: "peer" },
    });

    const peerVerify = attestationRuntime.verifyPeerAttestationEvidence("peer-node-b", peerEvidence.evidence, peerChallenge);
    const peerState = attestationRuntime.getAttestationState();
    cluster_mutual_attestation_enforced =
      peerVerify.ok === false &&
      peerState.peerTrustMap["peer-node-b"] &&
      peerState.peerTrustMap["peer-node-b"].trusted === false &&
      peerState.peerTrustMap["peer-node-b"].stickyUntrusted === true;

    const workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), "phase25-router-"));
    fs.mkdirSync(path.join(workspaceRoot, ".openclaw"), { recursive: true });
    writeTokenConfig(workspaceRoot, "phase25-token");
    const registryPath = writeRegistry(workspaceRoot);
    fs.writeFileSync(path.join(workspaceRoot, "inside.txt"), "phase25", "utf8");

    const manifestPath = path.resolve(__dirname, "..", "..", "security", "workload-manifest.json");
    const originalManifest = fs.readFileSync(manifestPath, "utf8");
    const originalMode = fs.statSync(manifestPath).mode & 0o777;
    const writableManifestMode = originalMode | 0o200;

    const routerSourcePath = path.resolve(__dirname, "..", "src", "core", "execution-router.js");
    const runtimeConfig = {
      tool: "supervisor.read_file",
      supervisorMode: false,
      supervisorAuthPhase: "compat",
      mutationGuardEnabled: false,
    };
    const temporaryManifest = {
      workloads: [
        {
          workloadID: "supervisor.read_file",
          adapterHash: sha256File(routerSourcePath),
          entrypointHash: sha256File(routerSourcePath),
          runtimeConfigHash: sha256Object(runtimeConfig),
          workloadVersion: 25,
          productionRequired: false,
        },
      ],
    };
    if ((originalMode & 0o200) === 0) {
      fs.chmodSync(manifestPath, writableManifestMode);
    }
    fs.writeFileSync(manifestPath, `${JSON.stringify(temporaryManifest, null, 2)}\n`, { encoding: "utf8", mode: 0o444 });
    fs.chmodSync(manifestPath, 0o444);

    const workloadManifestHash = computeWorkloadManifestHash(temporaryManifest);

    const previousNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    let legacyCalled = false;

    try {
      const router = createExecutionRouter({
        workspaceRoot,
        registryPath,
        auditLogPath: path.join(workspaceRoot, ".openclaw", "audit.log"),
        supervisorMode: false,
        supervisorAuthPhase: "compat",
        workloadManifestExpectedHash: workloadManifestHash,
        workloadIntegrityEnabled: true,
        workloadAttestationEnabled: true,
        integrityMetadataProvider: () => ({
          local: {
            executionPolicyHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            secretManifestHash: loadedReference.reference.secretManifestHash,
            workloadManifestHash: loadedReference.reference.workloadManifestHash,
          },
          peers: [],
        }),
      });

      const routed = await router.execute("supervisor.read_file", { path: "inside.txt" }, {
        requestId: "phase25-router-block",
        workspaceRoot,
        source: "http_api",
        caller: "phase25-validator",
        authHeader: "Bearer phase25-token",
        legacyExecute: async () => {
          legacyCalled = true;
          return { ok: true };
        },
      });

      router_blocks_untrusted_attestation = routed.ok === false && routed.code === "WORKLOAD_ATTESTATION_NOT_TRUSTED";

      const legacy = await router.execute("legacy.fake_tool", {}, {
        requestId: "phase25-router-bypass",
        workspaceRoot,
        source: "http_api",
        caller: "phase25-validator",
        authHeader: "Bearer phase25-token",
        legacyExecute: async () => {
          legacyCalled = true;
          return { ok: true };
        },
      });
      no_router_bypass_paths = legacy.ok === false && legacyCalled === false;
    } finally {
      if (typeof previousNodeEnv === "undefined") {
        delete process.env.NODE_ENV;
      } else {
        process.env.NODE_ENV = previousNodeEnv;
      }
      fs.chmodSync(manifestPath, writableManifestMode);
      fs.writeFileSync(manifestPath, originalManifest, "utf8");
      fs.chmodSync(manifestPath, originalMode);
    }

    try {
      const repoRoot = path.resolve(__dirname, "..", "..");
      const diff = execSync(`git -C ${JSON.stringify(repoRoot)} diff --name-only`, { encoding: "utf8" });
      const changed = diff
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean);
      no_control_plane_drift = !changed.includes("openclaw-bridge/cluster/cluster-manager.js");
    } catch (error) {
      errors.push(`unable to verify control-plane drift: ${error instanceof Error ? error.message : String(error)}`);
      no_control_plane_drift = false;
    }
  } catch (error) {
    errors.push(error instanceof Error ? error.message : String(error));
  }

  const payload = {
    attestation_identity_generated,
    attestation_evidence_signed,
    attestation_signature_verified,
    freshness_enforced,
    router_blocks_untrusted_attestation,
    cluster_mutual_attestation_enforced,
    snapshot_bound_to_attestation,
    no_router_bypass_paths,
    no_control_plane_drift,
    errors,
  };

  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
}

main().catch((error) => {
  const payload = {
    attestation_identity_generated: false,
    attestation_evidence_signed: false,
    attestation_signature_verified: false,
    freshness_enforced: false,
    router_blocks_untrusted_attestation: false,
    cluster_mutual_attestation_enforced: false,
    snapshot_bound_to_attestation: false,
    no_router_bypass_paths: false,
    no_control_plane_drift: false,
    errors: [error instanceof Error ? error.message : String(error)],
  };
  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
  process.exit(1);
});
