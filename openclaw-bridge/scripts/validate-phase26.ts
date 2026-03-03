import { execSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { createExecutionRouter } from "../src/core/execution-router";
import {
  createWorkloadProvenanceRuntime,
  loadBuildProvenanceFromDisk,
  resolveDefaultBuildProvenanceHashPath,
  resolveDefaultBuildProvenancePath,
  resolveDefaultBuildProvenancePublicKeyPath,
} from "../src/security/workload-provenance";

function normalizeString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function writeTokenConfig(workspaceRoot: string, token: string): void {
  const tokenPath = path.join(workspaceRoot, ".cline", "cline_mcp_settings.json");
  fs.mkdirSync(path.dirname(tokenPath), { recursive: true });
  fs.writeFileSync(tokenPath, `${JSON.stringify({ token }, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  fs.chmodSync(tokenPath, 0o600);
}

function writeRegistry(workspaceRoot: string, toolName: string): string {
  const registryPath = path.join(workspaceRoot, "supervisor", "supervisor-registry.json");
  fs.mkdirSync(path.dirname(registryPath), { recursive: true });
  fs.writeFileSync(
    registryPath,
    `${JSON.stringify(
      [
        {
          name: toolName,
          description: "phase26 test tool",
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

  let provenance_artifact_present = false;
  let provenance_hash_verified = false;
  let provenance_signature_verified = false;
  let container_digests_pinned = false;
  let lockfile_hash_verified = false;
  let router_blocks_invalid_provenance = false;
  let snapshot_bound_to_provenance = false;
  let no_router_bypass_paths = false;
  let no_control_plane_drift = false;

  try {
    const provenancePath = resolveDefaultBuildProvenancePath();
    const hashPath = resolveDefaultBuildProvenanceHashPath();
    const publicKeyPath = resolveDefaultBuildProvenancePublicKeyPath();

    provenance_artifact_present =
      fs.existsSync(provenancePath) &&
      fs.existsSync(hashPath) &&
      fs.existsSync(publicKeyPath);

    if (!provenance_artifact_present) {
      errors.push("build provenance artifact files are missing");
    }

    const loaded = loadBuildProvenanceFromDisk({
      production: false,
      provenancePath,
      provenanceHashPath: hashPath,
      publicKeyPath,
      allowProductionPathOverride: true,
      productionContainerMode: false,
    });

    provenance_hash_verified = true;
    provenance_signature_verified = true;
    lockfile_hash_verified = true;

    const digestValues = Object.values(loaded.provenance.containerImageDigests || {});
    container_digests_pinned =
      digestValues.length > 0 && digestValues.every((digest) => /^sha256:[a-f0-9]{64}$/.test(normalizeString(digest).toLowerCase()));

    const selectedWorkloadID = Object.keys(loaded.provenance.containerImageDigests || {})[0] || "supervisor.read_file";
    const selectedDigest =
      loaded.provenance.containerImageDigests[selectedWorkloadID] ||
      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    const runtime = createWorkloadProvenanceRuntime({
      production: false,
      provenancePath,
      provenanceHashPath: hashPath,
      publicKeyPath,
      allowProductionPathOverride: true,
      productionContainerMode: false,
    });
    const startup = runtime.initializeProvenance();
    if (!startup.ok) {
      errors.push(`provenance runtime startup failed: ${startup.code}`);
    } else {
      const verify = await runtime.verifyExecution({
        workloadID: selectedWorkloadID,
        runtimeDigest: selectedDigest,
        localMetadata: {
          executionPolicyHash: loaded.provenance.executionPolicyHash,
          secretManifestHash: loaded.provenance.secretManifestHash,
          workloadManifestHash: loaded.provenance.workloadManifestHash,
          attestationReferenceHash: loaded.provenance.attestationReferenceHash,
        },
      });
      snapshot_bound_to_provenance = verify.ok;
      if (!verify.ok) {
        errors.push(`snapshot provenance binding check failed: ${verify.code}`);
      }
    }

    const tamperedRoot = fs.mkdtempSync(path.join(os.tmpdir(), "phase26-provenance-"));
    const tamperedProvenancePath = path.join(tamperedRoot, "build-provenance.json");
    const tamperedHashPath = path.join(tamperedRoot, "build-provenance.hash");
    const tamperedPublicKeyPath = path.join(tamperedRoot, "build-provenance.pub");

    const tampered = JSON.parse(fs.readFileSync(provenancePath, "utf8"));
    tampered.repository = `${normalizeString(tampered.repository) || "repo"}-tampered`;
    fs.writeFileSync(tamperedProvenancePath, `${JSON.stringify(tampered, null, 2)}\n`, "utf8");
    fs.copyFileSync(hashPath, tamperedHashPath);
    fs.copyFileSync(publicKeyPath, tamperedPublicKeyPath);

    const workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), "phase26-router-"));
    fs.mkdirSync(path.join(workspaceRoot, ".openclaw"), { recursive: true });
    fs.writeFileSync(path.join(workspaceRoot, "inside.txt"), "phase26", "utf8");
    writeTokenConfig(workspaceRoot, "phase26-token");
    const registryPath = writeRegistry(workspaceRoot, selectedWorkloadID);

    let legacyCalled = false;
    const router = createExecutionRouter({
      workspaceRoot,
      registryPath,
      auditLogPath: path.join(workspaceRoot, ".openclaw", "audit.log"),
      supervisorMode: false,
      supervisorAuthPhase: "compat",
      workloadIntegrityEnabled: false,
      workloadAttestationEnabled: false,
      workloadProvenanceEnabled: true,
      buildProvenancePath: tamperedProvenancePath,
      buildProvenanceHashPath: tamperedHashPath,
      buildProvenancePublicKeyPath: tamperedPublicKeyPath,
    });

    const result = await router.execute(selectedWorkloadID, { path: "inside.txt" }, {
      requestId: "phase26-router-invalid-provenance",
      workspaceRoot,
      source: "http_api",
      caller: "phase26-validator",
      authHeader: "Bearer phase26-token",
      transportMetadata: {
        containerImageDigest: selectedDigest,
        executionMetadata: {
          executionPolicyHash: loaded.provenance.executionPolicyHash,
          secretManifestHash: loaded.provenance.secretManifestHash,
          workloadManifestHash: loaded.provenance.workloadManifestHash,
          attestationReferenceHash: loaded.provenance.attestationReferenceHash,
        },
      },
      legacyExecute: async () => {
        legacyCalled = true;
        return { ok: true };
      },
    });

    router_blocks_invalid_provenance = result.ok === false && result.code === "WORKLOAD_PROVENANCE_NOT_TRUSTED";
    no_router_bypass_paths = legacyCalled === false;

    if (!router_blocks_invalid_provenance) {
      errors.push(`router did not block invalid provenance (code=${result.code || "unknown"})`);
    }
    if (!no_router_bypass_paths) {
      errors.push("legacy fallback executed despite provenance block");
    }

    try {
      const repoRoot = path.resolve(__dirname, "..", "..");
      const diff = execSync(`git -C ${JSON.stringify(repoRoot)} diff --name-only`, {
        encoding: "utf8",
      });
      const changed = diff
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean);
      no_control_plane_drift = !changed.includes("openclaw-bridge/cluster/cluster-manager.js");
    } catch (error) {
      no_control_plane_drift = false;
      errors.push(`unable to verify control-plane drift: ${error instanceof Error ? error.message : String(error)}`);
    }
  } catch (error) {
    errors.push(error instanceof Error ? error.message : String(error));
  }

  const payload = {
    provenance_artifact_present,
    provenance_hash_verified,
    provenance_signature_verified,
    container_digests_pinned,
    lockfile_hash_verified,
    router_blocks_invalid_provenance,
    snapshot_bound_to_provenance,
    no_router_bypass_paths,
    no_control_plane_drift,
    errors,
  };

  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
}

main().catch((error) => {
  const payload = {
    provenance_artifact_present: false,
    provenance_hash_verified: false,
    provenance_signature_verified: false,
    container_digests_pinned: false,
    lockfile_hash_verified: false,
    router_blocks_invalid_provenance: false,
    snapshot_bound_to_provenance: false,
    no_router_bypass_paths: false,
    no_control_plane_drift: false,
    errors: [error instanceof Error ? error.message : String(error)],
  };

  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
  process.exit(1);
});
