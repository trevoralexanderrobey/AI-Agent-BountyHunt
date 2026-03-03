import { execSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { createExecutionRouter } from "../src/core/execution-router";
import {
  computeWorkloadManifestHash,
  resolveDefaultWorkloadManifestPath,
  validateWorkloadManifest,
} from "../src/security/workload-manifest";
import { createWorkloadIntegrityVerifier } from "../src/security/workload-integrity";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { createSupervisorV1 } = require("../../supervisor/supervisor-v1.js");

function normalizeString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function sha256FileHex(filePath: string): string {
  const content = fs.readFileSync(filePath);
  return crypto.createHash("sha256").update(content).digest("hex");
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

function sha256Object(value: unknown): string {
  return crypto.createHash("sha256").update(JSON.stringify(stableCanonical(value)), "utf8").digest("hex");
}

function writeTokenConfig(workspaceRoot: string, token: string): void {
  const tokenPath = path.join(workspaceRoot, ".cline", "cline_mcp_settings.json");
  fs.mkdirSync(path.dirname(tokenPath), { recursive: true });
  fs.writeFileSync(tokenPath, `${JSON.stringify({ token }, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  fs.chmodSync(tokenPath, 0o600);
}

async function main(): Promise<void> {
  const errors: string[] = [];

  let workload_manifest_present = false;
  let workload_manifest_hash_deterministic = false;
  let integrity_verified_at_startup = false;
  let router_blocks_unverified_execution = false;
  let image_digest_verified = false;
  let snapshot_bound_to_workload_manifest = false;
  let workload_drift_blocks_execution_in_prod = false;
  let no_router_bypass_paths = false;
  let no_control_plane_drift = false;

  try {
    const repoManifestPath = resolveDefaultWorkloadManifestPath();
    workload_manifest_present = fs.existsSync(repoManifestPath);
    if (workload_manifest_present) {
      const manifest = JSON.parse(fs.readFileSync(repoManifestPath, "utf8"));
      const schema = validateWorkloadManifest(manifest);
      if (!schema.valid) {
        errors.push(`workload manifest schema invalid: ${schema.errors.join("; ")}`);
      } else {
        const hashA = computeWorkloadManifestHash(manifest);
        const hashB = computeWorkloadManifestHash(JSON.parse(JSON.stringify(manifest)));
        workload_manifest_hash_deterministic = hashA === hashB;
      }
    }

    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "phase24-validate-"));
    const adapterPath = path.join(tempRoot, "adapter.js");
    const entrypointPath = path.join(tempRoot, "entrypoint.js");
    fs.writeFileSync(adapterPath, "module.exports = async () => 'ok';\n", "utf8");
    fs.writeFileSync(entrypointPath, "require('./adapter.js');\n", "utf8");

    const runtimeConfig = {
      mode: "deterministic",
      policyHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    };

    const declaredImageDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const testManifest = {
      offensiveManifestHash: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      workloads: [
        {
          workloadID: "phase24.test.tool",
          adapterHash: sha256FileHex(adapterPath),
          entrypointHash: sha256FileHex(entrypointPath),
          runtimeConfigHash: sha256Object(runtimeConfig),
          containerImageDigest: declaredImageDigest,
          workloadVersion: 1,
          productionRequired: true,
        },
      ],
    };

    const manifestPath = path.join(tempRoot, "workload-manifest.json");
    fs.writeFileSync(manifestPath, `${JSON.stringify(testManifest, null, 2)}\n`, { encoding: "utf8", mode: 0o444 });
    fs.chmodSync(manifestPath, 0o444);

    const expectedHash = computeWorkloadManifestHash(testManifest);

    const resolver = () => ({
      adapterPath,
      entrypointPath,
      runtimeConfig,
      containerImageDigest: declaredImageDigest,
      runtimeMutated: false,
    });

    const verifier = createWorkloadIntegrityVerifier({
      production: true,
      manifestPath,
      expectedHash,
      allowProductionPathOverride: true,
      runtimeDescriptorResolver: resolver,
    });

    const startup = verifier.initialize();
    integrity_verified_at_startup = startup.ok;

    const verifyImage = verifier.verifyExecution({
      tool: "phase24.test.tool",
      context: { source: "validate", caller: "phase24" },
    });
    image_digest_verified = verifyImage.ok;

    fs.writeFileSync(adapterPath, "module.exports = async () => 'tampered';\n", "utf8");
    const mismatch = verifier.verifyExecution({
      tool: "phase24.test.tool",
      context: { source: "validate", caller: "phase24" },
    });
    const blockedAfterMismatch = verifier.verifyExecution({
      tool: "phase24.test.tool",
      context: { source: "validate", caller: "phase24" },
    });
    workload_drift_blocks_execution_in_prod =
      mismatch.ok === false &&
      mismatch.code === "WORKLOAD_HASH_MISMATCH" &&
      blockedAfterMismatch.ok === false &&
      blockedAfterMismatch.code === "WORKLOAD_NOT_VERIFIED";

    const workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), "phase24-router-"));
    fs.mkdirSync(path.join(workspaceRoot, ".openclaw"), { recursive: true });
    writeTokenConfig(workspaceRoot, "phase24-token");

    const registryPath = path.join(workspaceRoot, "supervisor", "supervisor-registry.json");
    fs.mkdirSync(path.dirname(registryPath), { recursive: true });
    fs.writeFileSync(
      registryPath,
      `${JSON.stringify(
        [
          {
            name: "phase24.test.tool",
            description: "phase24 test tool",
            inputSchema: { type: "object", properties: {}, additionalProperties: false },
            mutationClass: "read",
            loggingLevel: "info",
            roles: ["supervisor", "internal", "admin"],
          },
        ],
        null,
        2,
      )}\n`,
      "utf8",
    );

    const previousNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    let legacyFallbackCalled = false;
    try {
      const router = createExecutionRouter({
        workspaceRoot,
        registryPath,
        auditLogPath: path.join(workspaceRoot, ".openclaw", "audit.log"),
        supervisorMode: false,
        supervisorAuthPhase: "compat",
        workloadIntegrityEnabled: true,
        workloadManifestPath: manifestPath,
        workloadManifestExpectedHash: expectedHash,
        workloadRuntimeDescriptorResolver: resolver,
      });

      const routed = await router.execute(
        "phase24.test.tool",
        {},
        {
          requestId: "phase24-router",
          workspaceRoot,
          source: "http_api",
          caller: "phase24-validator",
          authHeader: "Bearer phase24-token",
          legacyExecute: async () => {
            legacyFallbackCalled = true;
            return { ok: true };
          },
        },
      );

      router_blocks_unverified_execution = routed.ok === false;
      no_router_bypass_paths = legacyFallbackCalled === false;

      const supervisor = createSupervisorV1({
        execution: {
          executionMode: "host",
          containerRuntimeEnabled: false,
          backend: "mock",
        },
        workloadMetadataProvider: () => router.getWorkloadIntegrityMetadata(),
      });

      try {
        const status = await supervisor.getStatus();
        const metadata =
          status && status.executionMetadata && typeof status.executionMetadata === "object"
            ? status.executionMetadata
            : {};
        snapshot_bound_to_workload_manifest =
          normalizeString(metadata.workloadManifestHash) ===
          normalizeString(router.getWorkloadIntegrityMetadata().workloadManifestHash);
      } finally {
        await supervisor.shutdown();
      }
    } finally {
      if (typeof previousNodeEnv === "undefined") {
        delete process.env.NODE_ENV;
      } else {
        process.env.NODE_ENV = previousNodeEnv;
      }
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
      no_control_plane_drift = false;
      errors.push(`unable to verify control-plane drift: ${error instanceof Error ? error.message : String(error)}`);
    }
  } catch (error) {
    errors.push(error instanceof Error ? error.message : String(error));
  }

  const payload = {
    workload_manifest_present,
    workload_manifest_hash_deterministic,
    integrity_verified_at_startup,
    router_blocks_unverified_execution,
    image_digest_verified,
    snapshot_bound_to_workload_manifest,
    workload_drift_blocks_execution_in_prod,
    no_router_bypass_paths,
    no_control_plane_drift,
    errors,
  };

  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
}

main().catch((error) => {
  const payload = {
    workload_manifest_present: false,
    workload_manifest_hash_deterministic: false,
    integrity_verified_at_startup: false,
    router_blocks_unverified_execution: false,
    image_digest_verified: false,
    snapshot_bound_to_workload_manifest: false,
    workload_drift_blocks_execution_in_prod: false,
    no_router_bypass_paths: false,
    no_control_plane_drift: false,
    errors: [error instanceof Error ? error.message : String(error)],
  };
  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
  process.exit(1);
});
