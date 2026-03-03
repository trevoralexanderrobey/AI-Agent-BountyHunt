import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { createOffensiveDomainRuntime } from "../src/security/offensive-domain";
import { loadOffensiveManifestFromDisk } from "../src/security/offensive-workload-manifest";
import { loadBuildProvenanceFromDisk } from "../src/security/workload-provenance";

function normalizeString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function readFileSafe(filePath: string): string {
  try {
    return fs.readFileSync(filePath, "utf8");
  } catch {
    return "";
  }
}

function hasAll(content: string, patterns: RegExp[]): boolean {
  return patterns.every((pattern) => pattern.test(content));
}

function makeValidNmapArgs(): Record<string, unknown> {
  return {
    target: "scanme.nmap.org",
    protocol: "tcp",
  };
}

function resolveProjectRoot(): string {
  const direct = path.resolve(__dirname, "..");
  if (fs.existsSync(path.resolve(direct, "tools", "base-adapter.js"))) {
    return direct;
  }
  const distParent = path.resolve(__dirname, "..", "..");
  if (fs.existsSync(path.resolve(distParent, "tools", "base-adapter.js"))) {
    return distParent;
  }
  return direct;
}

async function main(): Promise<void> {
  const errors: string[] = [];

  let offensive_registry_static = true;
  let no_shell_execution_paths = true;
  let arguments_schema_enforced = true;
  let container_digests_pinned = true;
  let isolation_constraints_enforced = true;
  let network_policy_enforced = true;
  let resource_limits_enforced = true;
  let router_only_enforcement_preserved = true;
  let no_control_plane_drift = true;

  try {
    const root = resolveProjectRoot();
    const offensiveDomainPath = path.resolve(root, "src", "security", "offensive-domain.ts");
    const offensiveManifestSourcePath = path.resolve(root, "src", "security", "offensive-workload-manifest.ts");
    const routerPath = path.resolve(root, "src", "core", "execution-router.ts");
    const baseAdapterPath = path.resolve(root, "tools", "base-adapter.js");
    const containerRuntimePath = path.resolve(root, "execution", "container-runtime.js");
    const handlersPath = path.resolve(root, "http", "handlers.js");
    const serverPath = path.resolve(root, "bridge", "server.ts");
    const clusterManagerPath = path.resolve(root, "cluster", "cluster-manager.js");

    const offensiveDomainSource = readFileSafe(offensiveDomainPath);
    const offensiveManifestSource = readFileSafe(offensiveManifestSourcePath);
    const routerSource = readFileSafe(routerPath);
    const baseAdapterSource = readFileSafe(baseAdapterPath);
    const containerRuntimeSource = readFileSafe(containerRuntimePath);
    const handlersSource = readFileSafe(handlersPath);
    const serverSource = readFileSafe(serverPath);
    const clusterManagerSource = readFileSafe(clusterManagerPath);

    let loadedOffensive:
      | ReturnType<typeof loadOffensiveManifestFromDisk>
      | null = null;
    let loadedProvenance:
      | ReturnType<typeof loadBuildProvenanceFromDisk>
      | null = null;

    try {
      loadedOffensive = loadOffensiveManifestFromDisk({
        production: false,
        allowProductionPathOverride: true,
        productionContainerMode: false,
      });
    } catch (error) {
      offensive_registry_static = false;
      container_digests_pinned = false;
      isolation_constraints_enforced = false;
      network_policy_enforced = false;
      resource_limits_enforced = false;
      router_only_enforcement_preserved = false;
      errors.push(`offensive manifest failed verification: ${error instanceof Error ? error.message : String(error)}`);
    }

    try {
      loadedProvenance = loadBuildProvenanceFromDisk({
        production: false,
        allowProductionPathOverride: true,
        productionContainerMode: false,
      });
    } catch (error) {
      container_digests_pinned = false;
      router_only_enforcement_preserved = false;
      errors.push(`build provenance failed verification: ${error instanceof Error ? error.message : String(error)}`);
    }

    const expectedTools = new Set(["nmap", "sqlmap", "nikto", "ffuf"]);
    if (loadedOffensive) {
      const tools = loadedOffensive.manifest.tools || [];
      const names = tools.map((tool) => normalizeString(tool.toolName).toLowerCase()).filter(Boolean);
      const actualSet = new Set(names);
      if (
        names.length !== expectedTools.size ||
        actualSet.size !== expectedTools.size ||
        Array.from(expectedTools).some((tool) => !actualSet.has(tool))
      ) {
        offensive_registry_static = false;
        errors.push("offensive registry is not static to nmap/sqlmap/nikto/ffuf");
      }

      if (/fs\.watch|setInterval\(|reload|hot[-_]?load|register.+runtime|plugin/i.test(offensiveDomainSource)) {
        offensive_registry_static = false;
        errors.push("offensive registry appears dynamically mutable");
      }
    }

    const forbiddenShellPatterns = [
      /\/bin\/sh/,
      /shell\s*:\s*true/,
      /spawn\s*\([^)]*['"`]\s*\/bin\/sh/,
      /\$\(/,
    ];
    for (const source of [offensiveDomainSource, baseAdapterSource, containerRuntimeSource, handlersSource, serverSource]) {
      if (forbiddenShellPatterns.some((pattern) => pattern.test(source))) {
        no_shell_execution_paths = false;
      }
    }
    if (!no_shell_execution_paths) {
      errors.push("shell execution pattern detected in offensive execution surface");
    }

    if (loadedOffensive) {
      const tools = loadedOffensive.manifest.tools || [];
      for (const tool of tools) {
        const schema = tool.allowedArgsSchema || {};
        if (!(schema && typeof schema === "object" && schema.type === "object" && schema.additionalProperties === false)) {
          arguments_schema_enforced = false;
          errors.push(`argument schema is not strict object for ${normalizeString(tool.toolName)}`);
        }
      }

      const sqlmap = tools.find((tool) => normalizeString(tool.toolName).toLowerCase() === "sqlmap");
      if (!sqlmap) {
        arguments_schema_enforced = false;
        errors.push("sqlmap manifest entry missing");
      } else {
        const forcedFlags = new Set((sqlmap.forcedFlags || []).map((entry) => normalizeString(entry).toLowerCase()));
        const deniedFlags = new Set((sqlmap.deniedFlags || []).map((entry) => normalizeString(entry).toLowerCase()));
        if (!forcedFlags.has("--batch")) {
          arguments_schema_enforced = false;
          errors.push("sqlmap --batch is not forced");
        }
        for (const requiredDenied of ["--os-shell", "--os-pwn", "--file-write", "--file-read", "--udf-inject", "--tamper"]) {
          if (!deniedFlags.has(requiredDenied)) {
            arguments_schema_enforced = false;
            errors.push(`sqlmap denied flag missing: ${requiredDenied}`);
          }
        }
      }
    }

    if (loadedOffensive && loadedProvenance) {
      for (const tool of loadedOffensive.manifest.tools || []) {
        const digest = normalizeString(tool.containerImageDigest).toLowerCase();
        if (!/^sha256:[a-f0-9]{64}$/.test(digest)) {
          container_digests_pinned = false;
          errors.push(`non-pinned digest for ${normalizeString(tool.toolName)}`);
          continue;
        }

        const workloadKey = normalizeString(tool.workloadID || tool.toolName).toLowerCase();
        const provenanceDigest = normalizeString(loadedProvenance.provenance.containerImageDigests[workloadKey]).toLowerCase();
        if (!provenanceDigest || provenanceDigest !== digest) {
          container_digests_pinned = false;
          errors.push(`provenance digest mismatch for ${workloadKey}`);
        }
      }

      if (normalizeString(loadedProvenance.provenance.offensiveManifestHash).toLowerCase() !== loadedOffensive.canonicalPayloadHash) {
        container_digests_pinned = false;
        router_only_enforcement_preserved = false;
        errors.push("provenance offensiveManifestHash does not match offensive manifest hash");
      }
    }

    if (loadedOffensive) {
      for (const tool of loadedOffensive.manifest.tools || []) {
        const profile = tool.isolationProfile || {};
        const dropCapabilities = Array.isArray(profile.dropCapabilities) ? profile.dropCapabilities : [];
        const writableVolumes = Array.isArray(profile.writableVolumes) ? profile.writableVolumes : [];
        if (
          profile.privileged !== false ||
          profile.hostPID !== false ||
          profile.hostNetwork !== false ||
          profile.readOnlyRootFilesystem !== true ||
          profile.tty !== false ||
          profile.stdin !== false ||
          dropCapabilities.length !== 1 ||
          dropCapabilities[0] !== "ALL" ||
          writableVolumes.length !== 1 ||
          writableVolumes[0] !== "scratch"
        ) {
          isolation_constraints_enforced = false;
          errors.push(`isolation profile invalid for ${normalizeString(tool.toolName)}`);
        }
      }
    }

    if (
      !hasAll(containerRuntimeSource, [/AttachStdin:\s*false/, /OpenStdin:\s*false/, /StdinOnce:\s*false/, /Tty:\s*false/]) ||
      !/WORKLOAD_ISOLATION_INVALID/.test(baseAdapterSource) ||
      !/request\.nonInteractive\s*=\s*true/.test(baseAdapterSource) ||
      !/offensiveExecutionPlan/.test(baseAdapterSource)
    ) {
      isolation_constraints_enforced = false;
      errors.push("runtime/container isolation enforcement code path incomplete");
    }

    if (
      !/computeOffensiveToolRuntimeConfigHash/.test(offensiveManifestSource) ||
      !/runtimeConfigHash mismatch/.test(offensiveManifestSource)
    ) {
      isolation_constraints_enforced = false;
      router_only_enforcement_preserved = false;
      errors.push("deterministic runtimeConfigHash enforcement is missing");
    }

    if (loadedOffensive) {
      for (const tool of loadedOffensive.manifest.tools || []) {
        const constraints = tool.executionConstraints || {};
        const scope = normalizeString(constraints.networkScope);
        if (!["internal", "external", "target-bound"].includes(scope)) {
          network_policy_enforced = false;
          errors.push(`invalid networkScope for ${normalizeString(tool.toolName)}`);
        }
        if (typeof constraints.requiresTarget !== "boolean") {
          network_policy_enforced = false;
          errors.push(`requiresTarget missing for ${normalizeString(tool.toolName)}`);
        }
        if (!Array.isArray(constraints.allowedProtocols) || constraints.allowedProtocols.length === 0) {
          network_policy_enforced = false;
          errors.push(`allowedProtocols missing for ${normalizeString(tool.toolName)}`);
        }
      }
    }

    if (!/OFFENSIVE_TARGET_INVALID/.test(offensiveDomainSource) || !/OFFENSIVE_PROTOCOL_NOT_ALLOWED/.test(offensiveDomainSource)) {
      network_policy_enforced = false;
      errors.push("router offensive network policy rejection codes missing");
    }

    if (loadedOffensive) {
      for (const tool of loadedOffensive.manifest.tools || []) {
        const limits = tool.executionConstraints && tool.executionConstraints.resourceLimits;
        if (
          !limits ||
          !Number.isInteger(Number(limits.cpuShares)) ||
          !Number.isInteger(Number(limits.memoryLimitMb)) ||
          !Number.isInteger(Number(limits.maxRuntimeSeconds)) ||
          !Number.isInteger(Number(limits.maxOutputBytes)) ||
          Number(limits.cpuShares) <= 0 ||
          Number(limits.memoryLimitMb) <= 0 ||
          Number(limits.maxRuntimeSeconds) <= 0 ||
          Number(limits.maxOutputBytes) <= 0
        ) {
          resource_limits_enforced = false;
          errors.push(`resource limits missing/invalid for ${normalizeString(tool.toolName)}`);
        }
      }
    }

    if (
      !/OFFENSIVE_RATE_LIMIT_EXCEEDED/.test(offensiveDomainSource) ||
      !/OFFENSIVE_CONCURRENCY_EXCEEDED/.test(offensiveDomainSource) ||
      !/OFFENSIVE_BACKOFF_ACTIVE/.test(offensiveDomainSource)
    ) {
      resource_limits_enforced = false;
      errors.push("offensive rate/concurrency/backoff enforcement code missing");
    }

    if (loadedOffensive) {
      const runtime = createOffensiveDomainRuntime({
        production: false,
        manifestPath: loadedOffensive.manifestPath,
        hashPath: loadedOffensive.hashPath,
        signaturePath: loadedOffensive.signaturePath,
        publicKeyPath: loadedOffensive.publicKeyPath,
        expectedManifestHash: loadedOffensive.canonicalPayloadHash,
        maxPerToolPerWindow: 1,
        maxConcurrentOffensive: 1,
        maxConcurrentPerTool: 1,
        backoffBaseMs: 5_000,
        backoffMaxMs: 5_000,
      });

      const startup = runtime.initialize();
      if (!startup.ok) {
        offensive_registry_static = false;
        errors.push(`offensive runtime failed startup: ${startup.code}`);
      } else {
        const unknown = runtime.prepareExecution({
          tool: "unknown.run",
          args: {},
          requestId: "validate-phase27-unknown",
          principalId: "phase27",
        });
        if (unknown.code !== "UNREGISTERED_OFFENSIVE_TOOL") {
          offensive_registry_static = false;
          errors.push("unknown offensive tool was not rejected");
        }

        const missingRequired = runtime.prepareExecution({
          tool: "nmap.run",
          args: {},
          requestId: "validate-phase27-missing-arg",
          principalId: "phase27",
        });
        if (missingRequired.code !== "OFFENSIVE_ARGUMENTS_INVALID") {
          arguments_schema_enforced = false;
          errors.push("missing required offensive argument was not rejected");
        }

        const shellChars = runtime.prepareExecution({
          tool: "nmap.run",
          args: { target: "scanme.nmap.org;uname -a" },
          requestId: "validate-phase27-shell-arg",
          principalId: "phase27",
        });
        if (shellChars.code !== "OFFENSIVE_ARGUMENTS_INVALID") {
          arguments_schema_enforced = false;
          errors.push("shell-style offensive argument was not rejected");
        }

        const sqlmapDenied = runtime.prepareExecution({
          tool: "sqlmap.run",
          args: { url: "https://example.com/?id=1", flags: ["--os-shell"] },
          requestId: "validate-phase27-sqlmap-denied",
          principalId: "phase27",
        });
        if (sqlmapDenied.code !== "OFFENSIVE_ARGUMENTS_INVALID") {
          arguments_schema_enforced = false;
          errors.push("sqlmap denied flag was not rejected");
        }

        const targetViolation = runtime.prepareExecution({
          tool: "nmap.run",
          args: { target: "localhost" },
          requestId: "validate-phase27-target",
          principalId: "phase27",
        });
        if (targetViolation.code !== "OFFENSIVE_TARGET_INVALID") {
          network_policy_enforced = false;
          errors.push("localhost target was not rejected");
        }

        const protocolViolation = runtime.prepareExecution({
          tool: "nmap.run",
          args: { target: "scanme.nmap.org", protocol: "http" },
          requestId: "validate-phase27-protocol",
          principalId: "phase27",
        });
        if (protocolViolation.code !== "OFFENSIVE_PROTOCOL_NOT_ALLOWED" && protocolViolation.code !== "OFFENSIVE_ARGUMENTS_INVALID") {
          network_policy_enforced = false;
          errors.push("protocol allowlist violation was not rejected");
        }

        const firstAllowed = runtime.prepareExecution({
          tool: "nmap.run",
          args: makeValidNmapArgs(),
          requestId: "validate-phase27-rate-ok",
          principalId: "phase27",
        });
        if (!firstAllowed.ok || !firstAllowed.leaseId) {
          resource_limits_enforced = false;
          errors.push("baseline offensive prepare failed unexpectedly");
        } else {
          const secondBlocked = runtime.prepareExecution({
            tool: "nmap.run",
            args: makeValidNmapArgs(),
            requestId: "validate-phase27-rate-block",
            principalId: "phase27",
          });
          if (secondBlocked.code !== "OFFENSIVE_RATE_LIMIT_EXCEEDED") {
            resource_limits_enforced = false;
            errors.push("offensive per-tool rate limit was not enforced");
          }
          const backoffBlocked = runtime.prepareExecution({
            tool: "nmap.run",
            args: makeValidNmapArgs(),
            requestId: "validate-phase27-backoff",
            principalId: "phase27",
          });
          if (backoffBlocked.code !== "OFFENSIVE_BACKOFF_ACTIVE") {
            resource_limits_enforced = false;
            errors.push("offensive backoff was not enforced");
          }
          runtime.completeExecution({ leaseId: firstAllowed.leaseId, status: "success" });
        }
      }

      const runtimeForConcurrency = createOffensiveDomainRuntime({
        production: false,
        manifestPath: loadedOffensive.manifestPath,
        hashPath: loadedOffensive.hashPath,
        signaturePath: loadedOffensive.signaturePath,
        publicKeyPath: loadedOffensive.publicKeyPath,
        expectedManifestHash: loadedOffensive.canonicalPayloadHash,
        maxPerToolPerWindow: 10,
        maxConcurrentOffensive: 1,
        maxConcurrentPerTool: 1,
      });
      const startupConcurrency = runtimeForConcurrency.initialize();
      if (!startupConcurrency.ok) {
        resource_limits_enforced = false;
        errors.push("offensive runtime (concurrency) failed startup");
      } else {
        const running = runtimeForConcurrency.prepareExecution({
          tool: "nmap.run",
          args: makeValidNmapArgs(),
          requestId: "validate-phase27-concurrency-ok",
          principalId: "phase27",
        });
        const blocked = runtimeForConcurrency.prepareExecution({
          tool: "sqlmap.run",
          args: { url: "https://example.com/?id=1", method: "GET", flags: ["--batch"] },
          requestId: "validate-phase27-concurrency-block",
          principalId: "phase27",
        });
        if (running.ok && running.leaseId) {
          runtimeForConcurrency.completeExecution({ leaseId: running.leaseId, status: "success" });
        }
        if (blocked.code !== "OFFENSIVE_CONCURRENCY_EXCEEDED") {
          resource_limits_enforced = false;
          errors.push("offensive global concurrency limit was not enforced");
        }
      }

      const runtimeUntrusted = createOffensiveDomainRuntime({
        production: false,
        manifestPath: loadedOffensive.manifestPath,
        hashPath: loadedOffensive.hashPath,
        signaturePath: loadedOffensive.signaturePath,
        publicKeyPath: loadedOffensive.publicKeyPath,
        expectedManifestHash: "0".repeat(64),
      });
      const untrustedPrepare = runtimeUntrusted.prepareExecution({
        tool: "nmap.run",
        args: makeValidNmapArgs(),
        requestId: "validate-phase27-untrusted",
        principalId: "phase27",
      });
      if (untrustedPrepare.code !== "OFFENSIVE_DOMAIN_NOT_TRUSTED") {
        router_only_enforcement_preserved = false;
        errors.push("offensive domain was not fail-closed when manifest trust failed");
      }
    }

    if (
      !/createOffensiveDomainRuntime/.test(routerSource) ||
      !/offensiveDomainRuntime\.prepareExecution/.test(routerSource) ||
      !/OFFENSIVE_DOMAIN_NOT_TRUSTED/.test(routerSource) ||
      !/OFFENSIVE_ARGUMENTS_INVALID/.test(routerSource)
    ) {
      router_only_enforcement_preserved = false;
      errors.push("execution router offensive enforcement integration missing");
    }
    if (!/allowProductionPathOverride:\s*false/.test(routerSource)) {
      router_only_enforcement_preserved = false;
      errors.push("router allows offensive production path override");
    }

    if (/OFFENSIVE_|offensiveDomainRuntime|prepareExecution/.test(clusterManagerSource)) {
      no_control_plane_drift = false;
      errors.push("cluster manager contains offensive policy logic");
    }

    try {
      const diff = execSync(`git -C ${JSON.stringify(root)} diff --name-only`, {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      });
      const changed = diff
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean);
      if (changed.includes("cluster/cluster-manager.js") || changed.includes("openclaw-bridge/cluster/cluster-manager.js")) {
        no_control_plane_drift = false;
        errors.push("cluster-manager.js has local modifications");
      }
    } catch (error) {
      no_control_plane_drift = false;
      errors.push(`unable to verify control-plane drift: ${error instanceof Error ? error.message : String(error)}`);
    }
  } catch (error) {
    offensive_registry_static = false;
    no_shell_execution_paths = false;
    arguments_schema_enforced = false;
    container_digests_pinned = false;
    isolation_constraints_enforced = false;
    network_policy_enforced = false;
    resource_limits_enforced = false;
    router_only_enforcement_preserved = false;
    no_control_plane_drift = false;
    errors.push(error instanceof Error ? error.message : String(error));
  }

  process.stdout.write(
    `${JSON.stringify(
      {
        offensive_registry_static,
        no_shell_execution_paths,
        arguments_schema_enforced,
        container_digests_pinned,
        isolation_constraints_enforced,
        network_policy_enforced,
        resource_limits_enforced,
        router_only_enforcement_preserved,
        no_control_plane_drift,
        errors,
      },
      null,
      2,
    )}\n`,
  );
}

main().catch((error) => {
  process.stdout.write(
    `${JSON.stringify(
      {
        offensive_registry_static: false,
        no_shell_execution_paths: false,
        arguments_schema_enforced: false,
        container_digests_pinned: false,
        isolation_constraints_enforced: false,
        network_policy_enforced: false,
        resource_limits_enforced: false,
        router_only_enforcement_preserved: false,
        no_control_plane_drift: false,
        errors: [error instanceof Error ? error.message : String(error)],
      },
      null,
      2,
    )}\n`,
  );
  process.exit(1);
});
