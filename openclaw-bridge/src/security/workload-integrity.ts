import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  WorkloadManifest,
  WorkloadManifestEntry,
  computeWorkloadManifestHash,
  loadWorkloadManifestFromDisk,
} from "./workload-manifest";

export interface WorkloadIntegrityContext {
  requestId?: string;
  workspaceRoot?: string;
  source?: string;
  caller?: string;
  transportMetadata?: Record<string, unknown>;
}

export interface WorkloadRuntimeDescriptor {
  adapterPath: string;
  entrypointPath: string;
  runtimeConfig: unknown;
  containerImageDigest?: string;
  runtimeMutated?: boolean;
}

export interface WorkloadIntegrityMetrics {
  increment?: (name: string, labels?: Record<string, unknown>) => void;
  gauge?: (name: string, value: number, labels?: Record<string, unknown>) => void;
}

export interface WorkloadAuditEvent {
  event: string;
  status: "ok" | "warning" | "error";
  code?: string;
  details?: Record<string, unknown>;
}

export interface WorkloadIntegrityVerifierOptions {
  production?: boolean;
  nodeId?: string;
  manifestPath?: string;
  expectedHash?: string;
  allowProductionPathOverride?: boolean;
  runtimeDescriptorResolver: (tool: string, context: WorkloadIntegrityContext) => WorkloadRuntimeDescriptor | null;
  metrics?: WorkloadIntegrityMetrics;
  auditLog?: (event: WorkloadAuditEvent) => void;
}

export interface WorkloadVerificationResult {
  ok: boolean;
  code: string;
  message: string;
  details: Record<string, unknown>;
}

export interface WorkloadPeerSummary {
  ok: boolean;
  status: "aligned" | "mismatch" | "not_evaluated";
  criticalMismatches: Array<Record<string, unknown>>;
  warnings: Array<Record<string, unknown>>;
  timestamp: number;
}

export interface WorkloadIntegrityVerifier {
  initialize: () => WorkloadVerificationResult;
  verifyExecution: (input: { tool: string; context: WorkloadIntegrityContext }) => WorkloadVerificationResult;
  assertExecutionAllowed: (input: { tool: string; context: WorkloadIntegrityContext }) => void;
  evaluatePeerWorkloadPosture: (peers?: Array<Record<string, unknown>>) => WorkloadPeerSummary;
  getActiveMetadata: () => {
    nodeId: string;
    workloadManifestHash: string;
    workloadManifestLoaded: boolean;
    startupVerified: boolean;
    blocked: boolean;
    blockedReason: string;
  };
  isVerified: () => boolean;
}

function normalizeString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function normalizeHash(value: unknown): string {
  return normalizeString(value).toLowerCase();
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value
      .map((entry) => canonicalize(entry))
      .sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
  }
  if (!isPlainObject(value)) {
    return value;
  }

  const ordered: Record<string, unknown> = {};
  for (const key of Object.keys(value).sort((left, right) => left.localeCompare(right))) {
    ordered[key] = canonicalize(value[key]);
  }
  return ordered;
}

function computeSha256HexFromBuffer(buffer: Buffer): string {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function computeSha256HexFromObject(value: unknown): string {
  const canonical = canonicalize(value);
  return crypto.createHash("sha256").update(JSON.stringify(canonical), "utf8").digest("hex");
}

function computeFileHash(filePath: string): string {
  const resolvedPath = path.resolve(filePath);
  return computeSha256HexFromBuffer(fs.readFileSync(resolvedPath));
}

function normalizeDigest(value: unknown): string {
  const source = normalizeString(value).toLowerCase();
  if (!source) {
    return "";
  }
  if (/^sha256:[a-f0-9]{64}$/.test(source)) {
    return source;
  }
  const anchoredDigest = source.match(/@sha256:([a-f0-9]{64})/);
  if (anchoredDigest && anchoredDigest[1]) {
    return `sha256:${anchoredDigest[1]}`;
  }
  return "";
}

function isTagReference(value: unknown): boolean {
  const source = normalizeString(value);
  if (!source) {
    return false;
  }
  if (/^sha256:[a-f0-9]{64}$/i.test(source)) {
    return false;
  }
  if (source.includes("@sha256:")) {
    return false;
  }
  const slashSegment = source.split("/").at(-1) || "";
  return slashSegment.includes(":");
}

function makeError(code: string, message: string, details: Record<string, unknown> = {}): Error {
  const error = new Error(String(message || "Workload integrity failure"));
  (error as Error & { code?: string; details?: unknown }).code = code;
  (error as Error & { code?: string; details?: unknown }).details = details;
  return error;
}

function makeResult(code: string, message: string, details: Record<string, unknown> = {}, ok = false): WorkloadVerificationResult {
  return {
    ok,
    code,
    message,
    details,
  };
}

function createSafeMetrics(metrics?: WorkloadIntegrityMetrics): Required<WorkloadIntegrityMetrics> {
  const source = metrics && typeof metrics === "object" ? metrics : {};
  return {
    increment: (name, labels = {}) => {
      try {
        source.increment?.(name, labels);
      } catch {
        // fail-open metrics
      }
    },
    gauge: (name, value, labels = {}) => {
      try {
        source.gauge?.(name, value, labels);
      } catch {
        // fail-open metrics
      }
    },
  };
}

function createSafeAudit(log?: (event: WorkloadAuditEvent) => void): (event: WorkloadAuditEvent) => void {
  return (event) => {
    try {
      log?.(event);
    } catch {
      // fail-open audit
    }
  };
}

function mismatchForRecord(
  record: WorkloadManifestEntry,
  code: string,
  message: string,
  details: Record<string, unknown>,
): WorkloadVerificationResult {
  return makeResult(code, message, {
    workloadID: record.workloadID,
    ...details,
  });
}

export function createWorkloadIntegrityVerifier(options: WorkloadIntegrityVerifierOptions): WorkloadIntegrityVerifier {
  const production = options.production === true || normalizeString(process.env.NODE_ENV).toLowerCase() === "production";
  const nodeId = normalizeString(options.nodeId || process.env.SUPERVISOR_NODE_ID) || "node-unknown";
  const expectedHash = normalizeHash(options.expectedHash || process.env.WORKLOAD_MANIFEST_EXPECTED_HASH);
  const metrics = createSafeMetrics(options.metrics);
  const audit = createSafeAudit(options.auditLog);

  const runtimeDescriptorResolver = options.runtimeDescriptorResolver;
  if (typeof runtimeDescriptorResolver !== "function") {
    throw makeError("WORKLOAD_RESOLVER_INVALID", "runtimeDescriptorResolver is required", {});
  }

  let initialized = false;
  let startupVerified = false;
  let blocked = false;
  let blockedReason = "";
  let manifestHash = "";
  let manifest: WorkloadManifest | null = null;
  let workloadMap = new Map<string, WorkloadManifestEntry>();
  let peerSummary: WorkloadPeerSummary = {
    ok: true,
    status: "not_evaluated",
    criticalMismatches: [],
    warnings: [],
    timestamp: Date.now(),
  };

  function setBlocked(code: string, details: Record<string, unknown>): void {
    blocked = true;
    blockedReason = code;
    metrics.increment("workload.integrity.block", {
      node_id: nodeId,
      reason: code,
    });
    audit({
      event: "workload_drift_block",
      status: "error",
      code,
      details,
    });
  }

  function verifyRecord(
    record: WorkloadManifestEntry,
    descriptor: WorkloadRuntimeDescriptor,
    context: WorkloadIntegrityContext,
  ): WorkloadVerificationResult {
    const adapterPath = normalizeString(descriptor.adapterPath);
    const entrypointPath = normalizeString(descriptor.entrypointPath);

    if (!adapterPath || !entrypointPath) {
      return mismatchForRecord(record, "WORKLOAD_MUTATION_DETECTED", "Workload descriptor is incomplete", {
        adapterPath,
        entrypointPath,
        requestId: normalizeString(context.requestId),
        caller: normalizeString(context.caller),
        source: normalizeString(context.source),
      });
    }

    if (descriptor.runtimeMutated === true) {
      return mismatchForRecord(record, "WORKLOAD_MUTATION_DETECTED", "Runtime mutation detected", {
        adapterPath: path.resolve(adapterPath),
        entrypointPath: path.resolve(entrypointPath),
        requestId: normalizeString(context.requestId),
      });
    }

    let adapterHash = "";
    let entrypointHash = "";
    let runtimeConfigHash = "";

    try {
      adapterHash = computeFileHash(adapterPath);
    } catch (error) {
      return mismatchForRecord(record, "WORKLOAD_HASH_MISMATCH", "Adapter hash computation failed", {
        adapterPath: path.resolve(adapterPath),
        reason: error instanceof Error ? error.message : String(error),
      });
    }

    try {
      entrypointHash = computeFileHash(entrypointPath);
    } catch (error) {
      return mismatchForRecord(record, "WORKLOAD_HASH_MISMATCH", "Entrypoint hash computation failed", {
        entrypointPath: path.resolve(entrypointPath),
        reason: error instanceof Error ? error.message : String(error),
      });
    }

    try {
      runtimeConfigHash = computeSha256HexFromObject(descriptor.runtimeConfig || {});
    } catch (error) {
      return mismatchForRecord(record, "WORKLOAD_HASH_MISMATCH", "Runtime config hash computation failed", {
        reason: error instanceof Error ? error.message : String(error),
      });
    }

    if (normalizeHash(record.adapterHash) !== adapterHash) {
      return mismatchForRecord(record, "WORKLOAD_HASH_MISMATCH", "Adapter hash mismatch", {
        expectedAdapterHash: normalizeHash(record.adapterHash),
        actualAdapterHash: adapterHash,
        adapterPath: path.resolve(adapterPath),
      });
    }

    if (normalizeHash(record.entrypointHash) !== entrypointHash) {
      return mismatchForRecord(record, "WORKLOAD_HASH_MISMATCH", "Entrypoint hash mismatch", {
        expectedEntrypointHash: normalizeHash(record.entrypointHash),
        actualEntrypointHash: entrypointHash,
        entrypointPath: path.resolve(entrypointPath),
      });
    }

    if (normalizeHash(record.runtimeConfigHash) !== runtimeConfigHash) {
      return mismatchForRecord(record, "WORKLOAD_HASH_MISMATCH", "Runtime config hash mismatch", {
        expectedRuntimeConfigHash: normalizeHash(record.runtimeConfigHash),
        actualRuntimeConfigHash: runtimeConfigHash,
      });
    }

    if (record.containerImageDigest) {
      const expectedDigest = normalizeDigest(record.containerImageDigest);
      const actualDigest = normalizeDigest(descriptor.containerImageDigest);

      if (production && isTagReference(descriptor.containerImageDigest)) {
        return mismatchForRecord(record, "WORKLOAD_IMAGE_MISMATCH", "Tag-based container image references are forbidden in production", {
          expectedContainerImageDigest: expectedDigest,
          actualContainerImageDigest: normalizeString(descriptor.containerImageDigest),
          reason: "tag_reference_forbidden",
        });
      }

      if (!actualDigest || actualDigest !== expectedDigest) {
        return mismatchForRecord(record, "WORKLOAD_IMAGE_MISMATCH", "Container image digest mismatch", {
          expectedContainerImageDigest: expectedDigest,
          actualContainerImageDigest: actualDigest || normalizeString(descriptor.containerImageDigest),
        });
      }
    }

    return makeResult(
      "WORKLOAD_HASH_VERIFIED",
      "Workload integrity verified",
      {
        workloadID: record.workloadID,
        adapterHash,
        entrypointHash,
        runtimeConfigHash,
        containerImageDigest: record.containerImageDigest ? normalizeDigest(descriptor.containerImageDigest) : "",
      },
      true,
    );
  }

  function initialize(): WorkloadVerificationResult {
    try {
      if (production && !expectedHash) {
        throw makeError("WORKLOAD_MANIFEST_MISMATCH", "WORKLOAD_MANIFEST_EXPECTED_HASH is required in production", {});
      }

      const loadedManifest = loadWorkloadManifestFromDisk({
        manifestPath: options.manifestPath,
        production,
        allowProductionPathOverride: options.allowProductionPathOverride,
      });
      const computedHash = computeWorkloadManifestHash(loadedManifest);

      if (expectedHash && expectedHash !== computedHash) {
        throw makeError("WORKLOAD_MANIFEST_MISMATCH", "Workload manifest hash mismatch", {
          expectedHash,
          actualHash: computedHash,
        });
      }

      manifest = loadedManifest;
      manifestHash = computedHash;
      workloadMap = new Map(
        loadedManifest.workloads.map((entry) => [normalizeString(entry.workloadID), entry]),
      );
      initialized = true;
      startupVerified = true;
      blocked = false;
      blockedReason = "";

      metrics.gauge("workload.manifest.hash", 1, {
        node_id: nodeId,
        workload_manifest_hash: manifestHash,
      });

      for (const record of loadedManifest.workloads) {
        if (!record.productionRequired) {
          continue;
        }
        const descriptor = runtimeDescriptorResolver(record.workloadID, {
          requestId: "startup",
          source: "startup",
          caller: "workload_integrity",
        });

        if (!descriptor) {
          startupVerified = false;
          const failure = makeResult(
            "WORKLOAD_NOT_VERIFIED",
            "Workload descriptor is not resolvable at startup",
            {
              workloadID: record.workloadID,
            },
          );
          metrics.increment("workload.attestation.failure", {
            node_id: nodeId,
            workload_id: record.workloadID,
            code: failure.code,
          });
          audit({
            event: "workload_hash_verification",
            status: production ? "error" : "warning",
            code: failure.code,
            details: failure.details,
          });
          if (production) {
            setBlocked(failure.code, failure.details);
            return failure;
          }
          continue;
        }

        const verification = verifyRecord(record, descriptor, {
          requestId: "startup",
          source: "startup",
          caller: "workload_integrity",
        });

        if (!verification.ok) {
          startupVerified = false;
          metrics.increment(
            verification.code === "WORKLOAD_IMAGE_MISMATCH" ? "workload.image.mismatch" : "workload.hash.mismatch",
            {
              node_id: nodeId,
              workload_id: record.workloadID,
              code: verification.code,
            },
          );
          metrics.increment("workload.attestation.failure", {
            node_id: nodeId,
            workload_id: record.workloadID,
            code: verification.code,
          });
          audit({
            event: "workload_hash_verification",
            status: production ? "error" : "warning",
            code: verification.code,
            details: verification.details,
          });
          if (production) {
            setBlocked(verification.code, verification.details);
            return verification;
          }
        } else {
          metrics.increment("workload.hash.verified", {
            node_id: nodeId,
            workload_id: record.workloadID,
          });
        }
      }

      return makeResult(
        "WORKLOAD_HASH_VERIFIED",
        "Workload integrity initialized",
        {
          workloadManifestHash: manifestHash,
          workloadCount: loadedManifest.workloads.length,
          startupVerified,
        },
        true,
      );
    } catch (error) {
      initialized = false;
      startupVerified = false;

      const code =
        error && typeof error === "object" && "code" in error && typeof (error as { code?: unknown }).code === "string"
          ? String((error as { code?: unknown }).code)
          : "WORKLOAD_NOT_VERIFIED";
      const details =
        error && typeof error === "object" && "details" in error && isPlainObject((error as { details?: unknown }).details)
          ? ((error as { details?: unknown }).details as Record<string, unknown>)
          : {};
      const result = makeResult(
        code,
        error instanceof Error ? error.message : "Workload integrity initialization failed",
        details,
      );

      metrics.increment("workload.attestation.failure", {
        node_id: nodeId,
        code,
      });
      audit({
        event: "workload_manifest_validation",
        status: production ? "error" : "warning",
        code,
        details,
      });

      if (production) {
        setBlocked(code, details);
      }

      return result;
    }
  }

  function verifyExecution(input: { tool: string; context: WorkloadIntegrityContext }): WorkloadVerificationResult {
    const tool = normalizeString(input.tool);
    const context = input.context && typeof input.context === "object" ? input.context : {};

    if (!initialized) {
      const startup = initialize();
      if (!startup.ok && production) {
        return startup;
      }
    }

    if (!initialized || !manifest) {
      return makeResult("WORKLOAD_NOT_VERIFIED", "Workload integrity is not initialized", {
        tool,
      });
    }

    if (blocked && production) {
      return makeResult("WORKLOAD_NOT_VERIFIED", "Workload integrity is blocked", {
        blockedReason,
        workloadManifestHash: manifestHash,
      });
    }

    if (!tool) {
      return makeResult("WORKLOAD_NOT_VERIFIED", "Tool name is required for workload integrity", {
        workloadManifestHash: manifestHash,
      });
    }

    const record = workloadMap.get(tool);
    if (!record) {
      const result = makeResult("WORKLOAD_NOT_VERIFIED", "Tool is not present in workload manifest", {
        tool,
        workloadManifestHash: manifestHash,
      });
      metrics.increment("workload.hash.mismatch", {
        node_id: nodeId,
        workload_id: tool,
        code: result.code,
      });
      metrics.increment("workload.attestation.failure", {
        node_id: nodeId,
        workload_id: tool,
        code: result.code,
      });
      audit({
        event: "workload_hash_verification",
        status: production ? "error" : "warning",
        code: result.code,
        details: result.details,
      });
      if (production) {
        setBlocked(result.code, result.details);
      }
      return result;
    }

    const descriptor = runtimeDescriptorResolver(tool, context);
    if (!descriptor) {
      const result = makeResult("WORKLOAD_MUTATION_DETECTED", "Workload runtime descriptor is not resolvable", {
        tool,
        workloadManifestHash: manifestHash,
        requestId: normalizeString(context.requestId),
        caller: normalizeString(context.caller),
        source: normalizeString(context.source),
      });
      metrics.increment("workload.hash.mismatch", {
        node_id: nodeId,
        workload_id: tool,
        code: result.code,
      });
      metrics.increment("workload.mutation.detected", {
        node_id: nodeId,
        workload_id: tool,
      });
      metrics.increment("workload.attestation.failure", {
        node_id: nodeId,
        workload_id: tool,
        code: result.code,
      });
      audit({
        event: "workload_hash_verification",
        status: production ? "error" : "warning",
        code: result.code,
        details: result.details,
      });
      if (production) {
        setBlocked(result.code, result.details);
      }
      return result;
    }

    const verification = verifyRecord(record, descriptor, context);
    if (!verification.ok) {
      metrics.increment(
        verification.code === "WORKLOAD_IMAGE_MISMATCH" ? "workload.image.mismatch" : "workload.hash.mismatch",
        {
          node_id: nodeId,
          workload_id: tool,
          code: verification.code,
        },
      );
      if (verification.code === "WORKLOAD_MUTATION_DETECTED") {
        metrics.increment("workload.mutation.detected", {
          node_id: nodeId,
          workload_id: tool,
        });
      }
      metrics.increment("workload.attestation.failure", {
        node_id: nodeId,
        workload_id: tool,
        code: verification.code,
      });
      audit({
        event: "workload_hash_verification",
        status: production ? "error" : "warning",
        code: verification.code,
        details: verification.details,
      });
      if (production) {
        setBlocked(verification.code, verification.details);
      }
      return verification;
    }

    metrics.increment("workload.hash.verified", {
      node_id: nodeId,
      workload_id: tool,
    });
    audit({
      event: "workload_hash_verification",
      status: "ok",
      code: verification.code,
      details: verification.details,
    });
    return verification;
  }

  function assertExecutionAllowed(input: { tool: string; context: WorkloadIntegrityContext }): void {
    const result = verifyExecution(input);
    if (result.ok) {
      return;
    }
    throw makeError(result.code, result.message, result.details);
  }

  function evaluatePeerWorkloadPosture(peers: Array<Record<string, unknown>> = []): WorkloadPeerSummary {
    const now = Date.now();
    const criticalMismatches: Array<Record<string, unknown>> = [];
    const warnings: Array<Record<string, unknown>> = [];

    if (!initialized || !manifestHash) {
      const missingLocal = {
        classification: "MISSING_WORKLOAD_MANIFEST",
        peerId: "local",
      };
      if (production) {
        criticalMismatches.push(missingLocal);
      } else {
        warnings.push(missingLocal);
      }

      peerSummary = {
        ok: criticalMismatches.length === 0,
        status: criticalMismatches.length > 0 ? "mismatch" : "aligned",
        criticalMismatches,
        warnings,
        timestamp: now,
      };
      return peerSummary;
    }

    const healthyPeers = Array.isArray(peers)
      ? peers.filter((peer) => normalizeString(peer && peer.status).toUpperCase() === "UP")
      : [];

    for (const peer of healthyPeers) {
      const peerId = normalizeString(peer.peerId) || "unknown-peer";
      const peerHash = normalizeHash(peer.workloadManifestHash || (peer as Record<string, unknown>).workload_manifest_hash);

      if (!/^[a-f0-9]{64}$/.test(peerHash)) {
        const mismatch = {
          classification: "MISSING_WORKLOAD_MANIFEST",
          peerId,
          localWorkloadManifestHash: manifestHash,
        };
        if (production) {
          criticalMismatches.push(mismatch);
        } else {
          warnings.push(mismatch);
        }
        continue;
      }

      if (peerHash !== manifestHash) {
        const mismatch = {
          classification: "WORKLOAD_MANIFEST_MISMATCH",
          peerId,
          localWorkloadManifestHash: manifestHash,
          peerWorkloadManifestHash: peerHash,
        };
        metrics.increment("workload.manifest.hash.mismatch", {
          node_id: nodeId,
          peer_id: peerId,
        });
        if (production) {
          criticalMismatches.push(mismatch);
        } else {
          warnings.push(mismatch);
        }
      }
    }

    peerSummary = {
      ok: criticalMismatches.length === 0,
      status: criticalMismatches.length > 0 ? "mismatch" : "aligned",
      criticalMismatches,
      warnings,
      timestamp: now,
    };

    if (production && criticalMismatches.length > 0) {
      setBlocked("WORKLOAD_MANIFEST_MISMATCH", {
        nodeId,
        criticalMismatches,
      });
      audit({
        event: "workload_drift_block",
        status: "error",
        code: "WORKLOAD_MANIFEST_MISMATCH",
        details: {
          nodeId,
          criticalMismatches,
        },
      });
    }

    return peerSummary;
  }

  function getActiveMetadata() {
    return {
      nodeId,
      workloadManifestHash: manifestHash,
      workloadManifestLoaded: initialized,
      startupVerified,
      blocked,
      blockedReason,
    };
  }

  function isVerified(): boolean {
    if (!initialized) {
      return false;
    }
    if (production && blocked) {
      return false;
    }
    return true;
  }

  return {
    initialize,
    verifyExecution,
    assertExecutionAllowed,
    evaluatePeerWorkloadPosture,
    getActiveMetadata,
    isVerified,
  };
}
