import crypto, { KeyObject } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const REQUIRED_REFERENCE_KEYS = Object.freeze([
  "referenceVersion",
  "executionPolicyHash",
  "secretManifestHash",
  "workloadManifestHash",
  "evidenceTtlMs",
]);
const DEFAULT_EVIDENCE_TTL_MS = 120_000;
const MAX_EVIDENCE_TTL_MS = 300_000;
const DEFAULT_MAX_FUTURE_SKEW_MS = 5_000;

export interface WorkloadAttestationReference {
  referenceVersion: number;
  executionPolicyHash: string;
  secretManifestHash: string;
  workloadManifestHash: string;
  evidenceTtlMs: number;
}

export interface WorkloadAttestationChallenge {
  nonce?: string;
  timestampMs?: number;
}

export interface WorkloadAttestationEvidence {
  nodeId: string;
  workloadManifestHash: string;
  executionPolicyHash: string;
  secretManifestHash: string;
  runtimeMeasurements: Record<string, unknown>;
  snapshotHash: string;
  timestampMs: number;
  expiresAtMs: number;
  nonce: string;
  publicKey: string;
  evidenceHash: string;
  signature: string;
  algorithm: "ed25519";
}

export interface WorkloadAttestationMetrics {
  increment?: (name: string, labels?: Record<string, unknown>) => void;
  gauge?: (name: string, value: number, labels?: Record<string, unknown>) => void;
}

export interface WorkloadAttestationAuditEvent {
  event: string;
  status: "ok" | "warning" | "error";
  code?: string;
  details?: Record<string, unknown>;
}

export interface WorkloadAttestationVerificationResult {
  ok: boolean;
  code: string;
  message: string;
  details: Record<string, unknown>;
}

export interface WorkloadAttestationState {
  nodeId: string;
  trusted: boolean;
  blockedReason: string;
  referenceHash: string;
  lastEvidenceHash: string;
  lastVerifiedAt: number;
  peerTrustMap: Record<string, {
    trusted: boolean;
    failureReason: string;
    evidenceHash: string;
    verifiedAt: number;
    stickyUntrusted: boolean;
  }>;
}

export interface WorkloadAttestationRuntimeOptions {
  production?: boolean;
  nodeId?: string;
  referencePath?: string;
  expectedReferenceHash?: string;
  allowProductionPathOverride?: boolean;
  localMetadataProvider?: () => Record<string, unknown>;
  metrics?: WorkloadAttestationMetrics;
  auditLog?: (event: WorkloadAttestationAuditEvent) => void;
}

export interface WorkloadAttestationVerifyContext {
  challenge?: WorkloadAttestationChallenge;
  nowMs?: number;
  maxFutureSkewMs?: number;
  replayCache?: Map<string, number>;
}

export interface WorkloadAttestationRuntime {
  initializeAttestation: () => WorkloadAttestationVerificationResult;
  syncLocalAttestationPosture: (localMetadata?: Record<string, unknown>) => WorkloadAttestationVerificationResult;
  generateAttestationEvidence: (
    challenge?: WorkloadAttestationChallenge,
    context?: { localMetadata?: Record<string, unknown>; runtimeMeasurements?: Record<string, unknown> },
  ) => {
    ok: boolean;
    code: string;
    message: string;
    evidence?: WorkloadAttestationEvidence;
    details: Record<string, unknown>;
  };
  verifyAttestationEvidence: (
    evidence: unknown,
    trustedReference?: WorkloadAttestationReference,
    verifyContext?: WorkloadAttestationVerifyContext,
  ) => WorkloadAttestationVerificationResult;
  verifyPeerAttestationEvidence: (
    peerId: string,
    evidence: unknown,
    challenge?: WorkloadAttestationChallenge,
  ) => WorkloadAttestationVerificationResult;
  evaluatePeerAttestationPosture: (peers?: Array<Record<string, unknown>>) => {
    ok: boolean;
    status: "aligned" | "mismatch" | "not_evaluated";
    criticalMismatches: Array<Record<string, unknown>>;
    warnings: Array<Record<string, unknown>>;
    timestamp: number;
  };
  getAttestationState: () => WorkloadAttestationState;
}

interface LoadedReference {
  reference: WorkloadAttestationReference;
  referenceHash: string;
  referencePath: string;
  hashPath: string;
}

function normalizeString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function normalizeHash(value: unknown): string {
  return normalizeString(value).toLowerCase();
}

function parsePositiveInt(value: unknown, fallback: number): number {
  const parsed = Number.parseInt(String(value ?? "").trim(), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((entry) => canonicalize(entry));
  }
  if (!isPlainObject(value)) {
    return value;
  }

  const ordered: Record<string, unknown> = {};
  for (const key of Object.keys(value).sort((a, b) => a.localeCompare(b))) {
    ordered[key] = canonicalize(value[key]);
  }
  return ordered;
}

function sha256Hex(input: string): string {
  return crypto.createHash("sha256").update(input, "utf8").digest("hex");
}

function sha256HexObject(value: unknown): string {
  return sha256Hex(JSON.stringify(canonicalize(value)));
}

function makeResult(
  code: string,
  message: string,
  details: Record<string, unknown> = {},
  ok = false,
): WorkloadAttestationVerificationResult {
  return {
    ok,
    code,
    message,
    details,
  };
}

function resolveProjectRootFromCurrentDir(): string {
  const srcRoot = path.resolve(__dirname, "..", "..");
  const srcCandidate = path.resolve(srcRoot, "security", "workload-attestation-reference.json");
  if (fs.existsSync(srcCandidate)) {
    return srcRoot;
  }
  return path.resolve(__dirname, "..", "..", "..");
}

function resolveDefaultReferencePath(): string {
  return path.resolve(resolveProjectRootFromCurrentDir(), "security", "workload-attestation-reference.json");
}

function resolveDefaultReferenceHashPath(): string {
  return path.resolve(resolveProjectRootFromCurrentDir(), "security", "workload-attestation-reference.hash");
}

function assertProductionPathSafety(selectedPath: string, canonicalPath: string, errorCode: string, message: string): void {
  const resolvedSelected = path.resolve(selectedPath);
  const resolvedCanonical = path.resolve(canonicalPath);

  if (resolvedSelected !== resolvedCanonical) {
    const error = new Error(message) as Error & { code?: string; details?: unknown };
    error.code = errorCode;
    error.details = {
      configuredPath: resolvedSelected,
      requiredPath: resolvedCanonical,
    };
    throw error;
  }

  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(resolvedSelected);
  } catch {
    const error = new Error("Attestation reference file is missing") as Error & { code?: string; details?: unknown };
    error.code = "WORKLOAD_ATTESTATION_REFERENCE_MISSING";
    error.details = {
      referencePath: resolvedSelected,
      requiredPath: resolvedCanonical,
    };
    throw error;
  }

  if (stat.isSymbolicLink()) {
    const error = new Error("Attestation reference file must not be symlinked in production") as Error & {
      code?: string;
      details?: unknown;
    };
    error.code = "WORKLOAD_ATTESTATION_REFERENCE_PATH_OVERRIDE_FORBIDDEN";
    error.details = {
      referencePath: resolvedSelected,
      requiredPath: resolvedCanonical,
    };
    throw error;
  }

  if (!stat.isFile()) {
    const error = new Error("Attestation reference path must reference a regular file") as Error & {
      code?: string;
      details?: unknown;
    };
    error.code = "WORKLOAD_ATTESTATION_REFERENCE_MISSING";
    error.details = {
      referencePath: resolvedSelected,
      requiredPath: resolvedCanonical,
    };
    throw error;
  }

  try {
    fs.accessSync(resolvedSelected, fs.constants.W_OK);
    const error = new Error("Attestation reference file must not be writable in production") as Error & {
      code?: string;
      details?: unknown;
    };
    error.code = "WORKLOAD_ATTESTATION_REFERENCE_WRITABLE_IN_PRODUCTION";
    error.details = {
      referencePath: resolvedSelected,
      requiredPath: resolvedCanonical,
    };
    throw error;
  } catch (error) {
    if (
      error &&
      typeof error === "object" &&
      "code" in error &&
      String((error as { code?: unknown }).code || "") === "WORKLOAD_ATTESTATION_REFERENCE_WRITABLE_IN_PRODUCTION"
    ) {
      throw error;
    }
    // expected when not writable
  }
}

function validateReference(reference: unknown): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  if (!isPlainObject(reference)) {
    return {
      valid: false,
      errors: ["attestation reference must be an object"],
    };
  }

  for (const key of REQUIRED_REFERENCE_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(reference, key)) {
      errors.push(`missing required field '${key}'`);
    }
  }

  const unknown = Object.keys(reference).filter((key) => !REQUIRED_REFERENCE_KEYS.includes(key));
  if (unknown.length > 0) {
    errors.push(`unknown reference fields: ${unknown.join(",")}`);
  }

  const version = Number(reference.referenceVersion);
  if (!Number.isInteger(version) || version <= 0) {
    errors.push("referenceVersion must be a positive integer");
  }

  const policyHash = normalizeHash(reference.executionPolicyHash);
  const secretHash = normalizeHash(reference.secretManifestHash);
  const workloadHash = normalizeHash(reference.workloadManifestHash);

  if (!/^[a-f0-9]{64}$/.test(policyHash)) {
    errors.push("executionPolicyHash must be a 64-character lowercase hex string");
  }
  if (!/^[a-f0-9]{64}$/.test(secretHash)) {
    errors.push("secretManifestHash must be a 64-character lowercase hex string");
  }
  if (!/^[a-f0-9]{64}$/.test(workloadHash)) {
    errors.push("workloadManifestHash must be a 64-character lowercase hex string");
  }

  const evidenceTtlMs = parsePositiveInt(reference.evidenceTtlMs, 0);
  if (evidenceTtlMs <= 0 || evidenceTtlMs > MAX_EVIDENCE_TTL_MS) {
    errors.push(`evidenceTtlMs must be between 1 and ${MAX_EVIDENCE_TTL_MS}`);
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

function getCanonicalReference(reference: unknown): WorkloadAttestationReference {
  const validation = validateReference(reference);
  if (!validation.valid) {
    const error = new Error("Attestation reference schema invalid") as Error & { code?: string; details?: unknown };
    error.code = "WORKLOAD_ATTESTATION_REFERENCE_SCHEMA_INVALID";
    error.details = {
      errors: validation.errors,
    };
    throw error;
  }

  const input = reference as WorkloadAttestationReference;
  return {
    referenceVersion: Number(input.referenceVersion),
    executionPolicyHash: normalizeHash(input.executionPolicyHash),
    secretManifestHash: normalizeHash(input.secretManifestHash),
    workloadManifestHash: normalizeHash(input.workloadManifestHash),
    evidenceTtlMs: parsePositiveInt(input.evidenceTtlMs, DEFAULT_EVIDENCE_TTL_MS),
  };
}

export function computeAttestationReferenceHash(reference: unknown): string {
  return sha256HexObject(getCanonicalReference(reference));
}

export function resolveDefaultAttestationReferencePath(): string {
  return resolveDefaultReferencePath();
}

export function loadAttestationReferenceFromDisk(options: {
  referencePath?: string;
  expectedHash?: string;
  production?: boolean;
  allowProductionPathOverride?: boolean;
} = {}): LoadedReference {
  const production = options.production === true || normalizeString(process.env.NODE_ENV).toLowerCase() === "production";
  const defaultPath = resolveDefaultReferencePath();
  const defaultHashPath = resolveDefaultReferenceHashPath();
  const configuredPath = normalizeString(options.referencePath || process.env.WORKLOAD_ATTESTATION_REFERENCE_PATH);
  const selectedPath = configuredPath || defaultPath;

  if (production && configuredPath && options.allowProductionPathOverride !== true && path.resolve(configuredPath) !== path.resolve(defaultPath)) {
    const error = new Error("Attestation reference path override is forbidden in production") as Error & {
      code?: string;
      details?: unknown;
    };
    error.code = "WORKLOAD_ATTESTATION_REFERENCE_PATH_OVERRIDE_FORBIDDEN";
    error.details = {
      configuredPath: path.resolve(configuredPath),
      requiredPath: path.resolve(defaultPath),
    };
    throw error;
  }

  if (production && options.allowProductionPathOverride !== true) {
    assertProductionPathSafety(
      selectedPath,
      defaultPath,
      "WORKLOAD_ATTESTATION_REFERENCE_PATH_OVERRIDE_FORBIDDEN",
      "Attestation reference path override is forbidden in production",
    );
    assertProductionPathSafety(
      defaultHashPath,
      defaultHashPath,
      "WORKLOAD_ATTESTATION_REFERENCE_HASH_MISSING",
      "Attestation reference hash path override is forbidden in production",
    );
  }

  if (!fs.existsSync(path.resolve(selectedPath))) {
    const error = new Error("Attestation reference file is missing") as Error & { code?: string; details?: unknown };
    error.code = "WORKLOAD_ATTESTATION_REFERENCE_MISSING";
    error.details = {
      referencePath: path.resolve(selectedPath),
    };
    throw error;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(fs.readFileSync(path.resolve(selectedPath), "utf8"));
  } catch (error) {
    const wrapped = new Error("Attestation reference JSON could not be parsed") as Error & { code?: string; details?: unknown };
    wrapped.code = "WORKLOAD_ATTESTATION_REFERENCE_SCHEMA_INVALID";
    wrapped.details = {
      referencePath: path.resolve(selectedPath),
      reason: error instanceof Error ? error.message : String(error),
    };
    throw wrapped;
  }

  const canonicalReference = getCanonicalReference(parsed);
  const computedHash = computeAttestationReferenceHash(canonicalReference);

  let expectedHash = "";
  if (production) {
    try {
      expectedHash = normalizeHash(fs.readFileSync(defaultHashPath, "utf8"));
    } catch (error) {
      const wrapped = new Error("Attestation reference hash file is missing") as Error & { code?: string; details?: unknown };
      wrapped.code = "WORKLOAD_ATTESTATION_REFERENCE_HASH_MISSING";
      wrapped.details = {
        hashPath: path.resolve(defaultHashPath),
        reason: error instanceof Error ? error.message : String(error),
      };
      throw wrapped;
    }
    if (!/^[a-f0-9]{64}$/.test(expectedHash)) {
      const error = new Error("Attestation reference hash file is invalid") as Error & { code?: string; details?: unknown };
      error.code = "WORKLOAD_ATTESTATION_REFERENCE_HASH_MISSING";
      error.details = {
        hashPath: path.resolve(defaultHashPath),
      };
      throw error;
    }
  } else {
    expectedHash = normalizeHash(
      options.expectedHash || process.env.WORKLOAD_ATTESTATION_REFERENCE_EXPECTED_HASH || (fs.existsSync(defaultHashPath) ? fs.readFileSync(defaultHashPath, "utf8") : ""),
    );
  }

  if (expectedHash && expectedHash !== computedHash) {
    const error = new Error("Attestation reference hash mismatch") as Error & { code?: string; details?: unknown };
    error.code = "WORKLOAD_ATTESTATION_REFERENCE_MISMATCH";
    error.details = {
      expectedHash,
      actualHash: computedHash,
      referencePath: path.resolve(selectedPath),
    };
    throw error;
  }

  return {
    reference: canonicalReference,
    referenceHash: computedHash,
    referencePath: path.resolve(selectedPath),
    hashPath: path.resolve(defaultHashPath),
  };
}

function normalizeLocalMetadata(input: unknown): {
  executionPolicyHash: string;
  secretManifestHash: string;
  workloadManifestHash: string;
} {
  const source = isPlainObject(input) ? input : {};
  return {
    executionPolicyHash: normalizeHash(source.executionPolicyHash || source.execution_policy_hash),
    secretManifestHash: normalizeHash(source.secretManifestHash || source.secret_manifest_hash),
    workloadManifestHash: normalizeHash(source.workloadManifestHash || source.workload_manifest_hash),
  };
}

function buildSnapshotHash(localMetadata: {
  executionPolicyHash: string;
  secretManifestHash: string;
  workloadManifestHash: string;
}): string {
  return sha256HexObject({
    executionPolicyHash: localMetadata.executionPolicyHash,
    secretManifestHash: localMetadata.secretManifestHash,
    workloadManifestHash: localMetadata.workloadManifestHash,
  });
}

function makeNonce(): string {
  return crypto.randomBytes(16).toString("hex");
}

function toPublicKeyBase64(key: KeyObject): string {
  return key.export({ type: "spki", format: "der" }).toString("base64");
}

function verifySignature(evidenceHash: string, signatureBase64: string, publicKeyBase64: string): boolean {
  try {
    const publicKeyDer = Buffer.from(publicKeyBase64, "base64");
    const signature = Buffer.from(signatureBase64, "base64");
    const key = crypto.createPublicKey({ key: publicKeyDer, type: "spki", format: "der" });
    return crypto.verify(null, Buffer.from(evidenceHash, "utf8"), key, signature);
  } catch {
    return false;
  }
}

export function verifyAttestationEvidence(
  evidenceInput: unknown,
  trustedReference: WorkloadAttestationReference,
  verifyContext: WorkloadAttestationVerifyContext = {},
): WorkloadAttestationVerificationResult {
  const evidence = isPlainObject(evidenceInput) ? (evidenceInput as Record<string, unknown>) : null;
  if (!evidence) {
    return makeResult("WORKLOAD_ATTESTATION_EVIDENCE_INVALID", "Attestation evidence must be an object", {});
  }

  const nodeId = normalizeString(evidence.nodeId);
  const workloadManifestHash = normalizeHash(evidence.workloadManifestHash);
  const executionPolicyHash = normalizeHash(evidence.executionPolicyHash);
  const secretManifestHash = normalizeHash(evidence.secretManifestHash);
  const nonce = normalizeString(evidence.nonce);
  const publicKey = normalizeString(evidence.publicKey);
  const evidenceHash = normalizeHash(evidence.evidenceHash);
  const signature = normalizeString(evidence.signature);
  const algorithm = normalizeString(evidence.algorithm).toLowerCase();
  const timestampMs = Number(evidence.timestampMs);
  const expiresAtMs = Number(evidence.expiresAtMs);
  const runtimeMeasurements = isPlainObject(evidence.runtimeMeasurements)
    ? (evidence.runtimeMeasurements as Record<string, unknown>)
    : {};
  const snapshotHash = normalizeHash(evidence.snapshotHash);

  if (!nodeId || !nonce || !publicKey || !signature || !Number.isFinite(timestampMs) || !Number.isFinite(expiresAtMs)) {
    return makeResult("WORKLOAD_ATTESTATION_EVIDENCE_INVALID", "Attestation evidence is missing required fields", {
      nodeId,
    });
  }

  if (algorithm !== "ed25519") {
    return makeResult("WORKLOAD_ATTESTATION_SIGNATURE_INVALID", "Unsupported attestation signature algorithm", {
      algorithm,
    });
  }

  const canonicalPayload = {
    nodeId,
    workloadManifestHash,
    executionPolicyHash,
    secretManifestHash,
    runtimeMeasurements: canonicalize(runtimeMeasurements) as Record<string, unknown>,
    snapshotHash,
    timestampMs,
    expiresAtMs,
    nonce,
    publicKey,
  };
  const computedEvidenceHash = sha256HexObject(canonicalPayload);

  if (!evidenceHash || computedEvidenceHash !== evidenceHash) {
    return makeResult("WORKLOAD_ATTESTATION_EVIDENCE_INVALID", "Attestation evidence hash mismatch", {
      nodeId,
      expectedEvidenceHash: computedEvidenceHash,
      actualEvidenceHash: evidenceHash,
    });
  }

  if (!verifySignature(evidenceHash, signature, publicKey)) {
    return makeResult("WORKLOAD_ATTESTATION_SIGNATURE_INVALID", "Attestation signature verification failed", {
      nodeId,
      evidenceHash,
    });
  }

  if (workloadManifestHash !== trustedReference.workloadManifestHash) {
    return makeResult("WORKLOAD_ATTESTATION_REFERENCE_MISMATCH", "Workload manifest hash mismatch", {
      nodeId,
      expectedWorkloadManifestHash: trustedReference.workloadManifestHash,
      actualWorkloadManifestHash: workloadManifestHash,
      evidenceHash,
    });
  }
  if (executionPolicyHash !== trustedReference.executionPolicyHash) {
    return makeResult("WORKLOAD_ATTESTATION_REFERENCE_MISMATCH", "Execution policy hash mismatch", {
      nodeId,
      expectedExecutionPolicyHash: trustedReference.executionPolicyHash,
      actualExecutionPolicyHash: executionPolicyHash,
      evidenceHash,
    });
  }
  if (secretManifestHash !== trustedReference.secretManifestHash) {
    return makeResult("WORKLOAD_ATTESTATION_REFERENCE_MISMATCH", "Secret manifest hash mismatch", {
      nodeId,
      expectedSecretManifestHash: trustedReference.secretManifestHash,
      actualSecretManifestHash: secretManifestHash,
      evidenceHash,
    });
  }

  const nowMs = Number.isFinite(Number(verifyContext.nowMs)) ? Number(verifyContext.nowMs) : Date.now();
  const maxFutureSkewMs = parsePositiveInt(verifyContext.maxFutureSkewMs, DEFAULT_MAX_FUTURE_SKEW_MS);
  if (timestampMs > nowMs + maxFutureSkewMs) {
    return makeResult("WORKLOAD_ATTESTATION_STALE", "Attestation timestamp is too far in the future", {
      nodeId,
      timestampMs,
      nowMs,
      evidenceHash,
    });
  }
  if (expiresAtMs < nowMs) {
    return makeResult("WORKLOAD_ATTESTATION_STALE", "Attestation evidence is expired", {
      nodeId,
      expiresAtMs,
      nowMs,
      evidenceHash,
    });
  }

  const ttlMs = expiresAtMs - timestampMs;
  if (ttlMs <= 0 || ttlMs > trustedReference.evidenceTtlMs + maxFutureSkewMs) {
    return makeResult("WORKLOAD_ATTESTATION_STALE", "Attestation evidence TTL is outside allowed range", {
      nodeId,
      ttlMs,
      expectedMaxTtlMs: trustedReference.evidenceTtlMs,
      evidenceHash,
    });
  }

  const challenge = isPlainObject(verifyContext.challenge)
    ? (verifyContext.challenge as WorkloadAttestationChallenge)
    : {};
  const challengeNonce = normalizeString(challenge.nonce);
  if (challengeNonce && challengeNonce !== nonce) {
    return makeResult("WORKLOAD_ATTESTATION_CHALLENGE_MISMATCH", "Attestation nonce does not match challenge", {
      nodeId,
      expectedNonce: challengeNonce,
      actualNonce: nonce,
      evidenceHash,
    });
  }

  const replayCache = verifyContext.replayCache;
  if (replayCache instanceof Map) {
    const replayKey = `${nodeId}:${nonce}`;
    const previousExpiry = Number(replayCache.get(replayKey) || 0);
    if (previousExpiry > nowMs) {
      return makeResult("WORKLOAD_ATTESTATION_REPLAY_DETECTED", "Attestation nonce replay detected", {
        nodeId,
        nonce,
        evidenceHash,
      });
    }
    replayCache.set(replayKey, expiresAtMs);
  }

  return makeResult(
    "WORKLOAD_ATTESTATION_VERIFIED",
    "Attestation evidence verified",
    {
      nodeId,
      evidenceHash,
      expiresAtMs,
      nonce,
    },
    true,
  );
}

function buildSafeMetrics(metrics?: WorkloadAttestationMetrics): Required<WorkloadAttestationMetrics> {
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

function buildSafeAudit(log?: (event: WorkloadAttestationAuditEvent) => void): (event: WorkloadAttestationAuditEvent) => void {
  return (event) => {
    try {
      log?.(event);
    } catch {
      // fail-open audit
    }
  };
}

export function initializeAttestation(options: WorkloadAttestationRuntimeOptions = {}): WorkloadAttestationRuntime {
  const production = options.production === true || normalizeString(process.env.NODE_ENV).toLowerCase() === "production";
  const nodeId = normalizeString(options.nodeId || process.env.SUPERVISOR_NODE_ID) || "node-unknown";
  const metrics = buildSafeMetrics(options.metrics);
  const audit = buildSafeAudit(options.auditLog);

  let keyPair: { publicKey: KeyObject; privateKey: KeyObject } | null = null;
  let reference: WorkloadAttestationReference | null = null;
  let referenceHash = "";
  let initialized = false;
  let trusted = false;
  let blockedReason = "";
  let lastEvidenceHash = "";
  let lastVerifiedAt = 0;
  const replayCache = new Map<string, number>();
  const peerTrustMap = new Map<string, {
    trusted: boolean;
    failureReason: string;
    evidenceHash: string;
    verifiedAt: number;
    stickyUntrusted: boolean;
  }>();

  function pruneReplayCache(nowMs: number): void {
    for (const [key, expiresAtMs] of replayCache.entries()) {
      if (!Number.isFinite(Number(expiresAtMs)) || Number(expiresAtMs) <= nowMs) {
        replayCache.delete(key);
      }
    }
  }

  function setLocalTrust(nextTrusted: boolean, reason = ""): void {
    trusted = nextTrusted;
    blockedReason = nextTrusted ? "" : reason;
    metrics.gauge("workload.attestation.trusted", trusted ? 1 : 0, {
      node_id: nodeId,
    });
  }

  function evaluateLocalMetadata(localMetadataInput: unknown): WorkloadAttestationVerificationResult {
    if (!reference) {
      return makeResult("WORKLOAD_ATTESTATION_NOT_TRUSTED", "Attestation reference is not loaded", {
        nodeId,
      });
    }

    const localMetadata = normalizeLocalMetadata(localMetadataInput);

    if (!localMetadata.executionPolicyHash || !localMetadata.secretManifestHash || !localMetadata.workloadManifestHash) {
      return makeResult("WORKLOAD_ATTESTATION_NOT_TRUSTED", "Attestation metadata is incomplete", {
        nodeId,
        missing: {
          executionPolicyHash: !localMetadata.executionPolicyHash,
          secretManifestHash: !localMetadata.secretManifestHash,
          workloadManifestHash: !localMetadata.workloadManifestHash,
        },
      });
    }

    if (localMetadata.executionPolicyHash !== reference.executionPolicyHash) {
      return makeResult("WORKLOAD_ATTESTATION_REFERENCE_MISMATCH", "Execution policy hash does not match attestation reference", {
        nodeId,
        expectedExecutionPolicyHash: reference.executionPolicyHash,
        actualExecutionPolicyHash: localMetadata.executionPolicyHash,
      });
    }
    if (localMetadata.secretManifestHash !== reference.secretManifestHash) {
      return makeResult("WORKLOAD_ATTESTATION_REFERENCE_MISMATCH", "Secret manifest hash does not match attestation reference", {
        nodeId,
        expectedSecretManifestHash: reference.secretManifestHash,
        actualSecretManifestHash: localMetadata.secretManifestHash,
      });
    }
    if (localMetadata.workloadManifestHash !== reference.workloadManifestHash) {
      return makeResult("WORKLOAD_ATTESTATION_REFERENCE_MISMATCH", "Workload manifest hash does not match attestation reference", {
        nodeId,
        expectedWorkloadManifestHash: reference.workloadManifestHash,
        actualWorkloadManifestHash: localMetadata.workloadManifestHash,
      });
    }

    return makeResult(
      "WORKLOAD_ATTESTATION_VERIFIED",
      "Local attestation metadata matches trusted reference",
      {
        nodeId,
        snapshotHash: buildSnapshotHash(localMetadata),
      },
      true,
    );
  }

  function initializeInternal(): WorkloadAttestationVerificationResult {
    try {
      if (!keyPair) {
        keyPair = crypto.generateKeyPairSync("ed25519");
      }

      const loadedReference = loadAttestationReferenceFromDisk({
        referencePath: options.referencePath,
        expectedHash: options.expectedReferenceHash,
        production,
        allowProductionPathOverride: options.allowProductionPathOverride,
      });

      reference = loadedReference.reference;
      referenceHash = loadedReference.referenceHash;
      initialized = true;
      trusted = false;
      blockedReason = "";
      metrics.gauge("workload.attestation.reference.loaded", 1, {
        node_id: nodeId,
        reference_hash: referenceHash,
      });

      const localMetadata = options.localMetadataProvider ? options.localMetadataProvider() : {};
      const localResult = evaluateLocalMetadata(localMetadata);
      if (!localResult.ok && production) {
        setLocalTrust(false, localResult.code || "WORKLOAD_ATTESTATION_NOT_TRUSTED");
        metrics.increment("workload.attestation.failure", {
          node_id: nodeId,
          code: localResult.code,
        });
        audit({
          event: "workload_attestation_local_posture",
          status: "error",
          code: localResult.code,
          details: {
            nodeId,
            reason: localResult.message,
            failure: localResult.details,
          },
        });
        return localResult;
      }

      setLocalTrust(localResult.ok, localResult.ok ? "" : localResult.code || "WORKLOAD_ATTESTATION_NOT_TRUSTED");
      lastVerifiedAt = Date.now();
      metrics.increment("workload.attestation.success", {
        node_id: nodeId,
      });
      audit({
        event: "workload_attestation_initialized",
        status: "ok",
        details: {
          nodeId,
          referenceHash,
        },
      });

      return makeResult(
        "WORKLOAD_ATTESTATION_VERIFIED",
        "Attestation runtime initialized",
        {
          nodeId,
          referenceHash,
        },
        true,
      );
    } catch (error) {
      initialized = false;
      const code =
        error && typeof error === "object" && "code" in error && typeof (error as { code?: unknown }).code === "string"
          ? String((error as { code?: unknown }).code)
          : "WORKLOAD_ATTESTATION_NOT_TRUSTED";
      const details =
        error && typeof error === "object" && "details" in error && isPlainObject((error as { details?: unknown }).details)
          ? ((error as { details?: unknown }).details as Record<string, unknown>)
          : {};
      setLocalTrust(false, code);
      metrics.increment("workload.attestation.failure", {
        node_id: nodeId,
        code,
      });
      audit({
        event: "workload_attestation_initialized",
        status: production ? "error" : "warning",
        code,
        details: {
          nodeId,
          ...details,
        },
      });
      return makeResult(code, error instanceof Error ? error.message : "Attestation initialization failed", details);
    }
  }

  function syncLocalAttestationPosture(localMetadataInput?: Record<string, unknown>): WorkloadAttestationVerificationResult {
    if (!initialized) {
      const start = initializeInternal();
      if (!start.ok && production) {
        return start;
      }
    }

    const localMetadata = localMetadataInput || (options.localMetadataProvider ? options.localMetadataProvider() : {});
    const result = evaluateLocalMetadata(localMetadata);
    if (!result.ok) {
      if (production) {
        setLocalTrust(false, result.code || "WORKLOAD_ATTESTATION_NOT_TRUSTED");
      }
      metrics.increment("workload.attestation.failure", {
        node_id: nodeId,
        code: result.code,
      });
      audit({
        event: "workload_attestation_local_posture",
        status: production ? "error" : "warning",
        code: result.code,
        details: {
          nodeId,
          reason: result.message,
          failure: result.details,
        },
      });
      return result;
    }

    setLocalTrust(true);
    lastVerifiedAt = Date.now();
    metrics.increment("workload.attestation.success", {
      node_id: nodeId,
    });
    audit({
      event: "workload_attestation_local_posture",
      status: "ok",
      code: result.code,
      details: {
        nodeId,
        snapshotHash: result.details.snapshotHash,
      },
    });
    return result;
  }

  function generateAttestationEvidenceInternal(
    challenge: WorkloadAttestationChallenge = {},
    context: { localMetadata?: Record<string, unknown>; runtimeMeasurements?: Record<string, unknown> } = {},
  ): {
    ok: boolean;
    code: string;
    message: string;
    evidence?: WorkloadAttestationEvidence;
    details: Record<string, unknown>;
  } {
    const posture = syncLocalAttestationPosture(context.localMetadata);
    if (!posture.ok && production) {
      return {
        ok: false,
        code: posture.code || "WORKLOAD_ATTESTATION_NOT_TRUSTED",
        message: posture.message,
        details: posture.details,
      };
    }

    if (!keyPair || !reference) {
      const initResult = initializeInternal();
      if (!initResult.ok && production) {
        return {
          ok: false,
          code: initResult.code || "WORKLOAD_ATTESTATION_NOT_TRUSTED",
          message: initResult.message,
          details: initResult.details,
        };
      }
    }

    if (!keyPair || !reference) {
      return {
        ok: false,
        code: "WORKLOAD_ATTESTATION_NOT_TRUSTED",
        message: "Attestation runtime is not initialized",
        details: {
          nodeId,
        },
      };
    }

    const localMetadata = normalizeLocalMetadata(context.localMetadata || (options.localMetadataProvider ? options.localMetadataProvider() : {}));
    const nowMs = Date.now();
    pruneReplayCache(nowMs);
    const ttlMs = parsePositiveInt(reference.evidenceTtlMs, DEFAULT_EVIDENCE_TTL_MS);
    const nonce = normalizeString(challenge.nonce) || makeNonce();
    const timestampMs = Number.isFinite(Number(challenge.timestampMs)) ? Number(challenge.timestampMs) : nowMs;
    const expiresAtMs = timestampMs + ttlMs;
    const runtimeMeasurements = isPlainObject(context.runtimeMeasurements)
      ? (canonicalize(context.runtimeMeasurements) as Record<string, unknown>)
      : {};
    const publicKey = toPublicKeyBase64(keyPair.publicKey);

    const unsignedPayload = {
      nodeId,
      workloadManifestHash: localMetadata.workloadManifestHash,
      executionPolicyHash: localMetadata.executionPolicyHash,
      secretManifestHash: localMetadata.secretManifestHash,
      runtimeMeasurements,
      snapshotHash: buildSnapshotHash(localMetadata),
      timestampMs,
      expiresAtMs,
      nonce,
      publicKey,
    };

    const evidenceHash = sha256HexObject(unsignedPayload);
    const signature = crypto.sign(null, Buffer.from(evidenceHash, "utf8"), keyPair.privateKey).toString("base64");
    const evidence: WorkloadAttestationEvidence = {
      ...unsignedPayload,
      evidenceHash,
      signature,
      algorithm: "ed25519",
    };

    lastEvidenceHash = evidenceHash;
    lastVerifiedAt = nowMs;

    audit({
      event: "workload_attestation_evidence_generated",
      status: "ok",
      details: {
        nodeId,
        evidenceHash,
        nonceHash: sha256Hex(nonce),
      },
    });

    return {
      ok: true,
      code: "WORKLOAD_ATTESTATION_VERIFIED",
      message: "Attestation evidence generated",
      evidence,
      details: {
        nodeId,
        evidenceHash,
      },
    };
  }

  function verifyPeerAttestationEvidenceInternal(
    peerIdInput: string,
    evidence: unknown,
    challenge: WorkloadAttestationChallenge = {},
  ): WorkloadAttestationVerificationResult {
    if (!initialized) {
      const initResult = initializeInternal();
      if (!initResult.ok && production) {
        return initResult;
      }
    }

    if (!reference) {
      return makeResult("WORKLOAD_ATTESTATION_NOT_TRUSTED", "Attestation reference is not available", {
        nodeId,
      });
    }

    const peerId = normalizeString(peerIdInput) || "unknown-peer";
    const verification = verifyAttestationEvidence(evidence, reference, {
      challenge,
      nowMs: Date.now(),
      replayCache,
      maxFutureSkewMs: DEFAULT_MAX_FUTURE_SKEW_MS,
    });

    const previous = peerTrustMap.get(peerId);
    const stickyUntrusted = Boolean(previous && previous.stickyUntrusted);

    if (!verification.ok || stickyUntrusted) {
      const failureReason = stickyUntrusted ? "WORKLOAD_ATTESTATION_PEER_STICKY_UNTRUSTED" : verification.code;
      const details = verification.details || {};
      const evidenceHash = normalizeHash((details as Record<string, unknown>).evidenceHash);
      peerTrustMap.set(peerId, {
        trusted: false,
        failureReason,
        evidenceHash,
        verifiedAt: Date.now(),
        stickyUntrusted: true,
      });

      if (failureReason === "WORKLOAD_ATTESTATION_REPLAY_DETECTED") {
        metrics.increment("workload.attestation.replay_detected", {
          node_id: nodeId,
          peer_id: peerId,
        });
      }
      metrics.increment("workload.attestation.peer_untrusted", {
        node_id: nodeId,
        peer_id: peerId,
        reason: failureReason,
      });
      metrics.increment("workload.attestation.failure", {
        node_id: nodeId,
        peer_id: peerId,
        code: failureReason,
      });
      audit({
        event: "workload_attestation_peer_verify",
        status: "error",
        code: failureReason,
        details: {
          nodeId,
          peerId,
          evidenceHash,
          reason: failureReason,
        },
      });

      return makeResult(
        "WORKLOAD_ATTESTATION_NOT_TRUSTED",
        "Peer attestation is not trusted",
        {
          peerId,
          reason: failureReason,
          evidenceHash,
        },
      );
    }

    const evidenceHash = normalizeHash((verification.details as Record<string, unknown>).evidenceHash);
    peerTrustMap.set(peerId, {
      trusted: true,
      failureReason: "",
      evidenceHash,
      verifiedAt: Date.now(),
      stickyUntrusted: false,
    });

    metrics.increment("workload.attestation.success", {
      node_id: nodeId,
      peer_id: peerId,
    });
    audit({
      event: "workload_attestation_peer_verify",
      status: "ok",
      code: verification.code,
      details: {
        nodeId,
        peerId,
        evidenceHash,
      },
    });

    return verification;
  }

  function evaluatePeerAttestationPostureInternal(peers: Array<Record<string, unknown>> = []) {
    const nowMs = Date.now();
    const criticalMismatches: Array<Record<string, unknown>> = [];
    const warnings: Array<Record<string, unknown>> = [];

    if (!initialized) {
      return {
        ok: !production,
        status: production ? ("mismatch" as const) : ("not_evaluated" as const),
        criticalMismatches: production
          ? [
              {
                classification: "LOCAL_ATTESTATION_NOT_INITIALIZED",
                nodeId,
              },
            ]
          : [],
        warnings,
        timestamp: nowMs,
      };
    }

    const healthyPeers = Array.isArray(peers)
      ? peers.filter((peer) => normalizeString(peer && peer.status).toUpperCase() === "UP")
      : [];

    for (const peer of healthyPeers) {
      const peerId = normalizeString(peer.peerId) || "unknown-peer";
      const sticky = peer.attestationStickyUntrusted === true;
      const trustedFlag = peer.attestationTrusted === true;
      const failureReason = normalizeString(peer.attestationFailureReason || peer.attestation_failure_reason);

      if (sticky || !trustedFlag) {
        const mismatch = {
          classification: "PEER_ATTESTATION_UNTRUSTED",
          peerId,
          reason: failureReason || (sticky ? "WORKLOAD_ATTESTATION_PEER_STICKY_UNTRUSTED" : "WORKLOAD_ATTESTATION_NOT_TRUSTED"),
        };
        if (production) {
          criticalMismatches.push(mismatch);
        } else {
          warnings.push(mismatch);
        }
      }
    }

    return {
      ok: criticalMismatches.length === 0,
      status: criticalMismatches.length > 0 ? ("mismatch" as const) : ("aligned" as const),
      criticalMismatches,
      warnings,
      timestamp: nowMs,
    };
  }

  function getAttestationStateInternal(): WorkloadAttestationState {
    const peerSnapshot: WorkloadAttestationState["peerTrustMap"] = {};
    for (const [peerId, entry] of peerTrustMap.entries()) {
      peerSnapshot[peerId] = {
        trusted: entry.trusted,
        failureReason: entry.failureReason,
        evidenceHash: entry.evidenceHash,
        verifiedAt: entry.verifiedAt,
        stickyUntrusted: entry.stickyUntrusted,
      };
    }

    return {
      nodeId,
      trusted,
      blockedReason,
      referenceHash,
      lastEvidenceHash,
      lastVerifiedAt,
      peerTrustMap: peerSnapshot,
    };
  }

  return {
    initializeAttestation: initializeInternal,
    syncLocalAttestationPosture,
    generateAttestationEvidence: generateAttestationEvidenceInternal,
    verifyAttestationEvidence: (evidence, trustedReference = reference || undefined, verifyContext = {}) => {
      if (!trustedReference) {
        return makeResult("WORKLOAD_ATTESTATION_NOT_TRUSTED", "Trusted attestation reference is not available", {
          nodeId,
        });
      }
      return verifyAttestationEvidence(evidence, trustedReference, verifyContext);
    },
    verifyPeerAttestationEvidence: verifyPeerAttestationEvidenceInternal,
    evaluatePeerAttestationPosture: evaluatePeerAttestationPostureInternal,
    getAttestationState: getAttestationStateInternal,
  };
}

export function generateAttestationEvidence(
  runtime: WorkloadAttestationRuntime,
  challenge: WorkloadAttestationChallenge = {},
  context: { localMetadata?: Record<string, unknown>; runtimeMeasurements?: Record<string, unknown> } = {},
): {
  ok: boolean;
  code: string;
  message: string;
  evidence?: WorkloadAttestationEvidence;
  details: Record<string, unknown>;
} {
  if (!runtime || typeof runtime.generateAttestationEvidence !== "function") {
    return {
      ok: false,
      code: "WORKLOAD_ATTESTATION_NOT_TRUSTED",
      message: "Attestation runtime is unavailable",
      details: {},
    };
  }
  return runtime.generateAttestationEvidence(challenge, context);
}

export function getAttestationState(runtime: WorkloadAttestationRuntime): WorkloadAttestationState {
  if (!runtime || typeof runtime.getAttestationState !== "function") {
    return {
      nodeId: "node-unknown",
      trusted: false,
      blockedReason: "WORKLOAD_ATTESTATION_NOT_TRUSTED",
      referenceHash: "",
      lastEvidenceHash: "",
      lastVerifiedAt: 0,
      peerTrustMap: {},
    };
  }
  return runtime.getAttestationState();
}
