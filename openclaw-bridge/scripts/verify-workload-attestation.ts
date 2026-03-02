import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  computeAttestationReferenceHash,
  initializeAttestation,
  loadAttestationReferenceFromDisk,
  resolveDefaultAttestationReferencePath,
  verifyAttestationEvidence,
} from "../src/security/workload-attestation";

interface VerificationResult {
  ok: boolean;
  errors: string[];
  warnings: string[];
  referencePath: string;
  referenceHash: string;
  deterministic: boolean;
  signatureVerified: boolean;
  evidenceSchemaValid: boolean;
  ttlEnforced: boolean;
  noDynamicOverride: boolean;
}

function normalizeString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function parseArgs(argv: string[]): { referencePath?: string; expectedHash?: string } {
  const args = argv.slice(2);
  const parsed: { referencePath?: string; expectedHash?: string } = {};

  for (let i = 0; i < args.length; i += 1) {
    const token = args[i];
    if (token === "--reference" && args[i + 1]) {
      parsed.referencePath = args[i + 1];
      i += 1;
      continue;
    }
    if (token === "--expected-hash" && args[i + 1]) {
      parsed.expectedHash = args[i + 1];
      i += 1;
      continue;
    }
  }

  return parsed;
}

function hasRequiredEvidenceFields(value: unknown): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const evidence = value as Record<string, unknown>;
  const required = [
    "nodeId",
    "workloadManifestHash",
    "executionPolicyHash",
    "secretManifestHash",
    "runtimeMeasurements",
    "snapshotHash",
    "timestampMs",
    "expiresAtMs",
    "nonce",
    "publicKey",
    "evidenceHash",
    "signature",
    "algorithm",
  ];
  return required.every((key) => Object.prototype.hasOwnProperty.call(evidence, key));
}

function runVerification(args: { referencePath?: string; expectedHash?: string }): VerificationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  const referencePath = path.resolve(args.referencePath || resolveDefaultAttestationReferencePath());
  let loaded;
  try {
    loaded = loadAttestationReferenceFromDisk({
      referencePath,
      expectedHash: normalizeString(args.expectedHash),
      production: false,
      allowProductionPathOverride: true,
    });
  } catch (error) {
    return {
      ok: false,
      errors: [error instanceof Error ? error.message : String(error)],
      warnings,
      referencePath,
      referenceHash: "",
      deterministic: false,
      signatureVerified: false,
      evidenceSchemaValid: false,
      ttlEnforced: false,
      noDynamicOverride: false,
    };
  }

  const hashA = computeAttestationReferenceHash(loaded.reference);
  const hashB = computeAttestationReferenceHash(JSON.parse(JSON.stringify(loaded.reference)));
  const deterministic = hashA === hashB;
  if (!deterministic) {
    errors.push("attestation reference hash is non-deterministic");
  }

  let noDynamicOverride = false;
  try {
    const tmpFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "attestation-ref-override-")), "ref.json");
    fs.copyFileSync(referencePath, tmpFile);
    loadAttestationReferenceFromDisk({
      production: true,
      referencePath: tmpFile,
      allowProductionPathOverride: false,
    });
    errors.push("production attestation reference path override was not rejected");
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error ? String((error as { code?: unknown }).code || "") : "";
    noDynamicOverride = code === "WORKLOAD_ATTESTATION_REFERENCE_PATH_OVERRIDE_FORBIDDEN";
    if (!noDynamicOverride) {
      errors.push("production attestation reference override check failed unexpectedly");
    }
  }

  const localMetadata = {
    executionPolicyHash: loaded.reference.executionPolicyHash,
    secretManifestHash: loaded.reference.secretManifestHash,
    workloadManifestHash: loaded.reference.workloadManifestHash,
  };

  const runtime = initializeAttestation({
    production: false,
    referencePath,
    expectedReferenceHash: loaded.referenceHash,
    localMetadataProvider: () => localMetadata,
  });
  const initialized = runtime.initializeAttestation();
  if (!initialized.ok) {
    errors.push(`attestation runtime failed to initialize: ${initialized.code}`);
  }

  const challenge = { nonce: "verify-phase25-nonce", timestampMs: Date.now() };
  const generated = runtime.generateAttestationEvidence(challenge, {
    localMetadata,
    runtimeMeasurements: {
      source: "verify-workload-attestation",
    },
  });

  const evidenceSchemaValid = hasRequiredEvidenceFields(generated.evidence);
  if (!evidenceSchemaValid) {
    errors.push("generated attestation evidence schema is invalid");
  }

  const verification = verifyAttestationEvidence(generated.evidence, loaded.reference, {
    challenge,
    replayCache: new Map<string, number>(),
  });
  const signatureVerified = verification.ok;
  if (!signatureVerified) {
    errors.push(`attestation signature verification failed: ${verification.code}`);
  }

  let ttlEnforced = false;
  if (generated.evidence) {
    const expiredCheck = verifyAttestationEvidence(generated.evidence, loaded.reference, {
      challenge,
      nowMs: generated.evidence.expiresAtMs + 1,
      replayCache: new Map<string, number>(),
    });
    ttlEnforced = loaded.reference.evidenceTtlMs === 120000 && expiredCheck.ok === false && expiredCheck.code === "WORKLOAD_ATTESTATION_STALE";
  }
  if (!ttlEnforced) {
    errors.push("attestation TTL enforcement validation failed");
  }

  return {
    ok: errors.length === 0,
    errors,
    warnings,
    referencePath,
    referenceHash: loaded.referenceHash,
    deterministic,
    signatureVerified,
    evidenceSchemaValid,
    ttlEnforced,
    noDynamicOverride,
  };
}

function main(): void {
  const args = parseArgs(process.argv);
  const result = runVerification(args);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  process.exit(result.ok ? 0 : 1);
}

main();
