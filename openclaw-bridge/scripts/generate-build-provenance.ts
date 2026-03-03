import { execSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { computeAttestationReferenceHash } from "../src/security/workload-attestation";
import { computeWorkloadManifestHash } from "../src/security/workload-manifest";
import {
  WorkloadProvenanceDocument,
  computeBuildEnvironmentFingerprint,
  computeDetachedProvenancePayloadBytes,
  getCanonicalBuildProvenance,
  resolveDefaultBuildProvenanceHashPath,
  resolveDefaultBuildProvenancePath,
  resolveDefaultBuildProvenancePublicKeyPath,
  resolveDefaultDependencyLockPath,
} from "../src/security/workload-provenance";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { computePolicyHash } = require("../policy/execution-policy-manifest.js");
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { computeSecretManifestHash } = require("../security/secret-manifest.js");

interface CliOptions {
  outputPath: string;
  hashPath: string;
  publicKeyPath: string;
  privateKeyPath: string;
  repository: string;
  gitCommitSha: string;
  buildTimestamp: string;
  imageDigests: Record<string, string>;
}

function normalizeString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function parseImageDigestMap(value: string): Record<string, string> {
  const map: Record<string, string> = {};
  const normalized = normalizeString(value);
  if (!normalized) {
    return map;
  }

  for (const rawEntry of normalized.split(",")) {
    const entry = rawEntry.trim();
    if (!entry) {
      continue;
    }
    const separator = entry.indexOf("=");
    if (separator <= 0 || separator >= entry.length - 1) {
      continue;
    }
    const key = entry.slice(0, separator).trim().toLowerCase();
    const digest = entry.slice(separator + 1).trim().toLowerCase();
    if (!key || !digest) {
      continue;
    }
    map[key] = digest;
  }

  return map;
}

function parseArgs(argv: string[]): CliOptions {
  const args = argv.slice(2);
  const defaults = {
    outputPath: resolveDefaultBuildProvenancePath(),
    hashPath: resolveDefaultBuildProvenanceHashPath(),
    publicKeyPath: resolveDefaultBuildProvenancePublicKeyPath(),
    privateKeyPath: normalizeString(process.env.WORKLOAD_PROVENANCE_PRIVATE_KEY_PATH),
    repository: normalizeString(process.env.GIT_REPOSITORY || process.env.REPOSITORY_URL),
    gitCommitSha: normalizeString(process.env.GIT_COMMIT_SHA),
    buildTimestamp: new Date().toISOString(),
    imageDigests: {
      "phase24.test.tool": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "supervisor.read_file": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    },
  };

  const envImageDigests = parseImageDigestMap(normalizeString(process.env.WORKLOAD_PROVENANCE_IMAGE_DIGESTS));
  defaults.imageDigests = {
    ...defaults.imageDigests,
    ...envImageDigests,
  };

  for (let index = 0; index < args.length; index += 1) {
    const token = args[index];
    if (token === "--output" && args[index + 1]) {
      defaults.outputPath = path.resolve(args[index + 1]);
      index += 1;
      continue;
    }
    if (token === "--hash-output" && args[index + 1]) {
      defaults.hashPath = path.resolve(args[index + 1]);
      index += 1;
      continue;
    }
    if (token === "--public-key-output" && args[index + 1]) {
      defaults.publicKeyPath = path.resolve(args[index + 1]);
      index += 1;
      continue;
    }
    if (token === "--private-key" && args[index + 1]) {
      defaults.privateKeyPath = path.resolve(args[index + 1]);
      index += 1;
      continue;
    }
    if (token === "--repository" && args[index + 1]) {
      defaults.repository = args[index + 1];
      index += 1;
      continue;
    }
    if (token === "--commit" && args[index + 1]) {
      defaults.gitCommitSha = args[index + 1];
      index += 1;
      continue;
    }
    if (token === "--build-timestamp" && args[index + 1]) {
      defaults.buildTimestamp = args[index + 1];
      index += 1;
      continue;
    }
    if (token === "--image-digest" && args[index + 1]) {
      const parsed = parseImageDigestMap(args[index + 1]);
      defaults.imageDigests = {
        ...defaults.imageDigests,
        ...parsed,
      };
      index += 1;
      continue;
    }
  }

  return defaults;
}

function resolveRepository(): string {
  try {
    const remote = execSync("git config --get remote.origin.url", {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    if (remote) {
      return remote;
    }
  } catch {}

  return "unknown-repository";
}

function resolveGitCommitSha(): string {
  try {
    const sha = execSync("git rev-parse HEAD", {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    if (sha) {
      return sha;
    }
  } catch {}

  return "0000000000000000000000000000000000000000";
}

function sha256File(targetPath: string): string {
  return crypto.createHash("sha256").update(fs.readFileSync(targetPath)).digest("hex");
}

function loadJson(targetPath: string): unknown {
  return JSON.parse(fs.readFileSync(targetPath, "utf8"));
}

function loadPrivateKeyPem(privateKeyPath: string): { privateKeyPem: string; publicKeyPem: string } {
  const normalizedPath = normalizeString(privateKeyPath);
  if (normalizedPath && fs.existsSync(normalizedPath)) {
    const privateKeyPem = fs.readFileSync(path.resolve(normalizedPath), "utf8");
    const privateKey = crypto.createPrivateKey(privateKeyPem);
    const publicKeyPem = crypto
      .createPublicKey(privateKey)
      .export({ type: "spki", format: "pem" })
      .toString("utf8");
    return {
      privateKeyPem,
      publicKeyPem,
    };
  }

  const generated = crypto.generateKeyPairSync("ed25519");
  return {
    privateKeyPem: generated.privateKey.export({ type: "pkcs8", format: "pem" }).toString("utf8"),
    publicKeyPem: generated.publicKey.export({ type: "spki", format: "pem" }).toString("utf8"),
  };
}

function buildUnsignedProvenance(base: {
  gitCommitSha: string;
  repository: string;
  buildTimestamp: string;
  workloadManifestHash: string;
  executionPolicyHash: string;
  secretManifestHash: string;
  attestationReferenceHash: string;
  dependencyLockHash: string;
  containerImageDigests: Record<string, string>;
}): Omit<WorkloadProvenanceDocument, "provenanceSignature" | "provenanceHash"> {
  return {
    provenanceVersion: 1,
    gitCommitSha: normalizeString(base.gitCommitSha).toLowerCase(),
    repository: normalizeString(base.repository),
    buildTimestamp: new Date(base.buildTimestamp).toISOString(),
    workloadManifestHash: normalizeString(base.workloadManifestHash).toLowerCase(),
    executionPolicyHash: normalizeString(base.executionPolicyHash).toLowerCase(),
    secretManifestHash: normalizeString(base.secretManifestHash).toLowerCase(),
    attestationReferenceHash: normalizeString(base.attestationReferenceHash).toLowerCase(),
    containerImageDigests: Object.keys(base.containerImageDigests)
      .sort((left, right) => left.localeCompare(right))
      .reduce<Record<string, string>>((acc, key) => {
        acc[key.toLowerCase()] = normalizeString(base.containerImageDigests[key]).toLowerCase();
        return acc;
      }, {}),
    dependencyLockHash: normalizeString(base.dependencyLockHash).toLowerCase(),
    nodeVersion: process.version,
    buildEnvironmentFingerprint: computeBuildEnvironmentFingerprint({
      nodeVersion: process.version,
      platform: process.platform,
      arch: process.arch,
      ci: process.env.CI || "",
    }),
    signatureAlgorithm: "ed25519",
  };
}

function main(): void {
  const options = parseArgs(process.argv);

  const repoRoot = path.resolve(__dirname, "..");
  const workloadManifestPath = path.resolve(repoRoot, "security", "workload-manifest.json");
  const policyManifestPath = path.resolve(repoRoot, "policy", "execution-policy.json");
  const secretManifestPath = path.resolve(repoRoot, "security", "secret-manifest.json");
  const attestationReferencePath = path.resolve(repoRoot, "security", "workload-attestation-reference.json");
  const lockPath = resolveDefaultDependencyLockPath();

  const workloadManifestHash = computeWorkloadManifestHash(loadJson(workloadManifestPath));
  const executionPolicyHash = computePolicyHash(loadJson(policyManifestPath));
  const secretManifestHash = computeSecretManifestHash(loadJson(secretManifestPath));
  const attestationReferenceHash = computeAttestationReferenceHash(loadJson(attestationReferencePath));
  const dependencyLockHash = sha256File(lockPath);

  const repository = options.repository || resolveRepository();
  const gitCommitSha = options.gitCommitSha || resolveGitCommitSha();
  const timestamp = options.buildTimestamp || new Date().toISOString();

  const unsigned = buildUnsignedProvenance({
    gitCommitSha,
    repository,
    buildTimestamp: timestamp,
    workloadManifestHash,
    executionPolicyHash,
    secretManifestHash,
    attestationReferenceHash,
    dependencyLockHash,
    containerImageDigests: options.imageDigests,
  });

  const { privateKeyPem, publicKeyPem } = loadPrivateKeyPem(options.privateKeyPath);
  const payloadBytes = computeDetachedProvenancePayloadBytes(
    getCanonicalBuildProvenance({
      ...unsigned,
      provenanceSignature: "placeholder",
      provenanceHash: "0".repeat(64),
    }) as WorkloadProvenanceDocument,
  );

  const provenanceHash = crypto.createHash("sha256").update(payloadBytes).digest("hex");
  const signature = crypto.sign(null, payloadBytes, crypto.createPrivateKey(privateKeyPem)).toString("base64");

  const signed = getCanonicalBuildProvenance({
    ...unsigned,
    provenanceSignature: signature,
    provenanceHash,
  });

  fs.mkdirSync(path.dirname(options.outputPath), { recursive: true });
  fs.mkdirSync(path.dirname(options.hashPath), { recursive: true });
  fs.mkdirSync(path.dirname(options.publicKeyPath), { recursive: true });

  fs.writeFileSync(options.outputPath, `${JSON.stringify(signed, null, 2)}\n`, "utf8");
  fs.writeFileSync(options.hashPath, `${provenanceHash}\n`, "utf8");
  fs.writeFileSync(options.publicKeyPath, publicKeyPem, "utf8");

  process.stdout.write(
    `${JSON.stringify(
      {
        ok: true,
        outputPath: options.outputPath,
        hashPath: options.hashPath,
        publicKeyPath: options.publicKeyPath,
        provenanceHash,
        gitCommitSha: signed.gitCommitSha,
      },
      null,
      2,
    )}\n`,
  );
}

main();
