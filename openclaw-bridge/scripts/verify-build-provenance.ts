import path from "node:path";

import {
  loadBuildProvenanceFromDisk,
  verifyBuildProvenance,
} from "../src/security/workload-provenance";

interface CliOptions {
  provenancePath?: string;
  hashPath?: string;
  publicKeyPath?: string;
  expectedHash?: string;
  dependencyLockPath?: string;
  production: boolean;
}

function normalizeString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function parseArgs(argv: string[]): CliOptions {
  const args = argv.slice(2);
  const parsed: CliOptions = {
    production: false,
  };

  for (let index = 0; index < args.length; index += 1) {
    const token = args[index];
    if (token === "--provenance" && args[index + 1]) {
      parsed.provenancePath = path.resolve(args[index + 1]);
      index += 1;
      continue;
    }
    if (token === "--hash" && args[index + 1]) {
      parsed.hashPath = path.resolve(args[index + 1]);
      index += 1;
      continue;
    }
    if (token === "--public-key" && args[index + 1]) {
      parsed.publicKeyPath = path.resolve(args[index + 1]);
      index += 1;
      continue;
    }
    if (token === "--expected-hash" && args[index + 1]) {
      parsed.expectedHash = normalizeString(args[index + 1]).toLowerCase();
      index += 1;
      continue;
    }
    if (token === "--lockfile" && args[index + 1]) {
      parsed.dependencyLockPath = path.resolve(args[index + 1]);
      index += 1;
      continue;
    }
    if (token === "--production") {
      parsed.production = true;
      continue;
    }
  }

  return parsed;
}

function main(): void {
  const args = parseArgs(process.argv);
  const verification = verifyBuildProvenance({
    production: args.production,
    provenancePath: args.provenancePath,
    provenanceHashPath: args.hashPath,
    publicKeyPath: args.publicKeyPath,
    expectedProvenanceHash: args.expectedHash,
    dependencyLockPath: args.dependencyLockPath,
    allowProductionPathOverride: false,
    productionContainerMode: false,
  });

  if (!verification.ok) {
    process.stdout.write(`${JSON.stringify(verification, null, 2)}\n`);
    process.exit(1);
  }

  const loaded = loadBuildProvenanceFromDisk({
    production: args.production,
    provenancePath: args.provenancePath,
    provenanceHashPath: args.hashPath,
    publicKeyPath: args.publicKeyPath,
    expectedProvenanceHash: args.expectedHash,
    dependencyLockPath: args.dependencyLockPath,
    allowProductionPathOverride: false,
    productionContainerMode: false,
  });

  const payload = {
    ok: true,
    provenancePath: loaded.provenancePath,
    hashPath: loaded.hashPath,
    publicKeyPath: loaded.publicKeyPath,
    dependencyLockPath: loaded.dependencyLockPath,
    provenanceHash: loaded.canonicalPayloadHash,
    gitCommitSha: loaded.provenance.gitCommitSha,
    signatureAlgorithm: loaded.provenance.signatureAlgorithm,
    containerDigests: loaded.provenance.containerImageDigests,
  };

  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
}

main();
