import path from "node:path";

import {
  loadOffensiveManifestFromDisk,
  verifyOffensiveManifest,
} from "../src/security/offensive-workload-manifest";

interface CliOptions {
  manifestPath?: string;
  hashPath?: string;
  signaturePath?: string;
  publicKeyPath?: string;
  expectedHash?: string;
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
    if (token === "--manifest" && args[index + 1]) {
      parsed.manifestPath = path.resolve(args[index + 1]);
      index += 1;
      continue;
    }
    if (token === "--hash" && args[index + 1]) {
      parsed.hashPath = path.resolve(args[index + 1]);
      index += 1;
      continue;
    }
    if (token === "--signature" && args[index + 1]) {
      parsed.signaturePath = path.resolve(args[index + 1]);
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
    if (token === "--production") {
      parsed.production = true;
      continue;
    }
  }

  return parsed;
}

function main(): void {
  const args = parseArgs(process.argv);
  const verification = verifyOffensiveManifest({
    production: args.production,
    manifestPath: args.manifestPath,
    hashPath: args.hashPath,
    signaturePath: args.signaturePath,
    publicKeyPath: args.publicKeyPath,
    expectedManifestHash: args.expectedHash,
    allowProductionPathOverride: false,
    productionContainerMode: false,
  });

  if (!verification.ok) {
    process.stdout.write(`${JSON.stringify(verification, null, 2)}\n`);
    process.exit(1);
  }

  const loaded = loadOffensiveManifestFromDisk({
    production: args.production,
    manifestPath: args.manifestPath,
    hashPath: args.hashPath,
    signaturePath: args.signaturePath,
    publicKeyPath: args.publicKeyPath,
    expectedManifestHash: args.expectedHash,
    allowProductionPathOverride: false,
    productionContainerMode: false,
  });

  process.stdout.write(
    `${JSON.stringify(
      {
        ok: true,
        manifestPath: loaded.manifestPath,
        hashPath: loaded.hashPath,
        signaturePath: loaded.signaturePath,
        publicKeyPath: loaded.publicKeyPath,
        manifestHash: loaded.canonicalPayloadHash,
        tools: loaded.manifest.tools.map((tool) => tool.toolName),
      },
      null,
      2,
    )}\n`,
  );
}

main();
