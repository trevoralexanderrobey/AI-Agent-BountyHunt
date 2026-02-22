/**
 * Safety gates — replicates the mutation guards from the existing HTTP bridge.
 * Each gated operation checks its env-var gate before proceeding.
 */

export function isMutationGuardEnabled(): boolean {
  const value = (process.env.BOUNTY_HUNTER_ALLOW_MUTATIONS || "").trim().toLowerCase();
  return value === "1" || value === "true" || value === "yes";
}

export function isH1MutationGuardEnabled(): boolean {
  const value = (process.env.H1_ALLOW_MUTATIONS || "").trim().toLowerCase();
  return value === "1" || value === "true" || value === "yes";
}

export function isBurpActiveScanEnabled(): boolean {
  const value = (process.env.BURP_ALLOW_ACTIVE_SCAN || "").trim().toLowerCase();
  return value === "1" || value === "true" || value === "yes";
}

export function isBurpRawDataEnabled(): boolean {
  const value = (process.env.BURP_ALLOW_RAW_DATA || "").trim().toLowerCase();
  return value === "1" || value === "true" || value === "yes";
}

export function assertGate(gateName: string, enabled: boolean): void {
  if (!enabled) {
    throw new Error(
      `Safety gate blocked: ${gateName} is disabled. ` +
        `Set the corresponding env var to "true" to enable.`
    );
  }
}
