import fs from "node:fs/promises";
import path from "node:path";
import { SUPERVISOR_TOOL_REGISTRY } from "../src/supervisor/registry";

function stableStringify(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

async function main(): Promise<void> {
  const root = path.resolve(__dirname, "..");
  const jsonPath = path.join(root, "supervisor", "supervisor-registry.json");
  const expected = `${stableStringify(SUPERVISOR_TOOL_REGISTRY)}\n`;
  const actual = await fs.readFile(jsonPath, "utf8");

  if (actual !== expected) {
    // eslint-disable-next-line no-console
    console.error("Supervisor registry JSON is out of sync with src/supervisor/registry.ts");
    process.exit(1);
  }

  // eslint-disable-next-line no-console
  console.log("Supervisor registry JSON is in sync.");
}

main().catch((error) => {
  // eslint-disable-next-line no-console
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
