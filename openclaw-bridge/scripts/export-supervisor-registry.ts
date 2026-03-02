import fs from "node:fs/promises";
import path from "node:path";
import { SUPERVISOR_TOOL_REGISTRY } from "../src/supervisor/registry";

async function main(): Promise<void> {
  const root = path.resolve(__dirname, "..");
  const targetPath = path.join(root, "supervisor", "supervisor-registry.json");
  await fs.mkdir(path.dirname(targetPath), { recursive: true });
  await fs.writeFile(targetPath, `${JSON.stringify(SUPERVISOR_TOOL_REGISTRY, null, 2)}\n`, "utf8");
  // eslint-disable-next-line no-console
  console.log(`Wrote supervisor registry: ${targetPath}`);
}

main().catch((error) => {
  // eslint-disable-next-line no-console
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
