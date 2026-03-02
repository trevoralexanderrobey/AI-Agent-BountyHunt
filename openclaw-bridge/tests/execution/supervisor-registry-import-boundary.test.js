const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "../..");
const ALLOWED_IMPORTERS = new Set([
  path.join(ROOT, "src/core/execution-router.ts"),
  path.join(ROOT, "src/core/execution-router.js"),
]);

const SKIP_DIRS = new Set(["node_modules", ".git", "dist"]);
const CODE_EXTENSIONS = new Set([".js", ".ts", ".mjs", ".cjs"]);
const IMPORT_PATTERN = /(from\s+["'][^"']*supervisor-registry\.json["'])|(require\(\s*["'][^"']*supervisor-registry\.json["']\s*\))/;

async function collectCodeFiles(dir, out = []) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const entryPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) {
        continue;
      }
      await collectCodeFiles(entryPath, out);
      continue;
    }
    if (CODE_EXTENSIONS.has(path.extname(entry.name))) {
      out.push(entryPath);
    }
  }
  return out;
}

test("execution router is the only runtime importer of supervisor registry JSON", async () => {
  const files = await collectCodeFiles(ROOT);
  const violations = [];
  for (const filePath of files) {
    const source = await fs.readFile(filePath, "utf8");
    if (!IMPORT_PATTERN.test(source)) {
      continue;
    }
    if (!ALLOWED_IMPORTERS.has(filePath)) {
      violations.push(filePath);
    }
  }

  assert.deepEqual(
    violations,
    [],
    `Only execution router may import supervisor registry runtime JSON. Violations:\n${violations.join("\n")}`,
  );
});
