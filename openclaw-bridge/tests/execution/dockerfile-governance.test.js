const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const CONTAINER_SLUGS = ["nmap", "curl", "nslookup", "whois", "hashcat", "sqlmap", "nikto", "aircrack", "msfvenom", "ffuf"];

function readDockerfile(slug) {
  const dockerfilePath = path.resolve(__dirname, "../../containers", slug, "Dockerfile");
  const content = fs.readFileSync(dockerfilePath, "utf8");
  return { dockerfilePath, content };
}

test("tool Dockerfiles are digest-pinned and hardened", () => {
  for (const slug of CONTAINER_SLUGS) {
    const { dockerfilePath, content } = readDockerfile(slug);

    assert.match(content, /^FROM\s+\S+@sha256:[a-f0-9]{64}$/m, `FROM must be digest-pinned in ${dockerfilePath}`);
    assert.equal(/:latest\b/i.test(content), false, `:latest is not allowed in ${dockerfilePath}`);
    assert.match(content, /^USER\s+\S+/m, `USER must be set in ${dockerfilePath}`);
    assert.equal(/^USER\s+root\s*$/im.test(content), false, `USER root is not allowed in ${dockerfilePath}`);
    assert.match(content, /^ENTRYPOINT\s+\[/m, `ENTRYPOINT must be defined in ${dockerfilePath}`);
    assert.equal(/ENTRYPOINT\s+\[\s*"sh"/i.test(content), false, `shell wrapper entrypoint is not allowed in ${dockerfilePath}`);
  }
});
