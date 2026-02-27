const BUILTIN_TOOL_IMAGES = Object.freeze({
  curl: "ghcr.io/openclaw-bridge/curl@sha256:1111111111111111111111111111111111111111111111111111111111111111",
  nslookup: "ghcr.io/openclaw-bridge/nslookup@sha256:2222222222222222222222222222222222222222222222222222222222222222",
  whois: "ghcr.io/openclaw-bridge/whois@sha256:3333333333333333333333333333333333333333333333333333333333333333",
  hashcat: "ghcr.io/openclaw-bridge/hashcat@sha256:4444444444444444444444444444444444444444444444444444444444444444",
  sqlmap: "ghcr.io/openclaw-bridge/sqlmap@sha256:5555555555555555555555555555555555555555555555555555555555555555",
  nikto: "ghcr.io/openclaw-bridge/nikto@sha256:6666666666666666666666666666666666666666666666666666666666666666",
  aircrack: "ghcr.io/openclaw-bridge/aircrack@sha256:7777777777777777777777777777777777777777777777777777777777777777",
  msfvenom: "ghcr.io/openclaw-bridge/msfvenom@sha256:8888888888888888888888888888888888888888888888888888888888888888",
  ffuf: "ghcr.io/openclaw-bridge/ffuf@sha256:9999999999999999999999999999999999999999999999999999999999999999",
  nmap: "ghcr.io/openclaw-bridge/nmap@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
});

function normalizeSlug(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function isPlainObject(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function resolveToolImageReference(toolSlug, options = {}) {
  const slug = normalizeSlug(toolSlug);
  if (!slug) {
    return "";
  }

  const images = isPlainObject(options.images) ? options.images : {};
  const override = typeof images[slug] === "string" ? images[slug].trim() : "";
  if (override) {
    return override;
  }

  const fallback = typeof BUILTIN_TOOL_IMAGES[slug] === "string" ? BUILTIN_TOOL_IMAGES[slug].trim() : "";
  return fallback;
}

module.exports = {
  BUILTIN_TOOL_IMAGES,
  resolveToolImageReference,
};
