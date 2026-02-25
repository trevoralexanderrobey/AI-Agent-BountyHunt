const fs = require("node:fs");
const crypto = require("node:crypto");

function parseBoolean(value, fallback = false) {
  if (typeof value === "boolean") {
    return value;
  }
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (normalized === "true" || normalized === "1" || normalized === "yes") {
      return true;
    }
    if (normalized === "false" || normalized === "0" || normalized === "no") {
      return false;
    }
  }
  return fallback;
}

function readPemFile(pathValue, label) {
  if (!pathValue || typeof pathValue !== "string") {
    throw new Error(`${label} path is required`);
  }
  return fs.readFileSync(pathValue, "utf8");
}

function splitCertificateChain(pem) {
  const certs = [];
  const pattern = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  let match = pattern.exec(pem);
  while (match) {
    certs.push(match[0]);
    match = pattern.exec(pem);
  }
  return certs;
}

function validateCertificateChain(certPem) {
  const certs = splitCertificateChain(certPem);
  if (certs.length === 0) {
    throw new Error("TLS certificate chain is empty or invalid");
  }

  const now = Date.now();
  const parsed = certs.map((pem) => new crypto.X509Certificate(pem));
  for (const cert of parsed) {
    const notAfter = Date.parse(cert.validTo);
    if (!Number.isFinite(notAfter)) {
      throw new Error("Unable to parse certificate expiry");
    }
    if (notAfter <= now) {
      throw new Error("TLS certificate has expired");
    }
  }

  const leaf = parsed[0];
  const leafNotAfter = Date.parse(leaf.validTo);
  const daysRemaining = Math.max(0, Math.floor((leafNotAfter - now) / (24 * 60 * 60 * 1000)));

  return {
    subject: leaf.subject,
    issuer: leaf.issuer,
    validFrom: leaf.validFrom,
    validTo: leaf.validTo,
    daysRemaining,
    chainLength: parsed.length,
  };
}

function createTLSConfig(options = {}) {
  const enabled = parseBoolean(options.enabled, parseBoolean(process.env.TLS_ENABLED, false));
  const certPath = options.certPath || process.env.TLS_CERT_PATH || "";
  const keyPath = options.keyPath || process.env.TLS_KEY_PATH || "";
  const mtlsEnabled = parseBoolean(options.mtlsEnabled, parseBoolean(process.env.MTLS_ENABLED, false));
  const caPath = options.caPath || process.env.MTLS_CA_PATH || "";

  if (!enabled) {
    return {
      enabled: false,
      mtlsEnabled: false,
      certPath: "",
      keyPath: "",
      caPath: "",
      certificateInfo: null,
      serverOptions: null,
      validateCertificateChain,
    };
  }

  const cert = readPemFile(certPath, "TLS_CERT_PATH");
  const key = readPemFile(keyPath, "TLS_KEY_PATH");
  const certificateInfo = validateCertificateChain(cert);
  const serverOptions = {
    cert,
    key,
    minVersion: "TLSv1.2",
  };

  if (mtlsEnabled) {
    const ca = readPemFile(caPath, "MTLS_CA_PATH");
    serverOptions.ca = ca;
    serverOptions.requestCert = true;
    serverOptions.rejectUnauthorized = true;
  }

  return {
    enabled: true,
    mtlsEnabled,
    certPath,
    keyPath,
    caPath: mtlsEnabled ? caPath : "",
    certificateInfo,
    serverOptions,
    validateCertificateChain,
  };
}

module.exports = {
  createTLSConfig,
  validateCertificateChain,
};
