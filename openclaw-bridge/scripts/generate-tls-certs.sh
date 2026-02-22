#!/usr/bin/env bash
# Generate self-signed TLS certificates for the OpenClaw bridge.
# Certs are stored in ~/.openclaw/tls/ with restrictive permissions.
# Safe to run multiple times — skips generation if certs already exist.
set -euo pipefail

TLS_DIR="${HOME}/.openclaw/tls"
CERT_FILE="${TLS_DIR}/bridge-cert.pem"
KEY_FILE="${TLS_DIR}/bridge-key.pem"

if [[ -f "${CERT_FILE}" && -f "${KEY_FILE}" ]]; then
  echo "✅ TLS certs already exist at ${TLS_DIR}"
  echo "   cert: ${CERT_FILE}"
  echo "   key:  ${KEY_FILE}"
  exit 0
fi

if ! command -v openssl &>/dev/null; then
  echo "❌ openssl is required but not found in PATH."
  echo "   Install via: brew install openssl"
  exit 1
fi

mkdir -p "${TLS_DIR}"
chmod 700 "${TLS_DIR}"

echo "Generating self-signed TLS certificate (ECDSA P-256, 10-year validity)..."

openssl req -x509 -newkey ec \
  -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout "${KEY_FILE}" \
  -out "${CERT_FILE}" \
  -days 3650 \
  -nodes \
  -subj "/CN=localhost/O=OpenClaw Local" \
  -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
  2>/dev/null

chmod 600 "${KEY_FILE}" "${CERT_FILE}"

echo "✅ TLS certs generated:"
echo "   cert: ${CERT_FILE}"
echo "   key:  ${KEY_FILE}"
echo ""
echo "Fingerprint:"
openssl x509 -in "${CERT_FILE}" -noout -fingerprint -sha256 2>/dev/null || true
