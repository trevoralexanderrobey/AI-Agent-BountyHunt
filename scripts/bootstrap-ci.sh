#!/usr/bin/env bash
set -euo pipefail

echo "== CI Bootstrap Start =="

export DOCKER_HOST=unix://$HOME/.colima/default/docker.sock

# Ensure Colima running
if ! colima status >/dev/null 2>&1; then
  echo "Starting Colima..."
  colima start
fi

# Verify Docker
docker info >/dev/null

# Install required tooling deterministically
if ! command -v trivy >/dev/null 2>&1; then
  echo "Installing Trivy via Homebrew..."
  brew install aquasecurity/trivy/trivy
fi

if ! command -v cosign >/dev/null 2>&1; then
  echo "Installing Cosign via Homebrew..."
  brew install sigstore/tap/cosign
fi

# Ensure buildx builder exists
docker buildx inspect >/dev/null 2>&1 || docker buildx create --use

echo "== CI Bootstrap Complete =="
