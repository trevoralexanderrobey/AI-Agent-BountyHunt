#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo " Configuring Runner Environment"
echo "=========================================================="

# Find the .env file in the actions-runner directory relative to the project root
ENV_FILE=""

if [ -f ".env" ] && grep -q "ACTIONS_RUNNER_HOOK_JOB_STARTED" ".env" 2>/dev/null; then
    ENV_FILE=".env"
elif [ -f "actions-runner/.env" ]; then
    ENV_FILE="actions-runner/.env"
else
    echo "Creating .env file in actions-runner directory..."
    mkdir -p actions-runner
    ENV_FILE="actions-runner/.env"
    touch "$ENV_FILE"
fi

DOCKER_HOST_STR="DOCKER_HOST=unix://$HOME/.colima/default/docker.sock"

if ! grep -q "^DOCKER_HOST=" "$ENV_FILE" 2>/dev/null; then
    echo "$DOCKER_HOST_STR" >> "$ENV_FILE"
    echo "✅ Successfully added DOCKER_HOST to $ENV_FILE"
else
    # Replace existing DOCKER_HOST if it exists but is different, though simple approach is just reporting it's there
    echo "✅ DOCKER_HOST is already present in $ENV_FILE"
fi
