#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo " Self-Hosted GitHub Runner Setup (macOS + Colima)"
echo "=========================================================="
echo ""
echo "Before proceeding, please generate a runner registration token:"
echo "1. Go to Repository -> Settings -> Actions -> Runners"
echo "2. Click 'New self-hosted runner'"
echo "3. Select 'macOS' and your architecture."
echo "4. Copy the token provided in the configuration step."
echo ""
read -p "Enter your registration token: " RUNNER_TOKEN

if [ -z "$RUNNER_TOKEN" ]; then
  echo "Error: Token cannot be empty."
  exit 1
fi

# Define the runner version
RUNNER_VERSION="2.322.0"

# Create action runner directory
mkdir -p actions-runner
cd actions-runner || exit 1

# Check system architecture
ARCH=$(uname -m)
if [ "$ARCH" = "arm64" ]; then
    echo "Detected Apple Silicon (arm64)..."
    RUNNER_URL="https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-osx-arm64-${RUNNER_VERSION}.tar.gz"
else
    echo "Detected Intel (x64)..."
    RUNNER_URL="https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-osx-x64-${RUNNER_VERSION}.tar.gz"
fi

if [ ! -f "config.sh" ]; then
    echo "Downloading GitHub Actions Runner v${RUNNER_VERSION}..."
    curl -o actions-runner.tar.gz -L "$RUNNER_URL"
    echo "Extracting runner..."
    tar xzf ./actions-runner.tar.gz
    rm ./actions-runner.tar.gz
else
    echo "Runner already downloaded."
fi

echo "Configuring runner..."
# Attempt to infer repo URL
REPO_URL=$(git config --get remote.origin.url | sed -e 's/\.git$//' -e 's/^git@github\.com:/https:\/\/github.com\//' || true)

if [[ -z "$REPO_URL" || ! "$REPO_URL" == http* ]]; then
    read -p "Enter repository URL (e.g., https://github.com/trevoralexanderrobey/AI-Agent-BountyHunt): " REPO_URL
fi

./config.sh --url "$REPO_URL" \
            --token "$RUNNER_TOKEN" \
            --name "antigravity-local-runner" \
            --labels "self-hosted,antigravity,colima,linux-build" \
            --unattended \
            --replace

echo "Configuring runner environment for Colima..."
cd ..
./scripts/configure-runner-env.sh

cd actions-runner || exit 1
echo "Installing and starting runner service..."
./svc.sh install || echo "Service may already be installed."
./svc.sh start

echo "=========================================================="
echo " ✅ Runner successfully configured and started!"
echo " It will now run automatically as a background service."
echo " GitHub minutes billing has been eliminated for this repo."
echo "=========================================================="
