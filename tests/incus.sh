#!/bin/bash
# Incus-based testing for casspeed (full systemd environment)
set -e

echo "=== Incus-based Testing (Full OS + systemd) ==="
echo ""

# Check if Incus is available
if ! command -v incus &> /dev/null; then
  echo "✗ Incus not found, falling back to Docker"
  exec ./tests/docker.sh
fi

echo "Creating Incus container..."
incus launch images:debian/12 casspeed-test || true

echo "Waiting for container to start..."
sleep 3

echo "Copying source code..."
incus file push -r . casspeed-test/root/casspeed/

echo "Installing dependencies..."
incus exec casspeed-test -- bash -c "apt-get update && apt-get install -y golang-go"

echo "Building..."
incus exec casspeed-test -- bash -c "cd /root/casspeed && go build -o casspeed ./src"

echo "Running tests..."
incus exec casspeed-test -- bash -c "cd /root/casspeed && go test ./..."

echo "Cleaning up..."
incus delete casspeed-test --force

echo "✓ Tests passed"
