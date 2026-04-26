#!/bin/bash
# Docker-based testing for casspeed
set -e

echo "=== Docker-based Testing ==="
echo ""

# Build in Docker
echo "Building in Docker..."
docker run --rm \
  -v "$(pwd)":/src \
  -w /src \
  -e CGO_ENABLED=0 \
  golang:alpine \
  go build -o /tmp/casspeed ./src

echo "✓ Build successful"

# Run tests in Docker
echo ""
echo "Running tests in Docker..."
docker run --rm \
  -v "$(pwd)":/src \
  -w /src \
  -e CGO_ENABLED=0 \
  golang:alpine \
  go test ./...

echo "✓ Tests passed"
