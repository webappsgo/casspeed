#!/usr/bin/env bash
# tests/run_tests.sh - Auto-detect and run tests in containers
# Auto-detects Incus (preferred) or Docker
# Per PART 13: NEVER run binaries on host - ALWAYS use containers

set -e

PROJECT_NAME="casspeed"
BINARY_NAME="casspeed"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "========================================="
echo " Casspeed Test Runner"
echo "========================================="
echo

# Check if Incus is available (preferred)
if command -v incus &> /dev/null; then
    echo -e "${GREEN}✓ Incus detected (PREFERRED - full OS with systemd)${NC}"
    exec "$(dirname "$0")/incus.sh"
elif command -v docker &> /dev/null; then
    echo -e "${YELLOW}✓ Docker detected (fallback - quick tests)${NC}"
    exec "$(dirname "$0")/docker.sh"
else
    echo -e "${RED}✗ Neither Incus nor Docker found${NC}"
    echo
    echo "Please install one of:"
    echo "  - Incus (preferred): https://linuxcontainers.org/incus/"
    echo "  - Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

