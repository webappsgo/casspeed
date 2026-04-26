#!/bin/bash
# Health check script for casspeed
set -e

HEALTH_URL="${HEALTH_URL:-http://localhost:64580/healthz}"

response=$(curl -s -o /dev/null -w "%{http_code}" "$HEALTH_URL" 2>/dev/null || echo "000")

if [ "$response" = "200" ]; then
  echo "✓ casspeed is healthy"
  exit 0
else
  echo "✗ casspeed is unhealthy (HTTP $response)"
  exit 1
fi
