#!/usr/bin/env bash
set -eo pipefail

PROJECT_NAME="$(basename "$PWD")"
PROJECT_ORG="$(sed -n 's/^project_org:[[:space:]]*//p' IDEA.md | head -n1 | tr -d '[:space:]')"
INTERNAL_NAME="$(sed -n 's/^internal_name:[[:space:]]*//p' IDEA.md | head -n1 | tr -d '[:space:]')"
TEST_RUN_ID="$(od -An -N4 -tx1 /dev/urandom | tr -d '[:space:]')"
BIN_DIR="${BINDIR:-binaries/integration-$TEST_RUN_ID}"
RELEASE_DIR="${RELDIR:-releases/integration-$TEST_RUN_ID}"
CLEAN_BIN_DIR=0
CLEAN_RELEASE_DIR=0
[ -n "${BINDIR:-}" ] || CLEAN_BIN_DIR=1
[ -n "${RELDIR:-}" ] || CLEAN_RELEASE_DIR=1
TEST_NAME="${PROJECT_NAME}-$(od -An -N4 -tx1 /dev/urandom | tr -d '[:space:]')"

cleanup() {
    docker rm -f "$TEST_NAME" >/dev/null 2>&1 || true
    if [ "$CLEAN_BIN_DIR" -eq 1 ]; then rm -rf -- "$BIN_DIR"; fi
    if [ "$CLEAN_RELEASE_DIR" -eq 1 ]; then rm -rf -- "$RELEASE_DIR"; fi
}
trap cleanup EXIT INT TERM

if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker not found: binary tests require Docker" >&2
    exit 69
fi

echo "Building server and CLI binaries..."
make local BINDIR="$BIN_DIR" RELDIR="$RELEASE_DIR"

if [ ! -x "$BIN_DIR/casspeed" ] || [ ! -x "$BIN_DIR/casspeed-cli" ]; then
    echo "ERROR: expected server and CLI binaries in $BIN_DIR" >&2
    exit 1
fi

echo "Running binary validation in Alpine..."
docker run --rm --name "$TEST_NAME" -e PROJECT_ORG="$PROJECT_ORG" -e INTERNAL_NAME="$INTERNAL_NAME" -v "$PWD/$BIN_DIR:/app:ro" alpine:latest sh -ec "$(cat <<'CONTAINER_SCRIPT'
apk add --no-cache curl bash file jq tor i2pd tzdata ca-certificates >/dev/null
mkdir -p "${TMPDIR:-/tmp}/$PROJECT_ORG"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/$PROJECT_ORG/$INTERNAL_NAME-XXXXXX")"
chmod 700 "$TEST_ROOT"
cleanup_test_root() { rm -rf -- "$TEST_ROOT"; }
trap cleanup_test_root EXIT INT TERM
FAILURES=0
fail() { echo "FAILED: $*" >&2; FAILURES=$((FAILURES + 1)); }
check_output() {
  label="$1"
  shift
  if "$@"; then echo "PASS: $label"; else fail "$label"; fi
}

echo "Checking binary metadata and command help..."
check_output "server version" /app/casspeed --version
check_output "server help" /app/casspeed --help
check_output "CLI version" /app/casspeed-cli --version
check_output "CLI help" /app/casspeed-cli --help
if cp /app/casspeed "$TEST_ROOT/casspeed-renamed" && chmod +x "$TEST_ROOT/casspeed-renamed"; then
  "$TEST_ROOT/casspeed-renamed" --help > "$TEST_ROOT/renamed-help.txt" 2>&1
  if grep "casspeed-renamed" "$TEST_ROOT/renamed-help.txt" >/dev/null; then echo "PASS: renamed binary help"; else fail "renamed binary help"; fi
else fail "copy renamed server binary"; fi
if file /app/casspeed > "$TEST_ROOT/server-file.txt"; then echo "PASS: server binary file information"; else fail "server binary file information"; fi

cleanup_server() {
  if [ -n "${SERVER_PID:-}" ]; then kill "$SERVER_PID" >/dev/null 2>&1 || true; wait "$SERVER_PID" 2>/dev/null || true; fi
  rm -rf -- "$TEST_ROOT"
}
trap cleanup_server EXIT INT TERM

echo "Starting server with isolated runtime directories..."
/app/casspeed --address 127.0.0.1 --port 64580 --config "$TEST_ROOT/config" --data "$TEST_ROOT/data" --log "$TEST_ROOT/log" --mode development >"$TEST_ROOT/server.log" 2>&1 &
SERVER_PID=$!
READY=0
for attempt in $(seq 1 40); do
  if curl -q -fsS http://127.0.0.1:64580/api/v1/server/healthz >/dev/null 2>&1; then READY=1; break; fi
  sleep 0.25
done
if [ "$READY" -ne 1 ]; then cat "$TEST_ROOT/server.log" >&2; fail "server startup"; fi

request_ok() {
  label="$1"
  shift
  if curl -q -fsS "$@" >/dev/null; then echo "PASS: $label"; else fail "$label"; fi
}

echo "Checking API representations and public pages..."
request_ok "health API JSON" http://127.0.0.1:64580/api/v1/server/healthz
request_ok "health API text suffix" http://127.0.0.1:64580/api/v1/server/healthz.txt
request_ok "health API text Accept" -H "Accept: text/plain" http://127.0.0.1:64580/api/v1/server/healthz
request_ok "health API JSON Accept" -H "Accept: application/json" http://127.0.0.1:64580/api/v1/server/healthz
request_ok "health alias" http://127.0.0.1:64580/api/healthz
request_ok "OpenAPI document" http://127.0.0.1:64580/api/v1/server/swagger
for page in about privacy contact help help/mcp terms dpo security security/policy security/thanks docs/graphql docs/swagger; do
  request_ok "public page /server/$page" "http://127.0.0.1:64580/server/$page"
done
for asset in vendor/graphiql/graphiql.min.js vendor/graphiql/graphiql.min.css vendor/graphiql/react.production.min.js vendor/graphiql/react-dom.production.min.js js/docs-graphql.js; do
  request_ok "local GraphiQL asset $asset" "http://127.0.0.1:64580/static/$asset"
done

GRAPHQL_RESPONSE="$(curl -q -fsS 'http://127.0.0.1:64580/api/v1/server/graphql?query=%7Bhealth%7Bstatus%7D%7D')" || fail "GraphQL health query"
if printf "%s" "$GRAPHQL_RESPONSE" | jq -e '.data.health.status == "healthy"' >/dev/null; then echo "PASS: GraphQL health query"; else fail "GraphQL health query response"; fi

MCP_STATUS="$(curl -q -sS -o "$TEST_ROOT/mcp-response.json" -w "%{http_code}" -X POST http://127.0.0.1:64580/mcp -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')" || fail "MCP unauthenticated request"
if [ "$MCP_STATUS" = "401" ] && jq -e '.ok == false and .error == "unauthorized"' "$TEST_ROOT/mcp-response.json" >/dev/null; then echo "PASS: MCP requires bearer token"; else fail "MCP bearer authentication"; fi

HOME_PAGE="$(curl -q -fsS -H "Accept: text/html" http://127.0.0.1:64580/)" || fail "home page"
if printf "%s" "$HOME_PAGE" | grep "/server/administration" >/dev/null; then fail "public home page hides admin path"; else echo "PASS: public home page hides admin path"; fi

if [ "$FAILURES" -gt 0 ]; then
  echo "ERROR: $FAILURES binary checks failed" >&2
  exit 1
fi
echo "All binary checks passed"
CONTAINER_SCRIPT
)" || exit $?
