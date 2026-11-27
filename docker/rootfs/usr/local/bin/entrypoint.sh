#!/usr/bin/env bash
set -eo pipefail

APP_NAME="casspeed"
APP_BIN="/usr/local/bin/${APP_NAME}"

export TZ="${TZ:-America/New_York}"
export CONFIG_DIR="${CONFIG_DIR:-/config/${APP_NAME}}"
export DATA_DIR="${DATA_DIR:-/data/${APP_NAME}}"

ARGS=(--address "${LISTEN:-[::]}" --port "${PORT:-80}")
DEBUG_VALUE="${DEBUG:-false}"
case "${DEBUG_VALUE,,}" in
    true|yes|1|on|enable) ARGS+=(--debug) ;;
esac

exec "$APP_BIN" "${ARGS[@]}" "$@"
