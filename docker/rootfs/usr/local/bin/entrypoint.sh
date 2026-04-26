#!/usr/bin/env bash
set -e

APP_NAME="casspeed"
APP_BIN="/usr/local/bin/${APP_NAME}"

export TZ="${TZ:-America/New_York}"
export CONFIG_DIR="/config"
export DATA_DIR="/data"
export LOG_DIR="/data/logs"
export DATABASE_DIR="/data/db"
export BACKUP_DIR="/data/backup"

log() {
    echo "[entrypoint] $(date '+%Y-%m-% %H:%M:%S') $*"
}

log "Container starting..."
log "MODE: ${MODE:-production}"
log "DEBUG: ${DEBUG:-false}"
log "TZ: $TZ"
log "ADDRESS: ${ADDRESS:-[::]}"
log "PORT: ${PORT:-80}"

mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$DATABASE_DIR" "$LOG_DIR" "$BACKUP_DIR"

log "Starting ${APP_NAME}..."

# Build args
ARGS=(
    --address "${ADDRESS:-0.0.0.0}"
    --port "${PORT:-80}"
    --config "$CONFIG_DIR"
    --data "$DATA_DIR"
    --log "$LOG_DIR"
    --mode "${MODE:-production}"
)

# Add debug if true
if [[ "${DEBUG,,}" =~ ^(1|y|yes|true|on)$ ]]; then
    ARGS+=(--debug true)
fi

exec "$APP_BIN" "${ARGS[@]}"
