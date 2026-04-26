#!/bin/bash
# Backup script for casspeed
set -e

BACKUP_DIR="${BACKUP_DIR:-/data/backups}"
DB_PATH="${DB_PATH:-/data/db/speedtest.db}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/casspeed_backup_$TIMESTAMP.tar.gz"

echo "Creating backup..."
mkdir -p "$BACKUP_DIR"

# Backup database and config
tar -czf "$BACKUP_FILE" \
  -C / \
  "$(dirname "$DB_PATH")" \
  etc/casspeed 2>/dev/null || true

echo "✓ Backup created: $BACKUP_FILE"

# Keep only last 4 backups
ls -t "$BACKUP_DIR"/casspeed_backup_*.tar.gz | tail -n +5 | xargs rm -f 2>/dev/null || true
echo "✓ Old backups cleaned"
