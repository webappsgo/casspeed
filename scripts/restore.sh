#!/bin/bash
# Restore script for casspeed
set -e

if [ -z "$1" ]; then
  echo "Usage: $0 <backup_file>"
  echo "Available backups:"
  ls -lh /data/backups/casspeed_backup_*.tar.gz 2>/dev/null || echo "  No backups found"
  exit 1
fi

BACKUP_FILE="$1"

if [ ! -f "$BACKUP_FILE" ]; then
  echo "✗ Backup file not found: $BACKUP_FILE"
  exit 1
fi

echo "Restoring from: $BACKUP_FILE"
tar -xzf "$BACKUP_FILE" -C /

echo "✓ Restore complete"
echo "⚠️  Restart casspeed to apply changes"
