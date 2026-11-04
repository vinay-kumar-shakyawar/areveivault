#!/usr/bin/env bash
# Runs backup.sh once a day at BACKUP_HOUR_UTC.
set -euo pipefail
while true; do
  now=$(date -u +%s)
  next=$(date -u -d "today ${BACKUP_HOUR_UTC}:00" +%s)
  [ "$next" -le "$now" ] && next=$(date -u -d "tomorrow ${BACKUP_HOUR_UTC}:00" +%s)
  sleep $(( next - now ))
  /usr/local/bin/backup.sh || echo "backup failed at $(date -u)" >&2
done
