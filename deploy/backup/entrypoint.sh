#!/usr/bin/env bash
# Runs backup.sh once a day at BACKUP_HOUR_UTC.
# With arguments, runs that command instead (e.g. `restore.sh ...` for a restore drill).
set -euo pipefail

# One-off commands run as the container's user (root by default), so a restore drill can read an
# identity file that is only readable by its owner.
if [ "$#" -gt 0 ]; then exec "$@"; fi

# Starts as root only to fix ownership of the bind-mounted backup directory (Docker creates it
# root-owned on first run), then drops to the unprivileged user for the backup loop.
if [ "$(id -u)" = 0 ]; then
  mkdir -p /backups
  chown backup:backup /backups
  exec su-exec backup "$0"
fi

if [ -z "${AGE_RECIPIENT:-}" ]; then
  echo "BACKUP_AGE_RECIPIENT is not set: NO BACKUPS WILL BE MADE. See docs/backup-and-recovery.md." >&2
fi
if ! touch /backups/.write-test 2>/dev/null; then
  echo "/backups is not writable by uid $(id -u): NO BACKUPS WILL BE MADE." >&2
else
  rm -f /backups/.write-test
fi

while true; do
  now=$(date -u +%s)
  next=$(date -u -d "today ${BACKUP_HOUR_UTC}:00" +%s)
  [ "$next" -le "$now" ] && next=$(date -u -d "tomorrow ${BACKUP_HOUR_UTC}:00" +%s)
  sleep $(( next - now ))
  /usr/local/bin/backup.sh || echo "backup failed at $(date -u)" >&2
done
