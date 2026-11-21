#!/usr/bin/env bash
# Restore drill. Usage: restore.sh <db-*.dump.age> <attachments-*.tar.age> <age-identity-file>
# Restores into the database named by PGDATABASE (use a scratch DB for drills!).
# Attachments are unpacked into RESTORE_DIR (default /tmp/restore); mount a volume there to keep them.
set -euo pipefail
db=$1; att=$2; id=$3
out=${RESTORE_DIR:-/tmp/restore}
age -d -i "$id" "$db" | pg_restore --clean --if-exists --no-owner -d "$PGDATABASE"
mkdir -p "$out" && age -d -i "$id" "$att" | tar -C "$out" -xf -
echo "restored DB into $PGDATABASE and attachments into $out/attachments"
