#!/usr/bin/env bash
# Restore drill. Usage: restore.sh <db-*.dump.age> <attachments-*.tar.age> <age-identity-file>
# Restores into the database named by PGDATABASE (use a scratch DB for drills!).
set -euo pipefail
db=$1; att=$2; id=$3
age -d -i "$id" "$db" | pg_restore --clean --if-exists --no-owner -d "$PGDATABASE"
mkdir -p /restore && age -d -i "$id" "$att" | tar -C /restore -xf -
echo "restored DB into $PGDATABASE and attachments into /restore/attachments"
