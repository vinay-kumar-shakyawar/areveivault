#!/usr/bin/env bash
# Encrypted backup: Postgres (custom format) + attachments, each encrypted to an
# offline age recipient. Vault contents are already client-side encrypted; this
# additionally protects OPAQUE records, server secrets and metadata.
set -euo pipefail
: "${AGE_RECIPIENT:?AGE_RECIPIENT is required}"
ts=$(date -u +%Y%m%dT%H%M%SZ)
day=/backups/daily; month=/backups/monthly
mkdir -p "$day" "$month"

pg_dump --format=custom --no-owner | age -r "$AGE_RECIPIENT" > "$day/db-$ts.dump.age"
tar -C /data -cf - attachments | age -r "$AGE_RECIPIENT" > "$day/attachments-$ts.tar.age"
sha256sum "$day"/*-"$ts".* > "$day/SHA256SUMS-$ts"

# First backup of each month is also kept as a monthly.
if [ "$(date -u +%d)" = "01" ]; then cp "$day"/*-"$ts".* "$month"/; fi

ls -1t "$day"/db-*.age 2>/dev/null | tail -n +"$((RETAIN_DAILY + 1))" | while read -r f; do
  base=${f##*/db-}; stamp=${base%%.dump.age}; rm -f "$day"/*-"$stamp".*
done
ls -1t "$month"/db-*.age 2>/dev/null | tail -n +"$((RETAIN_MONTHLY + 1))" | while read -r f; do
  base=${f##*/db-}; stamp=${base%%.dump.age}; rm -f "$month"/*-"$stamp".*
done

if [ -n "${RCLONE_REMOTE:-}" ]; then rclone copy /backups "$RCLONE_REMOTE" --immutable; fi
echo "backup ok $ts"
