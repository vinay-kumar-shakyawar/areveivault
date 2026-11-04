# Backup and disaster recovery

For the person who operates the Arevei Vault server.

## What's in a backup, and why it's still encrypted

| Data | Already client-side encrypted? | Why the backup is encrypted anyway |
|---|---|---|
| Items, vault names, client names, keysets, attachments | Yes (zero-knowledge) | Defense in depth |
| OPAQUE records, account TOTP seeds (server-encrypted), server key material | No, these are server secrets | **A stolen backup must not help anyone impersonate the server or bypass 2FA** |
| Emails, IPs in the audit log, the access graph | No | Personal data under privacy law |

Backups are produced by the `backup` service in `deploy/docker-compose.yml`. Each night it runs `pg_dump` (custom format) and tars the attachment volume. Each artifact is encrypted to an **age public key**, and a `SHA256SUMS` file is written alongside. The age **private key must not live on the server.**

## One-time setup

1. On an offline machine (or a hardware-backed machine an owner controls):
   ```bash
   age-keygen -o arevei-backup-identity.txt
   ```
   It prints the public key (`age1...`). Put that value in `BACKUP_AGE_RECIPIENT` in `deploy/.env`.
2. Store `arevei-backup-identity.txt` in **two** separate offline locations, for example a printed copy in the office safe and an encrypted USB drive held by a second owner. Losing it makes every backup unrecoverable.
3. Optional off-host copies: configure an `rclone` remote (S3 with Object Lock, Backblaze B2, etc.) and set `BACKUP_RCLONE_REMOTE`. Files are uploaded with `--immutable`, so a compromised server can't overwrite history.
4. **Also back up `SERVER_SECRET_KEY`** from `deploy/.env` to the same offline locations. Without it, a restored database can't decrypt OPAQUE server keys or account TOTP seeds, and every user would have to re-enroll.

## Schedule and retention

- Daily at `BACKUP_HOUR_UTC` (default 02:00 UTC).
- Keeps `BACKUP_RETAIN_DAILY` dailies (30) and `BACKUP_RETAIN_MONTHLY` monthlies (12, taken on the 1st).
- Manual run: `docker compose -f deploy/docker-compose.yml exec backup backup.sh`

## Quarterly restore drill (required)

Run this against a **scratch** database, never production:

```bash
# 1. Bring up a throwaway Postgres
docker run -d --name restore-drill -e POSTGRES_PASSWORD=drill -e POSTGRES_USER=arevei -e POSTGRES_DB=drill postgres:16.4-bookworm

# 2. Verify checksums of the chosen backup set
cd backups/daily && sha256sum -c SHA256SUMS-<timestamp>

# 3. Restore (identity file brought from offline storage, then removed)
docker run --rm --network container:restore-drill -v "$PWD:/b" -v /path/to/identity:/id:ro \
  -e PGHOST=localhost -e PGUSER=arevei -e PGPASSWORD=drill -e PGDATABASE=drill \
  arevei-vault-backup restore.sh /b/db-<ts>.dump.age /b/attachments-<ts>.tar.age /id/arevei-backup-identity.txt

# 4. Sanity checks
docker exec restore-drill psql -U arevei -d drill -c "select count(*) from items;"
```

Then point a staging API at the scratch database (same `SERVER_SECRET_KEY`). A test user should be able to sign in and see their items. Record the drill date and result in the admin log.

## Disaster scenarios

| Scenario | Recovery |
|---|---|
| Server disk lost | Provision a new host, restore `deploy/.env` (including `SERVER_SECRET_KEY`) from offline storage, `docker compose up -d`, restore the latest backup as in the drill (into the real `arevei` DB). Users sign in normally, and their clients detect no change because vault data is identical. |
| Database corruption | Stop `api`, restore the latest good backup, start `api`. Writes made after that backup are lost from the server, but **clients that synced after the backup still hold newer ciphertext in their local caches**. Clients will show "server returned an older version" rollback warnings, which is expected here. Ask users to re-save any affected items. |
| `SERVER_SECRET_KEY` lost, DB intact | Vault data is unaffected (the server never held vault keys). OPAQUE server setup and account TOTP seeds can't be decrypted, so generate a new key, then force every user through credential re-registration and TOTP re-enrollment. *This needs an admin tool that isn't built yet. Treat the key as irreplaceable.* |
| Suspected server compromise | Rotate `SERVER_SECRET_KEY`, rotate DB and Redis passwords, revoke all sessions (`DELETE FROM sessions`), rebuild images from a verified git tag, and compare served bundle hashes against the signed release (§12.3). Tell users to unlock through the extension until build verification passes. Review the audit log, and compare hourly checkpoints against those held on Owner devices. Users' vault contents stay protected by the master password and Secret Key, but **any credentials a malicious server-delivered web bundle could have captured** should be considered exposed for users who unlocked in the plain web app during the compromise window. |
| Owner loses the master password | Personal Vault: unrecoverable by design. Shared projects: another admin re-grants access after the owner creates a new account (architecture §9). |
| All owners and admins lose access | **Unrecoverable for shared projects.** Keep at least two owners at all times. |
