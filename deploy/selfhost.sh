#!/usr/bin/env bash
# One-command self-hosting setup for a Linux server.
#
#   ./deploy/selfhost.sh vault.yourco.com you@yourco.com
#
# Generates every secret, creates the backup encryption key, writes deploy/.env and starts the
# Docker Compose stack (Caddy + API + Postgres + Redis + nightly encrypted backups).
# Safe to re-run: an existing deploy/.env is kept, so this is also the upgrade command.
# Full guide: docs/setup-guide.md
set -euo pipefail

cd "$(dirname "$0")/.."
ENV_FILE=deploy/.env
KEY_FILE=deploy/backup-identity.txt
COMPOSE=(docker compose -f deploy/docker-compose.yml --env-file "$ENV_FILE")

say() { printf '\n==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null || die "Docker is not installed. Install it with: curl -fsSL https://get.docker.com | sh"
docker compose version >/dev/null 2>&1 || die "The Docker Compose plugin is missing (need 'docker compose', v2)."
docker info >/dev/null 2>&1 || die "Cannot talk to Docker. Run this script with sudo, or add your user to the 'docker' group."
command -v openssl >/dev/null || die "openssl is required to generate secrets."

if [ ! -f "$ENV_FILE" ]; then
  DOMAIN=${1:-}
  EMAIL=${2:-}
  [ -n "$DOMAIN" ] && [ -n "$EMAIL" ] || die "usage: ./deploy/selfhost.sh <domain> <email-for-tls-certificates>"
  case "$DOMAIN" in
    *://* | */* | *" "*) die "pass the bare domain, e.g. vault.yourco.com (no https://, no path)" ;;
  esac

  say "Building the backup image (it carries the 'age' encryption tool)"
  docker build -q -t arevei-vault-backup deploy/backup >/dev/null

  say "Generating the backup encryption key"
  umask 077
  docker run --rm --entrypoint age-keygen arevei-vault-backup > "$KEY_FILE" 2>/dev/null
  AGE_RECIPIENT=$(sed -n 's/^# public key: //p' "$KEY_FILE")
  [ -n "$AGE_RECIPIENT" ] || die "could not generate the backup key"

  say "Writing $ENV_FILE with freshly generated secrets"
  cat > "$ENV_FILE" <<ENV
VAULT_DOMAIN=${DOMAIN}
ACME_EMAIL=${EMAIL}
SERVER_SECRET_KEY=$(openssl rand -base64 32)
POSTGRES_PASSWORD=$(openssl rand -hex 24)
REDIS_PASSWORD=$(openssl rand -hex 24)
BACKUP_AGE_RECIPIENT=${AGE_RECIPIENT}
ALLOW_SIGNUP=false
BACKUP_DIR=./backups
BACKUP_HOUR_UTC=2
BACKUP_RETAIN_DAILY=30
BACKUP_RETAIN_MONTHLY=12
BACKUP_RCLONE_REMOTE=
RUST_LOG=info
ENV
  umask 022
  FRESH=1
else
  say "Using the existing $ENV_FILE (delete it to start over; that also discards the server secret)"
  FRESH=0
fi

DOMAIN=$(sed -n 's/^VAULT_DOMAIN=//p' "$ENV_FILE")

# The Rust build needs roughly 4 GB of memory. Warn instead of failing halfway through.
if [ -r /proc/meminfo ]; then
  total_kb=$(awk '/^MemTotal:|^SwapTotal:/ {s += $2} END {print s}' /proc/meminfo)
  if [ "${total_kb:-0}" -lt 3800000 ]; then
    printf '\nwarning: under 4 GB of RAM + swap. The first build may be killed. Add swap first:\n'
    printf '  sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile\n'
  fi
fi

say "Building and starting the stack (the first build takes 15-25 minutes)"
"${COMPOSE[@]}" up -d --build

say "Waiting for the API to become healthy"
for _ in $(seq 1 60); do
  state=$("${COMPOSE[@]}" ps --format '{{.Health}}' api 2>/dev/null || true)
  [ "$state" = "healthy" ] && break
  sleep 5
done
[ "${state:-}" = "healthy" ] || die "the API did not become healthy. Check: ${COMPOSE[*]} logs api"

say "Running a first backup to prove backups work"
"${COMPOSE[@]}" exec -T -u backup backup backup.sh

cat <<DONE

Arevei Vault is running at https://${DOMAIN}
(Caddy fetches the TLS certificate on first request; DNS for ${DOMAIN} must point at this server
 and ports 80 and 443 must be open.)

Do these now:
  1. Open https://${DOMAIN} and sign up. The FIRST account becomes the organization Owner.
  2. Copy SERVER_SECRET_KEY from ${ENV_FILE} to offline storage. Losing it locks every account out.
DONE
if [ "$FRESH" = 1 ]; then
  cat <<DONE
  3. Move ${KEY_FILE} OFF this server (two offline copies), then delete it here.
     It is the only key that can decrypt your backups in deploy/backups/.
DONE
fi
cat <<DONE

Browser extension: install Arevei Vault, open it, choose "Use a self-hosted server" and enter
https://${DOMAIN}
DONE
