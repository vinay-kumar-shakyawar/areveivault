#!/usr/bin/env bash
# cloud-init user-data for an Ubuntu 24.04 EC2 host. Installs Docker, clones the repo,
# generates all secrets on the host, writes deploy/.env and starts the Compose stack.
# launch.sh prepends `export VAULT_DOMAIN=... ACME_EMAIL=... PUBLIC_IP=...` before sending it.
# Progress log: /var/log/arevei-bootstrap.log   Done marker: /var/log/arevei-bootstrap.done
set -euxo pipefail
exec > >(tee -a /var/log/arevei-bootstrap.log) 2>&1

REPO_URL="${REPO_URL:-https://github.com/vinay-kumar-shakyawar/areveivault.git}"
REPO_REF="${REPO_REF:-main}"
ACME_EMAIL="${ACME_EMAIL:-admin@arevei.com}"
PUBLIC_IP="${PUBLIC_IP:-}"
APP_DIR=/opt/arevei-vault

# No DNS yet? Use a sslip.io name that resolves to the Elastic IP; Caddy gets a real cert for it.
if [ -z "${VAULT_DOMAIN:-}" ]; then
  VAULT_DOMAIN="vault.${PUBLIC_IP//./-}.sslip.io"
fi

# Wait until the Elastic IP is attached, so the IP swap can't break downloads mid-build.
if [ -n "$PUBLIC_IP" ]; then
  for _ in $(seq 1 60); do
    tok=$(curl -sX PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60" || true)
    cur=$(curl -s -H "X-aws-ec2-metadata-token: $tok" http://169.254.169.254/latest/meta-data/public-ipv4 || true)
    [ "$cur" = "$PUBLIC_IP" ] && break
    sleep 5
  done
fi

# Swap: the Rust release build is memory hungry.
if [ ! -f /swapfile ]; then
  fallocate -l 4G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
  echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y git curl openssl age ca-certificates
curl -fsSL https://get.docker.com | sh
usermod -aG docker ubuntu || true
systemctl enable --now docker

if [ ! -d "$APP_DIR/.git" ]; then
  git clone --branch "$REPO_REF" "$REPO_URL" "$APP_DIR"
fi
cd "$APP_DIR"

if [ ! -f deploy/.env ]; then
  # Backup encryption key. Move the PRIVATE key off this host and keep it offline.
  age-keygen -o /root/arevei-vault-age-key.txt
  AGE_RECIPIENT=$(age-keygen -y /root/arevei-vault-age-key.txt)
  umask 077
  cat > deploy/.env <<ENV
VAULT_DOMAIN=${VAULT_DOMAIN}
ACME_EMAIL=${ACME_EMAIL}
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
fi

# The backup container runs as uid 10001 and must be able to write here.
mkdir -p deploy/backups && chown 10001:10001 deploy/backups

docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build

echo "Arevei Vault is starting at https://${VAULT_DOMAIN}"
touch /var/log/arevei-bootstrap.done
