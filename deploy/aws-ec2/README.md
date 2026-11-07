# Single-host AWS deployment

One EC2 instance running the standard Docker Compose stack from [`deploy/docker-compose.yml`](../docker-compose.yml): Caddy (TLS), the API, Postgres, Redis and the encrypted backup job.

## Launch

```bash
bash deploy/aws-ec2/launch.sh                            # no DNS needed: https://vault.<ip>.sslip.io
bash deploy/aws-ec2/launch.sh --domain vault.arevei.com  # once an A record points at the Elastic IP
```

The AWS CLI must be signed in with EC2 access. The script creates a key pair (`deploy/aws-ec2/arevei-vault.pem`, git-ignored), a security group, an Elastic IP and a `t3.large` with a 40 GB disk, then hands [`bootstrap.sh`](bootstrap.sh) to cloud-init. The host installs Docker, clones the repo, generates every secret locally, and runs `docker compose up -d --build`. The first build takes 15-25 minutes.

## After launch

1. Watch the build: `ssh -i deploy/aws-ec2/arevei-vault.pem ubuntu@<ip> 'sudo tail -f /var/log/arevei-bootstrap.log'`.
2. Open the vault URL and sign up. The first account is the organization Owner.
3. Copy `SERVER_SECRET_KEY` from `/opt/arevei-vault/deploy/.env` to offline storage. Losing it locks every account out.
4. Move `/root/arevei-vault-age-key.txt` off the host. Backups in `/opt/arevei-vault/deploy/backups` can only be decrypted with it.
5. Follow the first-run steps in [docs/setup-guide.md](../../docs/setup-guide.md): second Owner, organization fingerprint, HSTS preload.

## Switch to your own domain later

Point `vault.arevei.com` (an A record) at the Elastic IP, then on the host:

```bash
cd /opt/arevei-vault
sudo sed -i 's/^VAULT_DOMAIN=.*/VAULT_DOMAIN=vault.arevei.com/' deploy/.env
sudo docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d
```

Existing accounts and vault data are unaffected. The browser extension must be pointed at the new origin.

## Upgrade

```bash
cd /opt/arevei-vault && sudo git pull
sudo docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build
```

## Sizing

`t3.large` is for the first build. After it finishes you can stop the instance, change it to `t3.small`, and start it again. The Elastic IP stays attached.
