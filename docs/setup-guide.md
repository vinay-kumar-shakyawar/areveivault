# Setup guide

For the engineer deploying Arevei Vault or developing on it.

## Production (self-hosted, Docker Compose)

### Before you start

| You need | Why |
|---|---|
| A Linux server (the EC2 launcher uses Ubuntu 24.04) with **2 vCPU and 4 GB RAM**, 20 GB disk | The images are compiled on the server; the Rust build needs about 4 GB of RAM + swap. After the build the stack idles at well under 1 GB. |
| Docker Engine 24+ with the Compose plugin | `curl -fsSL https://get.docker.com \| sh` |
| A domain, e.g. `vault.yourco.com`, with a DNS **A record pointing at the server** | Caddy gets a Let's Encrypt certificate for it. The vault only works over HTTPS. |
| Ports **80 and 443** open to the internet | Certificate issuance and the app itself |

No domain yet? `vault.<server-ip-with-dashes>.sslip.io` (for example `vault.203-0-113-7.sslip.io`) resolves to the server and gets a real certificate.

### Quick setup (recommended)

```bash
git clone https://github.com/vinay-kumar-shakyawar/areveivault.git
cd areveivault
./deploy/selfhost.sh vault.yourco.com you@yourco.com
```

The script generates every secret, creates the backup encryption key, writes `deploy/.env`, builds and starts the stack, waits for the API to report healthy, and runs one backup to prove backups work. The first build takes 15-25 minutes. It then prints the three things you must do by hand:

1. Open `https://vault.yourco.com` and **sign up immediately**. The first account bootstraps the organization and becomes its Owner.
2. Copy `SERVER_SECRET_KEY` from `deploy/.env` to offline storage. If you lose it, every account is locked out.
3. Move `deploy/backup-identity.txt` off the server (two offline copies), then delete it there. It is the only key that can decrypt your backups.

### Manual setup

If you'd rather not run the script, this is everything it does:

```bash
git clone https://github.com/vinay-kumar-shakyawar/areveivault.git
cd areveivault
cp deploy/.env.example deploy/.env
# Fill in:
#   VAULT_DOMAIN          vault.yourco.com (bare domain)
#   ACME_EMAIL            address for certificate expiry notices
#   SERVER_SECRET_KEY     openssl rand -base64 32      (store a copy OFFLINE, see backup-and-recovery.md)
#   POSTGRES_PASSWORD     openssl rand -hex 24
#   REDIS_PASSWORD        openssl rand -hex 24
#   BACKUP_AGE_RECIPIENT  the public key from `age-keygen`, ideally run on an OFFLINE machine
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build
```

### Coolify (or any proxy that already owns ports 80 and 443)

`deploy/selfhost.sh` and `deploy/docker-compose.yml` bind ports 80/443 themselves, which collides with Coolify's proxy. Use `deploy/docker-compose.coolify.yml` instead: Coolify's proxy handles the certificate and forwards to the `caddy` service on port 80.

1. In Coolify, add a new resource from the public Git repository, branch `main`, with the **Docker Compose** build pack. Base directory `/`, compose file `/deploy/docker-compose.coolify.yml`.
2. Give the `caddy` service your domain, e.g. `https://vault.yourco.com`, and point that domain's DNS A record at the Coolify server. Leave the other services without a domain.
3. Deploy. There are no environment variables to fill in: Coolify generates the database and Redis passwords and the server secret itself, and passes the domain to the API. The first build takes 15-25 minutes (longer on a 1-CPU server) and needs about 4 GB of RAM + swap.
4. Open the domain and sign up. The first account creates the organization and becomes its Owner; everyone after that needs an invite.
5. Under **Environment Variables**, copy `SERVICE_PASSWORD_64_SERVERSECRET` somewhere safe and offline. A database backup can't be restored without it.

Optional: set `BACKUP_AGE_RECIPIENT` (the public key from `age-keygen`) to turn on encrypted nightly backups.

Backups go to the `backups` Docker volume rather than a folder in the repository.

### What is running

| Service | Role |
|---|---|
| `caddy` | HTTPS (automatic certificates), the web app, security headers, proxies `/api` to the API |
| `api` | The Arevei Vault server. Runs database migrations at startup. |
| `postgres`, `redis` | Data and rate-limit/session state. Not reachable from outside the host. |
| `backup` | Nightly encrypted dump of the database and attachments into `deploy/backups/` |

Leave `ALLOW_SIGNUP=false` so that everyone after the first account needs an invite.

### After first sign-in

1. Create a **second Owner** right away (Admin → Invites), so losing one owner never locks the team out of shared projects.
2. Note the **organization fingerprint** (Settings → Organization). Every member should compare it with an owner out of band, in person or on a call, the first time they sign in.
3. Submit your domain to the HSTS preload list (https://hstspreload.org) after confirming HTTPS works on every subdomain.
4. Set up off-host backup copies and schedule the quarterly restore drill (see [backup-and-recovery.md](backup-and-recovery.md)).

### Browser extension on a self-hosted server

The published extension talks to `https://vault.arevei.com` by default. To use it with your server, open the extension while signed out, choose **Use a self-hosted server**, and enter `https://vault.yourco.com`. The extension checks that an Arevei Vault server answers there before saving the address.

One feature is unavailable this way: the web app's lock signal to the extension, because browsers only let a web page message an extension from origins listed in the extension's manifest. The extension still locks on its own timer, on screen lock, and when the browser closes. If you want that link too, or want the address preset for your team, build your own copy: `VAULT_ORIGIN=https://vault.yourco.com pnpm --filter extension package` (see [extension/README.md](../extension/README.md)).

### Checking and troubleshooting

```bash
C="docker compose -f deploy/docker-compose.yml --env-file deploy/.env"
$C ps                # every service should be "running"; api, postgres, redis "healthy"
$C logs -f caddy     # certificate problems show up here
$C logs api
$C logs backup       # warns at startup if backups can't be written
```

| Symptom | Likely cause |
|---|---|
| Browser shows a certificate error or can't connect | DNS doesn't point at the server yet, or ports 80/443 are blocked. Caddy retries on its own once they're fixed. |
| Build stops with `Killed` or exit code 137 | Out of memory. Add 4 GB of swap and re-run. |
| Sign-up says "registration requires an invitation" | An Owner already exists. Ask them for an invite, or (for a fresh start) the database isn't empty. |
| Sign-in fails with "origin not allowed" | The address in the browser isn't exactly `https://` + `VAULT_DOMAIN`. |

### Upgrading
```bash
git fetch --tags && git checkout vX.Y.Z     # or: git pull
# Verify the release: compare web/dist/bundle-hashes.json from your build with the signed one on the release page
./deploy/selfhost.sh                        # keeps deploy/.env, rebuilds, restarts, runs a backup
```
Database migrations run automatically when the API starts.

## Production (AWS)

`deploy/terraform` provisions VPC, RDS Postgres (encrypted, 30-day PITR), ElastiCache Redis, ECS Fargate (API), EFS (attachments), S3 + CloudFront (web bundle, with the full security-header policy), an S3 Object Lock bucket (audit checkpoints), KMS, and Secrets Manager.

```bash
cd deploy/terraform
terraform init
terraform apply -var api_image_tag=<git-sha> \
  -var alb_certificate_arn=<acm arn in region> \
  -var cloudfront_certificate_arn=<acm arn in us-east-1>
# Push the API image to the ECR repo from outputs, and sync web/dist to the web bucket:
aws s3 sync web/dist s3://$(terraform output -raw web_bucket) --delete
```

The configuration passes `terraform validate`. It has **not yet been applied** to a real account, so review the sizing, region (`ap-south-1` default), and network ACLs before using it.

## Local development

Requirements: Rust (stable, plus the `wasm32-unknown-unknown` target), `wasm-bindgen-cli` 0.2.130, Node 20+, pnpm 10, and Docker.

```bash
# Rust toolchain on Windows without MSVC: rustup with the GNU host works
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.130 --locked

pnpm install
bash scripts/build-wasm.sh                          # core → packages/core-wasm/pkg
docker compose -f deploy/docker-compose.dev.yml up -d   # Postgres + Redis
cp server/.env.example server/.env && cargo run -p arevei-server
pnpm --filter web dev                               # http://localhost:5173 (proxies /api to :8080)
pnpm --filter extension build                       # load extension/dist/chrome as unpacked
```

### Tests

| Suite | Command |
|---|---|
| Core (crypto vectors, property tests, engine flows) | `cargo test -p arevei-core` |
| Core coverage (Linux/CI only; the Windows GNU toolchain lacks the profiler runtime) | `cargo llvm-cov -p arevei-core --fail-under-lines 80` |
| Server integration (needs dev compose up) | `cargo test -p arevei-server -- --test-threads=1` |
| Web unit + build + CSP audit | `pnpm --filter web test && pnpm --filter web build && node web/scripts/check-csp.mjs web/dist` |
| Extension unit + e2e | `pnpm --filter extension test && pnpm --filter extension e2e` |
