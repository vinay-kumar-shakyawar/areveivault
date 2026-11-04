# Setup guide

For the engineer deploying Arevei Vault or developing on it.

## Production (self-hosted, Docker Compose)

Requirements: a Linux host with Docker Engine 24+, ports 80/443 open, and DNS for `vault.arevei.com` pointing at the host.

```bash
git clone <repo> arevei-vault && cd arevei-vault
cp deploy/.env.example deploy/.env
# Fill in:
#   SERVER_SECRET_KEY     openssl rand -base64 32      (store a copy OFFLINE, see backup-and-recovery.md)
#   POSTGRES_PASSWORD     openssl rand -hex 24
#   REDIS_PASSWORD        openssl rand -hex 24
#   BACKUP_AGE_RECIPIENT  from `age-keygen` run on an OFFLINE machine
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build
```

Caddy obtains TLS certificates automatically. Open `https://vault.arevei.com` and **sign up immediately**. The first account bootstraps the organization and becomes its Owner. Leave `ALLOW_SIGNUP=false` so that everyone else needs an invite.

After first sign-in:
1. Create a **second Owner** right away (Admin → Invites), so losing one owner never locks the team out of shared projects.
2. Note the **organization fingerprint** (Settings → Organization). Every member should compare it with an owner out of band, in person or on a call, the first time they sign in.
3. Submit `vault.arevei.com` to the HSTS preload list (https://hstspreload.org) after confirming HTTPS works on every subdomain.
4. Schedule the quarterly restore drill (see [backup-and-recovery.md](backup-and-recovery.md)).

### Upgrading
```bash
git fetch --tags && git checkout vX.Y.Z
# Verify the release: compare web/dist/bundle-hashes.json from your build with the signed one on the release page
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build
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
