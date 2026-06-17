# wulf — Infrastructure

Terraform owns stateful resources (KV, R2, D1, droplet, DNS). Wrangler owns
Worker code deployment. The two meet at a handful of IDs that flow from
`terraform output` into the per-package `wrangler.toml`.

## Prerequisites

- Cloudflare account on **Workers Paid** (Dynamic Workers + DO 10GB require it).
- Cloudflare API token with: Workers Scripts, Workers KV, R2, D1 — edit perms.
- DigitalOcean API token.
- A domain you control. Delegate its nameservers to DigitalOcean before apply.
- An SSH keypair for the callback host.

## Apply order

```bash
cd infra
cp terraform.tfvars.example terraform.tfvars   # then edit
terraform init
terraform plan
terraform apply
```

After apply, wire the outputs into the two Worker packages:

```bash
terraform output -raw kv_namespace_id
terraform output -raw d1_database_id
terraform output -raw cloudflare_account_id
```

Update each package's `wrangler.toml`:

- `packages/worker/wrangler.toml` — replace `id = "wulf_kv_local"` and the
  D1 placeholder with the IDs above.
- `packages/dynamic-parent/wrangler.toml` — same.

Then deploy the Worker code:

```bash
export CLOUDFLARE_ACCOUNT_ID="$(terraform -chdir=infra output -raw cloudflare_account_id)"
pnpm --filter @wulf/worker          deploy
pnpm --filter @wulf/dynamic-parent  deploy
```

And point the harness at the deployed URLs:

```bash
pnpm --filter @wulf/harness exec tsx src/index.ts run \
  --base-url https://wulf-worker.<your-subdomain>.workers.dev \
  --track worker --run-id prod-$(date +%s)
```

## Deliberately out of scope (v1)

These are tracked in the PRD §4.2 but deferred:

- `cloudflare_workers_script` resources — wrangler handles this better; no
  upside to dual-managing.
- Tail Worker (`prey-tail`) — needs its own Worker code; PRD §3.1.5 / §3.4
  monitoring tests blocked until then.
- Durable Object class (Track 3) — separate `packages/durable/` not yet
  scaffolded.
- Cloudflare Queue, Analytics Engine dataset — only useful once probes for
  them exist (PRD §3.1.3 W-BND-01 covers their presence as bindings).
- Logpush job — needs a sink (R2 callback bucket can serve this later).

## Callback receivers

The VPS comes up bare. Receivers are deployed out-of-band — none of them
exist yet. When they do, they should:

1. Listen on 80/443 (HTTP), 443 (WSS upgrade), 53 (authoritative DNS for
   the `dns_exfil_zone` output).
2. Append every received event as a JSON line to `/var/log/wulf/*.jsonl`.
3. Upload every received event to the `${name_prefix}-callback-events` R2 bucket.

The harness `analyze` subcommand can then DuckDB-join probe results with
R2-hosted callback events.

The receiver implementation now lives in `packages/callbackd/`. Configure it
with:

```bash
export WULF_CALLBACK_DOMAIN="wulf.shart.cloud"
export WULF_DNS_ZONE="$(terraform output -raw dns_exfil_zone)"
export WULF_DNS_ANSWER_IPV4="$(terraform output -raw callback_host_ipv4)"
export WULF_R2_BUCKET="$(terraform output -raw r2_callback_events_bucket)"
export WULF_R2_ACCOUNT_ID="$(terraform output -raw cloudflare_account_id)"
export WULF_R2_ACCESS_KEY_ID="..."
export WULF_R2_SECRET_ACCESS_KEY="..."
go build ./packages/callbackd
```

Terraform now handles the host-side `callbackd` deployment too:

- `terraform apply` builds `packages/callbackd` locally.
- It uploads the binary, `/etc/wulf/callbackd.env`, and the systemd unit over SSH.
- It enables and restarts `callbackd.service` when the Go source, service unit,
  or rendered env file changes.

Additional required Terraform vars:

```bash
export TF_VAR_callback_r2_access_key_id="..."
export TF_VAR_callback_r2_secret_access_key="..."
export TF_VAR_ssh_private_key_path="$HOME/.ssh/id_ed25519"
```

Local prerequisites for `terraform apply`:

- `go` installed on the machine running Terraform
- SSH access to the droplet as `root` using `ssh_private_key_path`

Suggested rollout sequence:

```bash
export TF_VAR_cloudflare_api_token="..."
export TF_VAR_digitalocean_api_token="..."
export TF_VAR_cloudflare_account_id="..."
export TF_VAR_cloudflare_zone_id="..."
export TF_VAR_callback_domain="wulf.shart.cloud"
export TF_VAR_ssh_public_key_path="$HOME/.ssh/id_ed25519.pub"
export TF_VAR_ssh_private_key_path="$HOME/.ssh/id_ed25519"
export TF_VAR_callback_r2_access_key_id="..."
export TF_VAR_callback_r2_secret_access_key="..."

make callbackd-plan
make callbackd-apply
```

Equivalent npm-style entrypoints from the repo root:

```bash
pnpm run callbackd:plan
pnpm run callbackd:apply
```

The Track 1 and Track 2 Worker packages now also expect these vars in
`wrangler.toml` so `W-NET-01`, `W-NET-03`, `W-NET-05`, `D-NET-01`, and
`D-NET-02` default to controlled callback targets instead of public hosts.

## State backend

Local for now. To move to R2:

```hcl
terraform {
  backend "s3" {
    bucket                      = "wulf-tfstate"  # create out-of-band
    key                         = "infra.tfstate"
    region                      = "auto"
    endpoint                    = "https://<account>.r2.cloudflarestorage.com"
    skip_credentials_validation = true
    skip_region_validation      = true
    skip_metadata_api_check     = true
    use_path_style              = true
  }
}
```

Then `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` set to an R2 API token.

## Provider version caveats

- `cloudflare` ~> 5.0 — major v5 renamed several resources. If `terraform
  init` fails on `cloudflare_workers_kv_namespace` /
  `cloudflare_r2_bucket` / `cloudflare_d1_database`, check the v5 migration
  guide; they may have new attribute names.
- `digitalocean` ~> 2.40 — stable.

These haven't been `terraform apply`-tested. Run `terraform validate` +
`terraform plan` and fix any drift before applying.
