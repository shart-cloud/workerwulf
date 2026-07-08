# Wave 2 — Hyperdrive capability probe (W-CAP-01) runbook

Stands up a throwaway Postgres in the Talos cluster and routes Cloudflare
Hyperdrive to it over **Workers VPC** through a **dedicated `wulf-vpc` tunnel**, so
the **W-CAP-01** probe can demonstrate the Hyperdrive-binding blast radius.

```
Worker(env.HYPERDRIVE) → Hyperdrive → VPC Service → cloudflared(wulf-vpc) → wulf-pg-rw:5432
```

> ## ✅ DEPLOY-VERIFIED — `accessible`/`critical` (2026-07-08)
>
> W-CAP-01 exfiltrated `flag{w-cap-01-hyperdrive-canary}` end-to-end:
> ```
> Worker(env.HYPERDRIVE) → Hyperdrive ed30b8cf → VPC svc 019f3e90
>   → wulf-vpc tunnel afb91b61 (WARP routing) → wulf-pg-rw 10.98.113.176:5432
> ```
> `binding_exposed` returned host/user/password off the binding, and `rows`
> contained the canary. Run against `wulf-worker.sharted.workers.dev`.
>
> **Design note — dedicated tunnel (not the prod lab tunnel).** Rather than add
> `warp-routing` to the shared `lab-gitops` tunnel (teleport/gophish/*.lab), a
> throwaway **`wulf-vpc`** tunnel was created just for Workers VPC probes:
> ```
> cloudflared tunnel create wulf-vpc                       # id afb91b61-…
> cloudflared tunnel route ip add 10.96.0.0/12 wulf-vpc    # whole service CIDR
> ```
> With WARP routing over the whole service CIDR, **any** in-cluster Service is
> reachable to a Workers VPC service just by pointing `host.ipv4` at its ClusterIP
> — no tunnel edit per backend. Connector manifests live in
> `containers/talos-gitops/infrastructure/base/wulf-vpc/` (applied by `kubectl`,
> kept out of Flux so it stays tunable). Set `TF_VAR_wulf_tunnel_id=afb91b61-…`.
>
> **Gotcha — GRANT on the canary tables.** CNPG runs `postInitApplicationSQL` as
> the `postgres` superuser, so `wulf_canary`/`app_secrets` are owned by `postgres`
> and the `wulf` app user (the connection identity) gets `permission denied`. After
> the DB is up, grant read access — the probe returns `error` ("permission denied
> for table wulf_canary") until you do:
> ```bash
> kubectl exec -n wulf-pg wulf-pg-1 -- psql -U postgres -d wulf \
>   -c "GRANT SELECT ON wulf_canary, app_secrets TO wulf;"
> ```
>
> **Token scopes.** The Terraform token (`infra/.envrc`) needs account-scope
> **Hyperdrive: Edit** *and* **Workers VPC / connectivity: Edit** — the VPC
> `connectivity/directory/services` create 403s without the latter.

Everything below is applied by **you** — nothing here was deployed automatically.

## Pieces (already written)

| Where | What |
|---|---|
| `talos-gitops/infrastructure/base/wulf-pg/` | CNPG `Cluster` (db `wulf`, canary seeded via `postInitApplicationSQL`), namespace, kustomization, README |
| `infra/hyperdrive.tf` (+ vars/outputs) | `cloudflare_connectivity_directory_service` (VPC Service) + `cloudflare_hyperdrive_config` (origin `service_id`) |
| `packages/worker/wrangler.toml` | `[[hyperdrive]]` binding — **commented; fill `id` after apply** (see step 5) |
| `packages/worker/src/probes/w-cap-01.ts` | the probe (`postgres.js` dep added) |

## Prerequisites

1. **Provider ≥ 5.13** for Workers VPC: `terraform -chdir=infra init -upgrade`.
2. **WARP routing on the tunnel** — `cloudflared` must proxy raw TCP to the
   Postgres ClusterIP. Add to the `cloudflared-config` ConfigMap:
   ```yaml
   warp-routing:
     enabled: true
   ```
3. **Tunnel UUID** of the existing in-cluster `cloudflared` → TF `wulf_tunnel_id`.

## Apply sequence

1. **DB** — wire `../../base/wulf-pg` into the cluster kustomization, commit, let
   Flux reconcile. Verify the canary:
   ```bash
   kubectl exec -n wulf-pg wulf-pg-1 -- psql -U wulf -d wulf -c 'SELECT * FROM wulf_canary;'
   ```
2. **Collect TF inputs** (into `infra/terraform.tfvars` or `TF_VAR_*`):
   ```bash
   wulf_tunnel_id        = "<existing cloudflared tunnel UUID>"
   hyperdrive_pg_host    = "$(kubectl get svc wulf-pg-rw -n wulf-pg -o jsonpath='{.spec.clusterIP}')"
   hyperdrive_pg_user    = "$(kubectl get secret wulf-pg-app -n wulf-pg -o jsonpath='{.data.username}' | base64 -d)"
   hyperdrive_pg_password= "$(kubectl get secret wulf-pg-app -n wulf-pg -o jsonpath='{.data.password}' | base64 -d)"
   # hyperdrive_pg_database defaults to "wulf"; hyperdrive_cert_mode defaults to "disabled"
   ```
3. **Apply Hyperdrive/VPC**:
   ```bash
   terraform -chdir=infra plan
   terraform -chdir=infra apply
   HID=$(terraform -chdir=infra output -raw hyperdrive_id)
   ```
4. **Bind it** — in `packages/worker/wrangler.toml` uncomment and set:
   ```toml
   [[hyperdrive]]
   binding = "HYPERDRIVE"
   id = "<HID>"
   ```
5. **Deploy + run**:
   ```bash
   pnpm --filter @wulf/worker deploy
   cd packages/harness && pnpm start run --test W-CAP-01 --base-url https://wulf-worker.<subdomain>.workers.dev
   ```

## Expected result

`W-CAP-01` → `accessible` / `critical`: `binding_exposed` shows host/user/password
off the binding, and `rows` contains `flag{w-cap-01-hyperdrive-canary}` — the
Serverless-Prey "DB creds in the function env, used to read the database" finding,
on Workers.

## Notes / open items

- **TLS**: `hyperdrive_cert_mode = "disabled"` because CNPG presents a self-signed
  CA and Cloudflare doesn't yet support a custom CA for VPC services. Revisit to
  `verify_ca` when supported.
- **Host by IP vs DNS**: `hyperdrive_pg_host` uses the `-rw` ClusterIP. If the
  Service is recreated the IP can change — re-run `apply` with the new value, or
  pin the Service `clusterIP`.
- **Teardown**: delete the `wulf-pg` namespace + `terraform destroy` the two
  Hyperdrive resources. Canary-only data; nothing real is lost.
