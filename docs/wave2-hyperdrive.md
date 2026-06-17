# Wave 2 — Hyperdrive capability probe (W-CAP-01) runbook

Stands up a throwaway Postgres in the Talos cluster and routes Cloudflare
Hyperdrive to it over **Workers VPC** (your existing `cloudflared` tunnel), so the
**W-CAP-01** probe can demonstrate the Hyperdrive-binding blast radius.

```
Worker(env.HYPERDRIVE) → Hyperdrive → VPC Service → cloudflared → wulf-pg-rw:5432
```

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
