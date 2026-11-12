# @wulf/hub

ScanHub and ScanWorkflow for `POSTURE_PLAN.md` slice 3. One deployment scans one Cloudflare account on a schedule, keeps the findings lifecycle in Durable Object SQLite, and writes scan history to R2.

## How it works

- **ScanWorkflow** (`src/workflow.ts`) runs one scan in these steps: `begin` → `list scripts` → `collect scripts i/n` (4 scripts per step) → `collect namespaces` → `complete`.
  - Each collect step reads through `@wulf/core`'s `CfApi`, summarizes what it read with `@wulf/analyze`, and appends one batch to ScanHub.
  - Bundle text never leaves the step. A bundle over 1.5 MB isn't parsed, and is recorded as `analyze` / `unavailable` coverage instead.
- **ScanHub** (`src/hub.ts`, `src/store.ts`) is one Durable Object per account.
  - `append` is idempotent on `(scan_id, batch_no)`.
  - `complete` folds the batches into observations, edges and coverage, runs every account rule (`analyzeSummary`), and updates findings.
  - Finding states are open, resolved and suppressed. A `partial` scan resolves nothing.
  - An unseen finding stays open when its target's reads didn't complete, or when its rule threw.
  - The alarm exports finished scans to `history/<scan_id>/` in R2, then prunes.

## Endpoints

Every request needs `Authorization: Bearer <WULF_TOKEN>`. With no token configured, every request is refused.

| Endpoint | Does |
|---|---|
| `GET /findings?state=open\|resolved\|suppressed` | Findings, most severe first |
| `GET /scans`, `GET /scans/:id`, `GET /scans/:id/occurrences` | Scan records with coverage, and per-scan evidence |
| `POST /scans` | Start a scan now |
| `POST /findings/suppress` `{key, reason}`, `POST /findings/unsuppress` `{key}` | Suppression |
| `POST /ingest/scan` `{accountId, startedAt, batches}` | A scan pushed by `wulf scan --push <url>` (token from `WULF_HUB_TOKEN`) |

A cron trigger (`17 */6 * * *`) starts a scan every six hours.

## Config

`wrangler.jsonc` keeps `workers_dev` and `preview_urls` off. Each deployment sets:
- the var `CLOUDFLARE_ACCOUNT_ID`;
- the secrets `CLOUDFLARE_API_TOKEN` (read-only: Workers Scripts Read) and `WULF_TOKEN`;
- the R2 bucket `wulf-history`.

## Tests

`pnpm test` runs inside workerd with `@cloudflare/vitest-plugin`. `test/fake-cf.js` stands in for the Cloudflare API, and tests change its account between scans.

The tests cover:
- equivalence with in-memory `analyzeAccount`;
- identity across scans, resolve after a fix, and reopen;
- partial, denied, over-limit and failed scans;
- suppression and idempotency;
- R2 export and pruning;
- HTTP auth and push;
- a sentinel showing that no binding value or bundle text reaches SQLite or R2.

Vite doesn't see wrangler's `alias`, so `vitest.config.ts` points `oxc-parser` at the WASM shim itself. workerd logs an emnapi "Disallowed operation called within global scope" message while loading the parser. The tests still pass.
