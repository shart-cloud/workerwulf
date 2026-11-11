# Workerwulf Posture Platform: Plan

**Status:** Draft. Slice 1 is done on `gorejared/platform-core`; slice 2 is next.
**Author:** Jared Gore
**Date:** 2026-11-10
**Related:** `CLI_PRD.md`, `RULES_PRD.md`, `THREAT_MODEL.md`. This is not `platform_prd.md`, which covers Workerwulf Local, the self-hosted workerd lab on Talos.

---

## 1. Summary

Workerwulf already holds the research that a Cloudflare posture tool needs:

- probe families that show what an attacker can do from inside the runtime;
- `wulf`, a scanner whose 98 rule IDs each cite the probe that proved the weakness;
- container Durable Objects that run heavier analyzers.

This plan grows those pieces into a **Cloudflare-native security posture platform**. It runs inside your own Cloudflare account, scans that account on a schedule, and links config, code, identity and data exposure into one graph. It reports *combinations* of weaknesses (toxic combinations), not just single misconfigurations.

The platform is written in **TypeScript on Effect 4** and stores everything on the Cloudflare developer platform: Durable Object SQLite, Workflows, R2 and D1. It does not use DuckDB or corkscrew. Corkscrew stays a separate, multi-cloud, DuckDB-backed project.

The first audience is **your own account**. Open-sourcing comes later, and the design keeps that path open: one deployment per account, nothing hosted, and rules and research shared openly.

## 2. Goals and non-goals

### Goals

1. **Rules backed by evidence.** Every rule cites the probe or research finding that showed the weakness. No rule exists without one, and this is the main difference from generic CSPM rules.
2. **Coverage is explicit.** A read that was denied or failed is never reported as "secure". Every collection step records `complete`, `denied`, `unavailable` or `failed`, and reports show the gaps.
3. **Cloudflare-native at runtime.** Workflows run the scans, a Durable Object (SQLite) holds the state and write-ahead log, R2 keeps history, and an Access-protected Worker serves the UI. Nothing runs outside Cloudflare except the optional CLI.
4. **One rule engine, two runtimes.** The same rule code runs in the Node CLI (`wulf audit` / `wulf scan`) and in a Worker. Rules are pure functions over a snapshot, and only collection is effectful.
5. **A security graph.** Hostnames, routes, Workers, bindings, data stores, secrets, tokens and Access policies become nodes and edges. Toxic combinations are graph queries.
6. **Research flows in.** `ProbeResult`s from the harness and scheduled canary probes become findings in the same store. If the platform's behaviour changes under you, a finding opens.

### Non-goals (for now)

- Multi-tenant SaaS. One deployment means one account, which is one trust domain.
- Remediation that writes to the account. The platform reads only. Fixes are suggested, and IaC pull requests may come later.
- Replacing Cloudflare's built-in Security Center. We ingest its insights instead of rebuilding them.
- Changes to the **probe Workers** (`worker`, `durable`, `dynamic-parent`, `platform`, `container`). They measure the runtime from inside the isolate, and adding a framework would skew globals, timing and bundle size. They also back the ISE 5901 practicum, so their code and results stay frozen.

## 3. Where we are today

| Capability | Where | State |
|---|---|---|
| Config rules (wrangler) | `packages/cli/src/rules/config` | `WF-CFG`, `WF-BIND`, `WF-EGR`, `WF-WFP` |
| Source and bundle rules (AST) | `packages/cli/src/rules/source`, `src/ast` (oxc-parser) | Families A–H |
| Account rules (live API) | `packages/cli/src/rules/account` | `WF-DRIFT-01` (deployed vs local), least privilege (declared vs used bindings), `WF-NS-01..04` (WfP) |
| Cloudflare API client | `packages/cli/src/cf/client.ts` | `CfClient` interface plus `RestCfClient`. **It swallows errors:** a 403 on settings looks the same as "no bindings". |
| Finding shape | `packages/cli/src/engine/rule.ts` | `Finding` has no stable identity or lifecycle |
| Probe results | `packages/shared` (`ProbeResult`) | Plain interface, results kept as JSON files |
| Analysis store | `packages/harness/src/cmd-analyze.ts` | DuckDB over result files (**to retire**) |
| Heavy analyzers | `packages/llamafirewall`, `codeshield` | Container Durable Objects running Semgrep with `wulf-rules.yml` |

## 4. Design principles

1. **Rules are pure.** A rule is `(snapshot) => Finding[]`. It does no I/O, takes no clock reading and picks up no ambient config. That is what lets one engine run on Node, in a Worker and in tests.
2. **Collection is effectful and typed.** Every API call returns `Effect<A, PermissionDenied | NotFound | RateLimited | ApiError>`. Retries, pacing and concurrency are expressed as `Schedule` and `Effect.forEach({ concurrency })`, not hand-rolled.
3. **Coverage travels with the data.** A collector never turns a failure into an empty value. Either the value is absent and a coverage entry explains why, or the value is present and complete.
4. **Never store secret values.** Binding values (`plain_text`, `json`, `secret_text`) and Secrets Store material are never persisted. We store derived signals instead: looks-like-credential, pattern name, length. Bundles are stored as a hash plus redacted evidence snippets, never whole. (The rule comes from corkscrew's Cloudflare provider and is enforced by a sentinel test.)
5. **Stable identity.** Each resource has a deterministic `ResourceRef`. Each finding's key is `(rule_id, resource)`, so findings survive across scans and can be resolved or suppressed.
6. **Read-only by default.** The platform's own API token gets read permission groups only. The token lives in Secrets Store, and the UI sits behind Access.

## 5. Architecture

```
                         ┌──────────────────────── your Cloudflare account ────────────────────────┐
                         │                                                                         │
 cron / manual ─────────▶│  ScanWorkflow (Workflows)                                               │
                         │   step: begin ─▶ step: collect/<service>/<chunk> … ─▶ step: complete    │
                         │        │                │  (Effect collectors over CfApi,               │
                         │        │                │   paced under 1,200 req / 5 min)              │
                         │        ▼                ▼                                               │
                         │  ScanHub Durable Object (SQLite) — one per account                      │
                         │   ├─ batches        ← write-ahead log, idempotent on (scan_id, batch_no)│
                         │   ├─ observations   ← current inventory, attrs JSON                     │
                         │   ├─ edges          ← routes_to / binds / uses / exposes / can_deploy   │
                         │   ├─ coverage       ← what we could and couldn't see                    │
                         │   ├─ findings       ← lifecycle: open / resolved / suppressed           │
                         │   └─ occurrences    ← per-scan evidence                                 │
                         │        │ complete(): run rules (pure) + graph queries (WITH RECURSIVE)  │
                         │        │ alarm: export scan to R2 (JSONL/Parquet), prune old batches    │
                         │        ▼                                                                │
                         │  R2: history/<scan_id>/…   Console Worker (Access) ◀── you              │
                         │                                                                         │
                         │  Analyzer: oxc (WASM) in-Worker for AST rules;                          │
                         │            codeshield/llamafirewall container Durable Object for Semgrep│
                         │  Canary Workers: scheduled probe subsets → ProbeResult → ScanHub        │
                         └─────────────────────────────────────────────────────────────────────────┘
        wulf CLI (Node) ── same core + rules ── local audit / ad-hoc scan / push results to ScanHub
```

### Packages

| Package | Status | Contents |
|---|---|---|
| `@wulf/core` | **new (slice 1)** | Effect Schemas (`Finding`, `Evidence`, `Severity`, `ProbeResult`, `Coverage`, `AccountSnapshot`); the `CfApi` service and its typed errors; the `CfApiRest` layer (fetch-based, so it runs on Node and Workers); `collectAccount`. No Node APIs. |
| `@wulf/cli` | evolves | A thin Node shell: commands, file discovery and rendering. Its rules and AST engine move toward core-compatible pure modules (slice 2). `@wulf/core` is bundled in by tsup, and `effect` becomes a runtime dependency. |
| `@wulf/analyze` | new (slice 2) | The rule engine plus oxc AST, moved out of `cli/src` once it runs in workerd. Possibly folded into core if bundle size allows. |
| `@wulf/hub` | new (slice 3) | The `ScanHub` Durable Object, `ScanWorkflow`, SQLite migrations, R2 export and the graph queries |
| `@wulf/console` | new (slice 6) | Access-protected UI Worker: findings, the graph view, coverage |
| `@wulf/deploy` | new (slice 6) | Alchemy v2 (Effect) stack: Workflow, Durable Object, R2, Secrets Store, Access app, cron. One command deploys into your own account. |
| `@wulf/shared` | unchanged until slice 5 | Then `ProbeResult` becomes a type-only re-export from core's Schema, so probe Workers pick up no runtime Effect dependency |
| `@wulf/harness` | evolves (slice 5) | Posts `ProbeResult`s to ScanHub. `cmd-analyze.ts` (DuckDB) is removed. |
| probe Workers | **frozen** | No changes |

## 6. Data model

### ResourceRef

`cf:<account_id>/<kind>/<id…>`, deterministic and account-qualified:

| Kind | Ref |
|---|---|
| Worker script | `cf:<acct>/workers/<script>` |
| Binding | `cf:<acct>/workers/<script>/bindings/<name>` |
| Route | `cf:<acct>/zones/<zone>/routes/<pattern>` |
| Custom domain | `cf:<acct>/workers/domains/<hostname>` |
| Zone / DNS record | `cf:<acct>/zones/<zone>`, `…/dns/<record_id>` |
| R2 / KV / D1 / Queue / DO namespace | `cf:<acct>/r2/<bucket>`, `/kv/<id>`, `/d1/<id>`, `/queues/<id>`, `/do/<id>` |
| Secrets Store secret | `cf:<acct>/secrets/<store>/<secret>` |
| API token / member | `cf:<acct>/tokens/<id>`, `cf:<acct>/members/<id>` |
| Access app / policy | `cf:<acct>/access/apps/<id>`, `…/policies/<id>` |
| WfP namespace | `cf:<acct>/dispatch/<namespace>` |

In the CLI, `Finding.resource` keeps its human-readable form (`script:prey`, `wrangler.toml`). ScanHub stores the `ResourceRef` alongside it.

### Core records

- **Observation:** `{ scan_id, ref, kind, attrs (JSON), observed_at }`. Never modified after it is written. Latest-known inventory is a view.
- **Edge:** `{ scan_id, from_ref, to_ref, kind }` where `kind ∈ routes_to | binds | uses | exposes | can_deploy | stores`.
- **Coverage:** `{ scan_id, target, op, status: complete | denied | unavailable | failed, detail }`.
- **Finding:** `{ key = rule_id|ref, rule_id, probe, family, severity, ref, title, state: open | resolved | suppressed, first_seen, last_seen }`.
- **Occurrence:** `{ finding_key, scan_id, message, remediation, evidence[] }`.
- **Scan:** `{ scan_id, started_at, completed_at, status: running | complete | partial | failed }`. A scan with any `failed` coverage is `partial`, and a partial scan **never auto-resolves findings**.

## 7. Storage (ScanHub SQLite)

```sql
CREATE TABLE scans        (scan_id TEXT PRIMARY KEY, started_at TEXT, completed_at TEXT, status TEXT);
CREATE TABLE batches      (scan_id TEXT, batch_no INTEGER, payload TEXT, received_at TEXT,
                           PRIMARY KEY (scan_id, batch_no));              -- WAL; pruned after export
CREATE TABLE observations (scan_id TEXT, ref TEXT, kind TEXT, attrs TEXT, PRIMARY KEY (scan_id, ref));
CREATE TABLE edges        (scan_id TEXT, from_ref TEXT, to_ref TEXT, kind TEXT,
                           PRIMARY KEY (scan_id, from_ref, to_ref, kind));
CREATE TABLE coverage     (scan_id TEXT, target TEXT, op TEXT, status TEXT, detail TEXT);
CREATE TABLE findings     (key TEXT PRIMARY KEY, rule_id TEXT, probe TEXT, family TEXT, severity TEXT,
                           ref TEXT, title TEXT, state TEXT, first_seen TEXT, last_seen TEXT,
                           suppressed_reason TEXT);
CREATE TABLE occurrences  (finding_key TEXT, scan_id TEXT, message TEXT, remediation TEXT, evidence TEXT,
                           PRIMARY KEY (finding_key, scan_id));
```

- **Write path:** a Workflow step calls `append(scan_id, batch_no, batch)`, which does `INSERT … ON CONFLICT DO NOTHING`. Workflow step retries are therefore safe.
- **Complete:** `complete(scan_id)` folds the batches into observations, edges and coverage. It then builds the `AccountSnapshot`, runs the pure rules and the graph queries, upserts findings, and, unless the scan is partial, resolves open findings that weren't seen. The last step schedules an alarm.
- **Alarm:** writes `history/<scan_id>/{observations,edges,findings,coverage}.jsonl` to R2, prunes batches, and keeps observations for the last N scans (default 10).
- **Size:** a single account's graph is thousands of rows, well within Durable Object SQLite limits. D1 is only needed if a cross-account view ever exists.

## 8. Collection coverage roadmap

| Priority | Service | Gives us |
|---|---|---|
| P0 (slice 1, current) | Workers scripts, settings and bindings, script content, routes, WfP namespaces | Feature parity with `wulf scan` |
| P1 | workers.dev subdomain and `previews_enabled`, custom domains, zone routes, cron triggers, observability/logpush | Exposure edges (`exposes`, `routes_to`) |
| P1 | R2 (r2.dev and custom domains, CORS), KV, D1, Queues, DO namespaces, Hyperdrive (origin host only), Secrets Store (metadata only) | Data stores, binding resolution (dangling binding detection) |
| P2 | Zones and settings (min TLS, Always HTTPS, HSTS), DNSSEC, DNS records (DNS-only records that reveal an origin, dangling CNAMEs), rulesets/WAF | Zone baseline, origin bypass |
| P2 | Access apps, policies, identity providers, service tokens; Tunnels and their public hostnames | Identity and exposure for Zero Trust |
| P3 | API tokens (permission groups, expiry, IP filters), account members and roles, Audit Logs | `can_deploy` edges, identity drift, detections |
| P3 | Security Center insights, leaked-credential checks, Page Shield | Cloudflare's own findings, ingested as another source |
| P4 | AI Gateway (logging config), Vectorize, Workers AI usage, Agents/MCP behind Access | AI surface |

Each collector is an Effect function `collectX: Effect<Batch, never, CfApi>`. Failures go into the batch's coverage entries; the collector itself does not fail.

## 9. Rules and toxic combinations

Single-resource rules continue the existing families (A–H). New graph rules are queries over `edges` and `observations`. Each one cites the probe that makes it more than theory:

| ID (proposed) | Path | Evidence |
|---|---|---|
| `WF-TOX-01` | public entry (`workers.dev`, preview URL, route) → Worker → binding → data store holding sensitive data | `W-BND`, `W-CAP` |
| `WF-TOX-02` | Worker on workers.dev **and** on a route that has Access/WAF, so the controls can be bypassed | Track 1 network probes |
| `WF-TOX-03` | Worker with a preview URL → Hyperdrive bound to a production origin | `W-CAP-01` (Hyperdrive), wave 2 |
| `WF-TOX-04` | DNS-only record sharing the origin IP of a proxied host, with no Authenticated Origin Pulls or Tunnel | P2 collectors |
| `WF-TOX-05` | Tunnel public hostname with no Access app | P2 collectors |
| `WF-TOX-06` | route naming a missing script, or CNAME to a deprovisioned target (takeover) | corkscrew `CF.WRK.05` analogue |
| `WF-TOX-07` | token with Workers edit + no expiry + no IP filter → `can_deploy` → Worker holding prod bindings | P3 collectors |
| `WF-TOX-08` | DO class whose source builds SQL from request input → DO namespace bound by a publicly routed Worker | `D-DO` SQLi probes |
| `WF-TOX-09` | Dynamic Worker Loader host that grants user-generated code bindings beyond an allowlist | `W-DYN`, `AI-INJ` |

Graph rules run as SQLite `WITH RECURSIVE` queries inside ScanHub, with cycle guards and a depth cap of 6.

## 10. Research integration

- **ProbeResult as a source of findings.** `harness` posts `ProbeResult`s to ScanHub (`/ingest/probe`). A probe with verdict `accessible` and severity ≥ medium opens a `WF-PROBE-<test_id>` finding against the target ref.
- **Canary Workers.** A scheduled subset of the safe, read-only probes (`W-ENV`, `W-NET`, `W-BND` discovery) runs in the account. If an observed boundary changes, for example an egress that used to be blocked now succeeds, a finding opens. This turns the research into regression tests on the platform itself.
- **Rule provenance.** `wulf report --matrix` already maps rules to probes. The console shows the same matrix, linking each finding to its probe write-up.

## 11. Security of the platform itself

- **API token.** Read-only permission groups. It is stored in Secrets Store and bound to the Workflow Worker only. `wulf scan --print-scopes` (slice 4) prints exactly the groups a scan needs.
- **The console** sits behind an Access application. There is no public route, and `workers_dev = false` and `preview_urls = false` on every platform Worker. Rule `WF-BIND`/`WF-EGR` checks run against the platform's own config in CI.
- **Bundles.** Script content is analysed in memory. Only its SHA-256 and redacted evidence snippets of at most 200 characters, with secret patterns masked, are stored. A sentinel test asserts that no binding value appears in any persisted row.
- **Ingest.** `/ingest/probe` takes a separate token from the console's Access session. The harness and canaries cannot read findings.
- **Adversarial content.** Evidence such as script names, bundle strings and DNS comments is attacker-controllable and rendered as text only. The console must never interpret it, and any LLM-assisted triage added later treats it as untrusted data.

## 12. Phases

Each slice ends with the repo green (`pnpm -r typecheck`, all tests) and the CLI working as before.

### Slice 1: `@wulf/core` and a coverage-aware `wulf scan` (this branch)

- `packages/core`:
  - `Severity`, `Evidence`, `Finding` and `ProbeResult` as Effect Schemas.
  - `findingKey`.
  - Typed errors: `PermissionDenied`, `NotFound`, `RateLimited`, `ApiError`.
  - The `CfApi` service, plus `CfApiRest` (fetch, URL-encoded path segments, status → error mapping, retry on 429/5xx with exponential backoff) and `CfApi.fromPromises` (adapter for promise-shaped clients, so existing fakes keep working).
  - `collectAccount`, which returns an `AccountSnapshot` with per-operation `Coverage` and fetches script details with concurrency 4.
- `packages/cli`:
  - `Finding`, `Severity` and `Evidence` types come from core.
  - `wulf scan` collects through core and prints coverage gaps as notes; JSON output gains an additive `coverage` array.
  - `RestCfClient` stays exported (it's used by tests and the public API) but is no longer used by `scan`.
  - tsup bundles `@wulf/core`, and `effect` is added as a dependency.
- Tests:
  - core unit tests for error mapping, retry, coverage and the snapshot shape;
  - a type-level check that the core `ProbeResult` schema matches `@wulf/shared`'s interface;
  - the existing 36 CLI tests unchanged and passing;
  - a new CLI test showing a denied bindings read appears as a coverage note.
- **Exit:** `wulf scan` gives the same findings as before against the fakes, and a 403 now shows up as a coverage gap instead of a silent pass.
- **Result (2026-11-10): done.**
  - Tests: `@wulf/core` 20, `@wulf/cli` 41 (the original 36 unchanged, plus 5 new for coverage). All pass on Node 18 and current Node.
  - The `ProbeResult` compatibility check fails `tsc` if `@wulf/shared` drifts.
  - CI (`.github/workflows/cli.yml`) now typechecks and tests core too.
  - The CLI bundle grew from 137 KB to 146 KB, with `effect` external.
  - **Follow-up:** check `GET /accounts/{id}/workers/scripts/{name}/routes` against the OpenAPI spec. If it isn't a real endpoint, every script will report `routes: unavailable`, and route collection should move to zone routes plus custom domains in slice 4.

### Slice 2: the rule engine runs in workerd

- Split Node-only code (fs and path in `parsers/wrangler.ts`, `report/*`, the `_utils` file reads) away from the pure rule and AST code. Move the pure parts to `@wulf/analyze`.
- Prove that oxc-parser runs in a Worker (`oxc-parser` WASM build, or `@oxc-parser/wasm`), with a bundle-size budget of 3 MB gzipped for the analyzer Worker. If that fails, fall back to the codeshield container for AST analysis.
- **Exit:** a `wrangler dev` test Worker runs every account and source rule against a fixture snapshot, and its output matches the CLI byte for byte.
- **Parser proof of concept (2026-11-10): passed.** See `packages/analyze-poc/README.md`.
  - **How it works:** a wrangler `alias` swaps `oxc-parser` for a shim over `@oxc-parser/wasm@0.40.1`, the WASM build at the same version as the CLI's native parser. The CLI's parser, rules and report code run in workerd **unchanged**. The only CLI change is `parseWranglerText` split out of `parseWrangler`.
  - **Findings:** for all 7 CLI fixtures, the Worker's output under `wrangler dev` deep-equals `wulf audit --source --json`. That's 66 reference findings. The 5 supply-chain (`WF-SC-*`) findings are excluded because they read Dockerfile and package.json from disk; a Worker needs those passed in as files.
  - **AST:** identical between WASM and native across 272 files (1.5 MB: every package's source plus Effect's bundles), and over HTTP from workerd for every fixture source. The one exception is a label: the WASM build marks JavaScript `sourceType.variant` as `"jsx"`. Parse errors and every node are otherwise identical, and no rule reads that field.
  - **Size:** 347 KiB gzipped in total (WASM 275 KiB, JS 77 KiB), against the 3 MB budget.
  - **CPU:** WASM is 2.5–3× slower than native, about 55–62 ms for a 150–350 KB bundle in Node, with source files near 0 ms. A 356 KB bundle takes about 200 ms round trip in `wrangler dev`. That's fine on Workers Paid and in Workflow steps, but **large bundles exceed the Free plan's 10 ms CPU limit**.
  - **Dependency risk:** npm marks `@oxc-parser/wasm` as no longer supported. Current `oxc-parser` (0.158) has an official `oxc-parser/workerd` entry, but its AST appears to be ESTree-shaped, unlike 0.40's native shape (e.g. `StaticMemberExpression`) that the rules match on. Moving to it means adapting the AST helpers in `src/ast`, and the equivalence tests here are the safety net for that.
  - **Still to do for the slice:** move the pure code into `@wulf/analyze`. Have supply-chain rules take file text instead of reading disk. Run the account rules in workerd as well (the POC covers config and source rules). Put `analyze-poc`'s equivalence tests in CI.

### Slice 3: ScanHub and ScanWorkflow

- `@wulf/hub`: the Durable Object with the SQLite migrations from §7 and `begin/append/complete`; the Workflow with one step per collector chunk; the R2 export alarm.
- Findings lifecycle (open, resolved, suppressed). A partial scan never resolves anything.
- `wulf scan --push <hub-url>` sends a CLI scan to ScanHub.
- **Exit:** a cron scan of the research account produces the same findings as `wulf scan`, keeps their identity across two scans, and resolves a finding after the misconfiguration is fixed.

### Slice 4: exposure and data-store graph

- P1 collectors, the edges table filled in, dangling-binding detection, `WF-TOX-01..03` and `-06`.
- `wulf scan --print-scopes`.
- **Exit:** a seeded fixture account produces each TOX finding, and so does at least one real misconfiguration in the research account.

### Slice 5: research ingest and canaries

- `ProbeResult` moves into core's Schema, and `@wulf/shared` re-exports it as types only.
- `harness` posts to ScanHub. DuckDB (`cmd-analyze.ts`) is removed and replaced by `wulf report` queries against ScanHub.
- Canary Worker with a scheduled probe subset.
- **Must happen after the practicum results freeze.**

### Slice 6: console and deploy

- `@wulf/console`: findings, coverage, graph path view, rule ↔ probe matrix, behind Access.
- `@wulf/deploy`: an Alchemy v2 stack, so `pnpm deploy` stands up the whole platform in your own account.

### Slice 7 and later

P2–P4 collectors, zone baseline, Access and Tunnels, identity (`can_deploy`), Audit Log detections, ingesting Security Center, the AI surface, IaC-ownership findings (unmanaged objects, drift from declared Terraform/wrangler), and suggested fixes as PRs.

## 13. Risks and open questions

| Risk | Mitigation |
|---|---|
| oxc-parser in workerd: WASM size and loading | Slice 2 is a dedicated proof with a budget and a container fallback |
| Effect 4 bundle size in Workers | Measure in slice 2. Import from `effect/<Module>` paths and keep collectors tree-shakable |
| Workflow step limits and payload size | Chunk collectors (4 scripts/step). Batches carry no bundle content, only derived data |
| Cloudflare API rate limit (1,200 req / 5 min) | `Schedule`-based pacing in `CfApiRest`, retrying 429s with backoff, concurrency 4 |
| Some endpoints differ from what `wulf` assumes (e.g. per-script routes) | Coverage `unavailable` makes it visible. Verify each endpoint against the OpenAPI spec as collectors are added |
| Churn in practicum-cited code | Probe Workers are frozen. `shared` changes only in slice 5, after the freeze |
| Effect learning curve for contributors | Rules stay plain functions, so Effect is only needed in collectors and the hub |

**Open questions**

1. Should `@wulf/analyze` and `@wulf/core` be one package? Decide after slice 2 measures bundle sizes.
2. Should history in R2 be JSONL or Parquet? JSONL is the default. Revisit when queries over history become a real need. R2 SQL / Data Catalog is optional and only arrives with Parquet.
3. When open-sourcing, under what name, and should the platform live in this repo or a new one? The research repo stays academic, so a likely split is `workerwulf` (research) and a separate platform repo, with rules/probe IDs shared.
4. Should the platform's own token be minted per scan (short-lived, Vault-style) or stay a long-lived read-only token in Secrets Store?

## 14. Decisions

| Date | Decision |
|---|---|
| 2026-11-10 | TypeScript on **Effect 4** (not Rust). Rust only shows up as WASM modules (oxc). |
| 2026-11-10 | No DuckDB and no corkscrew dependency. Durable Object SQLite is the store and WAL, and R2 holds history. |
| 2026-11-10 | Probe Workers are frozen. Effect goes into `core`, `cli`, `hub`, `harness` and `console` only. |
| 2026-11-10 | Coverage is part of the data model: failures are never turned into empty values. |
| 2026-11-10 | One deployment per account. No multi-tenant SaaS. |
