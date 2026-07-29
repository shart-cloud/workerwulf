# Wave 5 — Workers Cache (`ctx.cache`) blast-radius probes (`W-WC-01…07`)

New probe family targeting **Workers Cache** —
<https://developers.cloudflare.com/workers/cache/> — the Worker-owned,
declarative **response** cache reached via `ctx.cache` /
`import cache from "cloudflare:workers"`. This is a **different feature** from the
legacy imperative Cache API (`caches.default` / `caches.open`) already covered by
`W-CACHE-01/02/03`; those stay as-is. All Wave 5 probes are tagged
`misconfig:cache`, carry a benign run-tagged `flag{w-wc-NN-…}` canary, and
exercise **one** behavior — no floods, no third-party targets. Delivery is pinned
to the researcher's own account and the probes' own cache namespace.

The AWS Lambda / Azure Functions / GCP Functions `comparison` block on every
probe records the novelty thesis: **none of the container-FaaS platforms expose a
per-Worker, edge-resident, tiered *response* cache with programmatic purge.** The
closest analogs (CloudFront + Lambda\@Edge, API Gateway caching, Cloud CDN) are
zone/distribution-owned and configured out-of-band, not code-owned inside the
function isolate. The bad patterns below therefore have no prior container-FaaS
research to inherit.

---

## Why this is a new surface, not more `W-CACHE`

| | Legacy Cache API (`W-CACHE-*`) | Workers Cache (`W-WC-*`) |
|---|---|---|
| API | `caches.default.put()/match()` imperative | `ctx.cache` declarative + `ctx.cache.purge()` |
| What is cached | whatever the Worker explicitly `put()`s | the Worker's **fetch response**, automatically |
| Key | the `Request` you pass | path + entrypoint + `ctx.props` + Worker version (**not** hostname, method, or custom auth headers) |
| Scope | per Worker script | per Worker + per entrypoint; **tiered** (network-wide upper tier) |
| Extras | none | request collapsing, tag/prefix/`purgeEverything` purge, `Vary` variants, heuristic freshness, `Set-Cookie`/`Authorization` auto-bypass |

The security-relevant behaviors that create the Wave 5 findings, all from the
docs:

- **Unkeyed auth footgun (documented):** *"If you authenticate callers through
  some mechanism other than `ctx.props` — for example, by reading a custom header
  your gateway Worker attaches — that input is **not** automatically part of the
  cache key."* → one caller can receive another's cached response (leak) or
  populate a shared entry (poison).
- **Tiered cache:** the first request for a key *anywhere* populates a network-wide
  upper tier that every lower tier consults on a miss — a single request's response
  is served globally without re-invoking the Worker.
- **Request collapsing:** simultaneous same-key requests are joined to one in-flight
  response stream; the Worker runs **once**.
- **Purge:** `ctx.cache.purge({tags|prefixes|purgeEverything})`, rate-limited by the
  zone plan; `purgeEverything` *"temporarily increases load on your Worker and any
  upstream services."*
- **Heuristic freshness / auto-bypass:** responses with no `Cache-Control` may be
  cached via RFC 9111 heuristics; `Set-Cookie` on the response and `Authorization`
  on the request auto-bypass — a bypass a naive Worker can defeat by normalizing
  those away.

---

## Architecture

### Deliberately-vulnerable cached entrypoint (`WcVictim`)

`W-WC-03/04/05/06/07` need a cached surface to attack, following the
intentionally-vulnerable-Durable-Object precedent. It lives as a **named export
`WcVictim`** on `wulf-worker` with **cache enabled on that entrypoint only** (via
the Wrangler `exports` map). The default `fetch` handler — the `/probe/*` router —
**stays uncached**, so the 60+ existing Track-1 probes keep their determinism
(threat-model **T4**). The victim carries only run-tagged `flag{}` canaries and a
module-global **execution counter** so a probe can tell a cache **hit** (Worker not
re-invoked, counter unchanged) from a **miss** (counter incremented).

The victim deliberately implements the documented anti-patterns, selectable by
path/header so one entrypoint backs all five attack probes:

- `/wc/reflect` — reflects an **unkeyed** request header/query into the cached body
  (poisoning source, `W-WC-03`).
- `/wc/whoami` — returns a per-identity `flag{}` secret, authenticating identity via
  an **unkeyed custom header** instead of `ctx.props` (leak source, `W-WC-04`).
- `/wc/sensitive` — returns per-user content with **no `Cache-Control`** (heuristic)
  and strips `Set-Cookie`/`Authorization` before responding (defeated auto-bypass,
  `W-WC-05`).
- shared: every response sets `Cache-Control` + a `Cache-Tag`, increments the exec
  counter, and echoes it — the oracle for `W-WC-06/07`.

> **Prerequisite:** per-entrypoint cache control requires **Wrangler ≥ 4.107.0**.
> Installed is 4.104.0 (worker pins `^4.94.0`); bump the `@wulf/worker` dev-dep to
> `^4.107.0`. The base `cache` block needs only 4.69 (already satisfied).

### Self-orchestrating loopback (no harness change)

The docs confirm the cache is *"shared across every way the Worker can be invoked,
including loopback `ctx.exports` calls."* So each attack probe runs the full
attacker→victim sequence **inside one `/probe/<ID>` invocation** via loopback
(`ctx.exports.WcVictim.fetch(...)`, or the existing `SVC_SELF` self service
binding), inspects `cf-cache-status` + body + the exec counter, and returns one
`ProbeResult`. This matches the self-contained `W-CACHE-01` model and needs **no
change to the harness** (`cmd-run` keeps sending a single GET).

**Known limit:** loopback stays within one PoP. `W-WC-06` (tiered / cross-PoP) and
`W-WC-07` (collapsing / concurrency-timed) therefore land as **`partial` with a
documented edge-only caveat** — the same class of limitation as the W-CAP-07 mTLS
CF-egress note and the local-dev timer-clamping constraint. The mechanism is still
exercised; only the multi-PoP amplification half is deferred to an external
multi-region driver.

---

## Probe roster

### W-WC-01 — Workers Cache surface introspection — informational

Detect `ctx.cache` and `import cache from "cloudflare:workers"`; enumerate available
methods (`purge`, tag/prefix/`purgeEverything` shapes); confirm the Worker's own
responses are actually being cached by reading `cf-cache-status` on a loopback to
`WcVictim`. Baseline capability map. Deploy-only (needs the edge cache layer);
locally → `blocked`.

Expected: `accessible`/`informational` with `cache_api_present:true`,
`response_cached:true`.

### W-WC-02 — Purge-driven DoS / cache eviction — accessible/high

Ordinary isolate code calls `ctx.cache.purge({purgeEverything:true})` (and tag /
prefix variants) — no per-call authz, no allowlist. The finding: **any** code in the
isolate, including injected/generated **Track-4** code, can evict the Worker's entire
cache, forcing every subsequent request back to the Worker/origin (load + CPU-billing
amplification) and, by exhausting the plan's shared purge rate-limit, **prevent
legitimate purges** so poisoned/stale content cannot be evicted. This is the
Workers-Cache instance of the threat model's unmitigated financial-DoS line (**T11**),
adjacent to `W-CAP-09`.

**Safeguard:** the probe purges **only the `WcVictim` entrypoint's own cache**
(entrypoint-scoped by the platform) with a single run-tagged call — it does not touch
production zone cache and issues no flood.

Expected: `accessible`/`high` with `purge_succeeded:true`,
`purge_everything_succeeded:true`, `exec_counter_reset` proven by a post-purge miss.

### W-WC-03 — Unkeyed-input cache poisoning — accessible/high (integrity)

Attacker loopback-seeds `/wc/reflect` with an attacker value in the **unkeyed** header;
victim loopback-fetches the **same keyed path** with a different identity and receives
the **attacker's content** with `cf-cache-status: HIT` and an unchanged exec counter
(served from cache, Worker not re-run). Proves a shared entry is poisoned by
unkeyed input.

Expected: `accessible`/`high` with `poisoned_content_served:true`,
`cache_status:"HIT"`, `worker_reexecuted:false`.

### W-WC-04 — Cross-caller response leak — accessible/critical (confidentiality)

Caller **A** (holding `flag{w-wc-04-…}`) loopback-seeds `/wc/whoami`; caller **B**,
different identity header, same keyed path, receives **A's canary** from cache. The
confidentiality direction of the same missing-`ctx.props` root cause. A control leg
puts identity into `ctx.props` and shows separate entries (isolation works when used
correctly) — strengthens the "misconfig, not platform bug" framing for disclosure.

Expected: `accessible`/`critical` with `cross_identity_leak:true`,
`leaked_canary_matched:true`, and `ctx_props_control_isolated:true`.

### W-WC-05 — Accidental caching of sensitive responses — accessible/high

`/wc/sensitive` returns per-user content with **no `Cache-Control`** (RFC 9111
heuristic freshness) and with `Set-Cookie`/`Authorization` normalized away, defeating
the auto-bypass. Probe shows a response that should be per-request is cached and
replayed to a second caller. Operator-misconfig angle (`misconfig:cache`).

Expected: `accessible`/`high` with `heuristic_cached:true`,
`autobypass_defeated:true`, `replayed_to_second_caller:true`.

### W-WC-06 — Tiered-cache global amplification — partial/medium (edge-only)

Demonstrate that one populated entry is served without re-invoking the Worker
(exec-counter proof) and record the tiered mechanism: a single request populates the
network-wide upper tier that every PoP consults. The **cross-PoP** amplification half
is edge-only and cannot be shown from one loopback invocation → recorded as a
documented caveat with the deferred external multi-region driver. Single-PoP
"served-from-cache, Worker-not-re-run" evidence is captured.

Expected: `partial`/`medium` with `served_without_worker:true`,
`tiered_crosspop:"deferred-edge-only"`.

### W-WC-07 — Request-collapsing victim-joining / concurrency oracle — partial→accessible/medium

Fire N concurrent same-key loopbacks; the exec counter shows the Worker ran **once**
(collapsing) while all N received the body — an attacker who triggers the in-flight
response has every concurrent victim joined to it. Also the **in-flight oracle**:
whether a key is currently being computed is observable. Timing-sensitive → the
local-dev timer-clamping constraint applies; deploy-verify required, and the
cross-PoP scope is noted as edge-only.

Expected: `partial`–`accessible`/`medium` with `worker_ran_once:true`,
`concurrent_joined:N`, `inflight_oracle:true`.

---

## Wire-up & deploy-verify

```bash
# 1. Bump wrangler for per-entrypoint cache control
pnpm --filter @wulf/worker add -D wrangler@^4.107.0

# 2. Uncomment the [cache] + [[exports]] stanzas in packages/worker/wrangler.toml
#    (cache enabled on the WcVictim entrypoint only; probe router stays uncached)

# 3. Deploy + run the family
pnpm --filter @wulf/worker deploy
cd packages/harness && pnpm start run --track worker --test W-WC-0X \
  --base-url https://wulf-worker.sharted.workers.dev
```

Deploy-verify status: **DEPLOY-VERIFIED 2026-07-29** (version
`4fd485f8-98ae-44ff-8cb7-d9a9499dcc30`). All seven probes ran live against
`wulf-worker.sharted.workers.dev`.

| Probe | Result | Severity | Evidence |
|---|---|---|---|
| W-WC-01 introspection | accessible | informational | `MISS`→`HIT`, identical nonce — cache live on `WcVictim`, router uncached |
| W-WC-02 purge DoS | accessible | high | `purgeEverything` from unprivileged isolate code evicted the entrypoint cache (`MISS` + fresh nonce after propagation) |
| W-WC-03 unkeyed poisoning | accessible | high | Victim received the attacker's `flag{}` despite sending its own header value |
| W-WC-04 cross-caller leak | **accessible** | **critical** | Caller `bob` received `flag{w-wc-04-secret-for-alice}` — identity header is not part of the cache key |
| W-WC-05 accidental caching | accessible | high | Heuristic freshness cached a per-user secret and replayed it to a second caller |
| W-WC-06 tiered amplification | partial | medium | Single-PoP served without re-invoking the Worker; cross-PoP amplification **refuted** (per-colo entries) |
| W-WC-07 request collapsing | accessible | medium | 8 concurrent requests → 1 execution; collapse doubles as an in-flight oracle; scope **bounded to one colo** |

The cross-PoP arms were added after the initial sweep and re-verified on version
`bd8f2395-a5a3-4cd1-9997-1cd1e67fe0b2` (raw: `packages/harness/results/w-wc-0*-wave5-xpop-bd8f2395.json`).

### Resolved open items

- **Wrangler syntax — RESOLVED.** Verified against `wrangler@4.108.0`'s
  `config-schema.json`. The syntax originally sketched here was wrong: `exports` is
  a **map keyed by export name**, and each entry **requires `type = "worker"`** — it
  is *not* an `[[exports]]` array with a `name` key. Correct form now in
  `wrangler.toml`; direction is enable-only-victim (top-level `enabled = false`,
  `[exports.WcVictim] cache.enabled = true`), plus `cross_version_cache = false`.
- **`purgeEverything` scope — RESOLVED, safe.** Per the docs, purges are "scoped to
  the Worker that owns the cache" and "further scoped to the entrypoint that called
  `purge()`"; "no zone-level purge … affects Workers Caching content." The
  `shart.cloud` zone cache is unreachable from W-WC-02. **Caveat:** purges share
  "the same rate-limiting system as Cloudflare's zone purge API", so W-WC-02 must
  not be loop-tested — a flood could starve legitimate zone purges.

### Corrections made during deploy-verify

- **W-WC-02 oracle was racy.** The post-purge re-read raced purge propagation and
  always reported `evicted: false` → `partial`. Confirmed the purge was real by
  re-running with a fixed `run_id` 25s apart (same key returned a fresh nonce), then
  added a 10s `PURGE_PROPAGATION_MS` wait before the re-read. Now `accessible`.
  The wait is not a measurement — no verdict derives from elapsed time — so the
  nonce oracle stays host-clock-independent.
- **W-WC-05 conflated two mechanisms.** It sent `Authorization` while trying to
  measure heuristic freshness; the edge decides that auto-bypass on the **inbound
  request**, so the response came back `BYPASS` and the heuristic half was never
  exercised (probe read `blocked`). Split into arm A (no `Authorization`, the
  heuristic test → `accessible`/high) and arm B (with it, as a control).
- **New defensive result from arm B:** the `Authorization` auto-bypass **held** even
  though the Worker stripped the header from the *response*. The bypass is decided
  inbound and **cannot be defeated by response-side normalization** — so the
  "defeated auto-bypass" half of the original W-WC-05 thesis is **refuted** for
  `Authorization`. Forwarding it is safe-by-default.
- `/wc/sensitive` was emitting `flag{w-wc-04-…}`; now emits `flag{w-wc-05-…}`.

## Closed open items (2026-07-29, version `bd8f2395`)

### The cross-PoP driver — `WcRegionDriver`

The cross-PoP half never needed an *external* driver. A Durable Object is the only
primitive that lets Worker code choose where it runs: `locationHint` pins a
newly-created object to a region, and a service-binding fetch issued from inside that
object dispatches in the object's own data center. `packages/worker/src/wc-region-driver.ts`
drives `SVC_WC_VICTIM` from objects pinned to `wnam` / `weur` / `apac`, and every
result carries the colo it actually ran in (read back from `/cdn-cgi/trace`) — hints
are best-effort, so a conclusion is only drawn from **confirmed-different** colos.
Observed placements across runs: DFW/AMS/KIX, DEN/MRS/SIN, LAX/CDG/HKG, SJC/LIS.

The object stores nothing; it exists only to be somewhere. A DO class still needs a
migration, hence `[[migrations]] tag = "v1"` in `wrangler.toml` — the first migration
on `wulf-worker`.

### W-WC-06 cross-PoP amplification — **REFUTED** (defensive result)

Remote colos did not serve the origin's `invocation_nonce`. Crucially they did not
merely miss: on a re-read 15s later each remote colo returned the nonce **it had
created itself**, as a `HIT`. Every data center holds its own entry for the same key,
which excludes propagation lag as the explanation — the failure mode a single-pass
probe could not have ruled out. Confirmed manually first (same `run_id` re-driven 45s
apart: DEN/MRS/SIN each `HIT` their own nonce), then encoded as the probe's own
`per-colo` verdict so it no longer rests on a hand-run.

This **bounds** rather than extends blast radius, and it downgrades the practical
reach of W-WC-03: a poisoned entry does not go global for free — an attacker must land
the poisoning in each data center whose traffic they want to affect. Scope of the
refutation: this account's cache configuration, `workers.dev`, this response shape.
The arm is kept as a regression: if Cloudflare's tiering behavior changes it flips to
`confirmed` and severity rises with it.

### W-WC-07 collapsing scope — **BOUNDED to one data center** (defensive result)

Simultaneous 8-way bursts from two confirmed-different colos (SJC, LIS) produced
disjoint nonce sets — 1 execution each, no shared execution. Victim-joining is
PoP-local, so the primitive is capped at one data center's concurrent traffic rather
than the network's.

### W-WC-05 `Set-Cookie` half — thesis **HOLDS** for `Set-Cookie`

Arm C re-attaches `Set-Cookie` to the response shape arm A already proved cacheable
(`?cookie=1` on `/wc/sensitive`), which is the only way to attribute a bypass to the
header rather than to the shape. Result: `BYPASS`, and the second caller received
their own secret. So the `Set-Cookie` auto-bypass is **real**, and it is the Worker's
response-side strip that destroys it — the original "defeated auto-bypass" thesis
holds here even though arm B refuted it for `Authorization`. The two halves of that
thesis have opposite answers: `Authorization` is decided inbound and cannot be
defeated response-side; `Set-Cookie` is response-side and a normalizing gateway
removes the protection. **Do not normalize `Set-Cookie` off per-user responses.**

## Open items

None. Wave 5 is complete.
