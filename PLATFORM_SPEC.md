# Workerwulf — Track 5: Workers for Platforms Multi-Tenant Boundary

> **Purpose:** Test the security boundaries of Cloudflare Workers for Platforms (WfP) — the production, multi-tenant evolution of the Dynamic Workers sandbox studied in Track 2. Where Track 2 asks "what can loaded code see?" within a single account, Track 5 asks the question a managed multi-tenant FaaS uniquely raises: **does WfP give a platform operator the isolation guarantees needed to safely run mutually-distrusting customers' code side by side?**
>
> **Prerequisite findings:** Track 1 (Workers runtime introspection) establishes the standard-Worker baseline that the *untrusted* user-Worker mode is differentially compared against. Track 2 (Dynamic Workers `globalOutbound`, RPC, capability scope) supplies the bypass techniques replayed here against a *platform-level* egress control. Track 4 (`RESULTS.md` §7) explicitly names a "runtime egress allowlist / `globalOutbound` interceptor at the platform level" as the #1 missing defense layer and the only thing that would have caught the residual `evade-b64-url` injection — the WfP **outbound Worker is that layer in production**, and P-OUT-03 retests the residual against it.
>
> **Convention:** Probe IDs use the `P-` prefix with subcategory (e.g. `P-OUT-03`). All probes follow the existing `ProbeResult` JSON output schema from `@wulf/shared`. New track value: `"platform"`.

---

## 1. The Trust-Model Inversion

This is the conceptual core of Track 5 and the framing for research question RQ4.

| | Track 2 / Track 4 (single-account sandbox) | Track 5 (Workers for Platforms) |
|---|---|---|
| **Defender** | The researcher's own parent Worker | A real platform operator: dispatch Worker + outbound Worker + custom limits |
| **Untrusted code** | A child the researcher loads and controls | A user Worker uploaded by an end customer |
| **Victim** | *(none — single tenant)* | **A sibling tenant in the same dispatch namespace** |
| **Question** | What can loaded code observe/reach? | Can a malicious tenant break the operator's isolation guarantees and reach a sibling tenant or the platform itself? |

The sibling tenant is the actor that does not exist anywhere in Tracks 1–4. Its presence is what makes Track 5 novel: it converts "sandbox introspection" into "multi-tenant isolation assurance," which is precisely the dimension Serverless Prey (single-function-per-account FaaS) never examined.

**RQ4 (proposed):** *When a platform operator runs untrusted, mutually-distrusting customer code in a single Workers for Platforms dispatch namespace, what can a malicious user Worker observe about, reach across to, or exfiltrate from (a) sibling tenants and (b) the platform's own control plane — and which platform controls (untrusted mode, outbound Workers, custom limits, trace Workers) actually constrain it?*

---

## 2. Platform Mechanics Under Test

Confirmed against current Cloudflare WfP documentation (2026-05). These are the exact surfaces the probes exercise.

### 2.1 Components

- **Dispatch namespace** — container holding all user Workers (e.g. `wulf-tenants`). User Workers run in **untrusted mode by default**.
- **Dynamic dispatch Worker** — the platform entry point. Routes by hostname/path/header, runs platform logic (auth, rate limiting), sets per-customer limits, sanitizes responses. Invokes user Workers via the dispatch-namespace binding.
- **User Worker** — customer code, deployed via the WfP API. The attacker-controlled component in this track.
- **Outbound Worker (optional)** — intercepts `fetch()` requests made by user Workers; used for egress control, request logging, and request modification (e.g. credential injection).
- **Trace Worker (optional)** — observability/detection surface.

### 2.2 The dispatch invocation (P-DISP, P-OUT, P-LIM hinge on this)

```js
// Inside the dynamic dispatch Worker:
const userWorker = env.DISPATCHER.get(
  workerName,
  {},
  {
    outbound: { customer_name: workerName, url: request.url }, // passed to outbound Worker
    limits: { cpuMs: 10, subRequests: 5 },                     // per-invocation governance
  },
);
return await userWorker.fetch(request);
// get() of a missing script throws an Error whose message starts with "Worker not found"
```

Key facts the probes rely on:

1. **Untrusted mode** (default; `trusted_workers = false` on the namespace): user Workers do **not** share the zone Cache API, and `request.cf` is **undefined**. → Differential targets for P-TEN-01 and P-DISP-03.
2. **Outbound Worker scope** is "**any `fetch()` requests from a user Worker**." The dispatcher's `outbound` object is readable in the outbound Worker via `env.<VAR>`. → P-OUT-04 (identity confusion), P-OUT-06 (does "any fetch()" actually mean *all* egress, or only `fetch`?).
3. **Custom limits throw on the user Worker immediately** when `cpuMs` or `subRequests` is exceeded. → P-LIM-01 baseline; P-LIM-03 tests amplification *around* the per-invocation budget.
4. **`Worker not found`** is a distinct, observable error string from `get()`. → P-DISP-02 enumeration oracle.

---

## 3. Architecture

```
                         Client request (tenant-prey.wulf.example / tenant-victim.wulf.example)
                                              │
                                              ▼
                    ┌─────────────────────────────────────────────────┐
                    │  Dynamic Dispatch Worker: wulf-dispatch           │
                    │  - routes by subdomain → script name              │
                    │  - get(name, {}, { outbound, limits })            │
                    │  - applies custom limits + outbound binding        │
                    └───────────────┬─────────────────────┬────────────┘
                                    │                     │
                  env.DISPATCHER.get("tenant-prey")   ...get("tenant-victim")
                                    │                     │
                                    ▼                     ▼
        ┌───────────────────────────────────┐  ┌──────────────────────────────┐
        │  User Worker: tenant-prey         │  │  User Worker: tenant-victim   │
        │  (ATTACKER — port of prey-worker  │  │  (VICTIM — holds canaries)    │
        │   + child-source probe library)   │  │  bindings: VICTIM_KV,         │
        │  untrusted mode                   │  │   VICTIM_DO, VICTIM_SECRET    │
        │  bindings: PREY_KV (own scope)    │  │  untrusted mode               │
        └───────────────┬───────────────────┘  └──────────────────────────────┘
                        │ fetch() to anything
                        ▼
        ┌───────────────────────────────────┐        ┌──────────────────────────┐
        │  Outbound Worker: wulf-outbound   │───────▶│  Callback Server          │
        │  - egress allowlist               │ allowed │  (callbackd on VPS)       │
        │  - logs {customer_name,url} to R2 │        │  + DNS authority          │
        │  - blocks non-allowlisted hosts   │        └──────────────────────────┘
        └───────────────────────────────────┘
                        ▲
                        │ (trace events)
        ┌───────────────────────────────────┐
        │  Trace Worker: wulf-trace         │  ← P-OBS detection-surface mapping
        └───────────────────────────────────┘
```

---

## 4. Infrastructure Requirements

### 4.1 New package: `packages/platform/`

Mirrors the `dynamic-parent` package layout. Contains the dispatch Worker, the probe library that runs *inside* `tenant-prey`, and the loader/helper conventions adapted to WfP.

```
packages/platform/
  src/
    dispatch.ts        # wulf-dispatch: routing + get(outbound, limits)
    outbound.ts        # wulf-outbound: egress allowlist + logging
    trace.ts           # wulf-trace: observability capture
    tenant-prey.ts     # attacker user Worker — entrypoint + probe runner
    tenant-victim.ts   # victim user Worker — canary holder
    probes/
      index.ts
      _helpers.ts
      p-disp-01.ts ... p-obs-02.ts
  wrangler.toml        # dispatch_namespace bindings, outbound binding, limits
  package.json
```

### 4.2 Cloudflare resources (Terraform-managed, add to `/infra`)

| Resource | Purpose |
|----------|---------|
| `cloudflare_workers_for_platforms_dispatch_namespace` `wulf-tenants` | Holds user Workers. `trusted_workers = false` (default) for the primary run; a second `wulf-tenants-trusted` namespace with `trusted_workers = true` for the differential in P-TEN-01 / P-DISP-03. |
| Worker `wulf-dispatch` | Dynamic dispatch Worker, `dispatch_namespace` binding `DISPATCHER`. |
| Worker `wulf-outbound` | Outbound Worker bound to the namespace; egress allowlist + R2 logging. |
| Worker `wulf-trace` | Trace Worker attached to the namespace. |
| User Worker `tenant-prey` | Uploaded via WfP API to `wulf-tenants`. Tagged `role:attacker`. |
| User Worker `tenant-victim` | Uploaded via WfP API. Bindings `VICTIM_KV`, `VICTIM_DO`, `VICTIM_SECRET`. Tagged `role:victim`. Seeded with canaries. |
| R2 bucket `wulf-outbound-log` | Outbound Worker egress audit log. |

### 4.3 User Worker deployment

User Workers are not deployed by `wrangler deploy` in the normal sense; they are uploaded into the namespace via the API (or `wrangler deploy --dispatch-namespace wulf-tenants`):

```
PUT /accounts/{account_id}/workers/dispatch/namespaces/wulf-tenants/scripts/tenant-prey
PUT /accounts/{account_id}/workers/dispatch/namespaces/wulf-tenants/scripts/tenant-victim
```

Extend `scripts/seed.sh` with a `seed-platform` target that uploads both tenants, applies tags, and seeds `tenant-victim`'s canaries:

```bash
# tenant-victim canaries
wrangler kv key put --namespace-id $VICTIM_KV_ID "secret-doc" 'flag{p-ten-03-kv-canary}'
wrangler d1 execute victim-d1 --command "INSERT INTO secrets VALUES (1,'flag{p-ten-03-d1-canary}')"
# tenant-victim DO seeded with flag{p-ten-04-do-canary} on first /init
```

### 4.4 Harness extensions

- `--track platform` to run the `P-` probes.
- Probe invocation hits `tenant-prey` *through* `wulf-dispatch` (i.e. via the customer-facing hostname) so the full dispatch → user Worker → outbound path is exercised, not a direct call.
- `--namespace trusted|untrusted` flag to run the differential probes against both namespace trust modes.
- Outbound-log polling: after each P-OUT probe, query `wulf-outbound-log` (R2) and the callback server to confirm whether egress was allowed, blocked, or unseen.
- Tag-scoped runs: `--tag role:attacker`.

---

## 5. Probes

### Subcategory P-DISP — Dispatch & Namespace Boundary

#### P-DISP-01: Dispatch Binding Reachability from a User Worker

**Description:** Determine whether a user Worker's `env` contains any dispatch-namespace binding (or any handle) that would let it invoke sibling Workers directly, bypassing the dispatch Worker's routing/authz.

**Method:** Inside `tenant-prey`, enumerate `env` (reuse the Track 1 `W-ENV-02` / `D-CAP-02` reflection walk). For every binding, typeof-check and probe for a `.get(name)` method shaped like a dispatcher. Attempt `env.<candidate>.get("tenant-victim")`.

**Expected output:**
```json
{
  "test_id": "P-DISP-01",
  "track": "platform",
  "user_worker_env_keys": ["PREY_KV"],
  "dispatcher_binding_present": false,
  "dispatcher_get_callable": false,
  "result": "blocked",
  "severity": "informational",
  "note": "User Worker env contains only operator-provisioned bindings; no dispatch-namespace handle is exposed to customer code"
}
```

**Why it matters:** If a user Worker could see a `DISPATCHER` binding, the entire routing/authz layer the platform implements in the dispatch Worker is bypassable. This is the single most consequential capability-leak in the model.

---

#### P-DISP-02: Sibling-Script Enumeration Oracle

**Description:** The dispatch Worker's `get()` throws `Worker not found` for missing scripts. Test whether a malicious tenant — *if* it ever obtains a dispatcher handle (P-DISP-01 positive), or via the dispatch Worker's externally-observable behavior — can distinguish existent from non-existent sibling script names via error text or timing.

**Method:** Two angles. (a) External: send requests to `<guess>.wulf.example` for a dictionary of likely tenant names and classify responses (404 vs 500 vs 200, latency distribution). (b) Internal (only if P-DISP-01 is positive): call `get(existing)` vs `get(nonexistent)` and compare thrown error string and timing.

**Expected output:**
```json
{
  "test_id": "P-DISP-02",
  "track": "platform",
  "names_probed": 200,
  "external_status_oracle": { "existing": 200, "missing": 404, "distinguishable": true },
  "internal_error_oracle": { "tested": false, "reason": "no dispatcher handle in user env" },
  "timing_oracle_ms_delta": 1.4,
  "result": "partial",
  "severity": "low",
  "note": "Tenant existence is inferable from the operator's own 404/200 routing, not from a namespace-level leak. Mitigation is a dispatch-Worker concern (uniform responses)."
}
```

**Why it matters:** Tenant enumeration is reconnaissance for targeted cross-tenant attacks. It also separates *platform-implementation* leakage (the operator's routing choices) from *platform-primitive* leakage (the namespace itself), which matters for the disclosure decision.

---

#### P-DISP-03: Namespace / Account Metadata Disclosure (Untrusted-Mode Differential)

**Description:** Determine what a user Worker can learn about its own deployment context — namespace name, account ID, colo, platform identity — and confirm the documented untrusted-mode property that `request.cf` is undefined.

**Method:** Inside `tenant-prey`: read `request.cf` (expect `undefined` in untrusted mode), walk `globalThis`, the `Cloudflare` global (reuse `W-OBJ-01`), `navigator`, and any `env` strings for account/namespace identifiers. Run against both `wulf-tenants` (untrusted) and `wulf-tenants-trusted` (trusted) for the differential.

**Expected output:**
```json
{
  "test_id": "P-DISP-03",
  "track": "platform",
  "untrusted": { "request_cf": null, "cf_available": false },
  "trusted":   { "request_cf": "present", "cf_available": true },
  "account_id_discoverable": false,
  "namespace_name_discoverable": false,
  "result": "blocked",
  "severity": "informational",
  "comparison": { "aws_lambda": "context object exposes account id, function arn, region" },
  "note": "Untrusted mode strips request.cf as documented; standard-Worker baseline (Track 1) has it"
}
```

**Why it matters:** Directly validates a documented isolation control and produces a clean Track-1-vs-Track-5 before/after. The Lambda comparison column (context/ARN exposure) writes itself.

---

### Subcategory P-OUT — Outbound Worker Egress Control

#### P-OUT-01: Outbound Interception Baseline

**Description:** Confirm the outbound Worker actually intercepts user-Worker `fetch()` and that the allowlist blocks a non-allowlisted host while permitting an allowlisted one.

**Method:** `tenant-prey` issues `fetch()` to (a) an allowlisted host and (b) the callback server (non-allowlisted). The outbound Worker logs both and blocks (b). Harness confirms via callback server + R2 log. Analog of `D-NET-01`.

**Expected output:**
```json
{
  "test_id": "P-OUT-01",
  "track": "platform",
  "allowlisted_fetch": { "reachable": true, "intercepted": true },
  "blocked_fetch": { "reachable": false, "intercepted": true, "callback_received": false },
  "result": "blocked",
  "severity": "informational",
  "note": "Outbound Worker mediates user fetch() and enforces the allowlist"
}
```

---

#### P-OUT-03: Residual Injection Replay Against Production Egress (headline probe)

**Description:** Replay the Track 4 residual `evade-b64-url` — the base64-obfuscated callback URL that survived LlamaFirewall + WULF gating because static analysis cannot decode `atob()` chains — against a **real outbound-Worker allowlist**. The hypothesis from `RESULTS.md` §7 #1: a runtime egress allowlist catches the exfil *regardless of how the URL was obfuscated in source*, because enforcement happens on the resolved request, not the source string.

**Method:** Deploy into `tenant-prey` the exact generated artifact AI-INJ-14 produced for `evade-b64-url` (`await fetch(atob("..."))` resolving to the callback host). Invoke through the dispatch path with the outbound allowlist active. Confirm whether the callback fires.

**Expected output:**
```json
{
  "test_id": "P-OUT-03",
  "track": "platform",
  "payload": "evade-b64-url",
  "source_obfuscation": "base64_atob_fetch",
  "static_analysis_would_catch": false,
  "outbound_allowlist_active": true,
  "resolved_fetch_host": "cb.<redacted>",
  "egress_blocked_by_outbound": true,
  "callback_received": false,
  "result": "blocked",
  "severity": "informational",
  "note": "Confirms RESULTS.md §7 hypothesis: runtime egress enforcement defeats source-level obfuscation that defeated scanner-based gating. The 1/15 residual is closed by a platform-level allowlist."
}
```

**Why it matters:** This is the empirical payoff that ties Track 4 and Track 5 together: it demonstrates that the defense layer your scanner study identified as missing is exactly the layer WfP provides, and measures whether it actually closes the gap. Strong paper figure.

---

#### P-OUT-04: Outbound Identity / Parameter Confusion

**Description:** The dispatcher passes `outbound: { customer_name, url }` to the outbound Worker as trusted tenant context. Test whether the user Worker can influence or spoof that context — e.g. by manipulating the request URL, headers, or fetch arguments such that the outbound Worker attributes egress to the wrong tenant or applies the wrong policy.

**Method:** `tenant-prey` makes fetches with crafted `Host`/URL/headers designed to confuse any outbound-Worker logic that derives identity or policy from the request rather than from the dispatcher-set binding. Compare what the outbound Worker logs as `customer_name` vs the true caller. Analog of `W-SVC-02` header spoofing.

**Expected output:**
```json
{
  "test_id": "P-OUT-04",
  "track": "platform",
  "true_customer": "tenant-prey",
  "spoof_vectors": ["host_header", "url_authority", "x-forwarded-for"],
  "outbound_attributed_customer": "tenant-prey",
  "policy_confusion_achieved": false,
  "result": "blocked",
  "severity": "medium",
  "note": "customer_name comes from the dispatcher binding (env), not request-derived data, so attribution held. Probes whether operators who key policy off request fields are exploitable."
}
```

**Why it matters:** Many real platforms will (incorrectly) key egress policy off request-derived fields rather than the dispatcher-set `outbound` binding. This probe documents the safe vs unsafe pattern.

---

#### P-OUT-05: Exfiltration Through Channels the Outbound Worker Does Not Mediate

**Description:** The outbound Worker mediates `fetch()`. Test exfil paths that are *not* user-Worker `fetch()`: the dispatch return value (response body the dispatch Worker relays to the client), error messages/stack traces, and response timing. Direct WfP analogs of `D-NET-03/04/05`.

**Method:** `tenant-prey` reads a canary it legitimately holds (`PREY_KV`) and attempts to return it (a) in the response body, (b) embedded in a thrown error the dispatch Worker may relay (note the dispatch template's `return new Response(e.message, {status:500})` pattern), (c) modulated into response latency. Measure what reaches the client without touching `fetch()`.

**Expected output:**
```json
{
  "test_id": "P-OUT-05",
  "track": "platform",
  "channels": {
    "response_body": { "exfil_possible": true, "note": "outbound Worker never sees this" },
    "error_message_relay": { "exfil_possible": true, "note": "dispatch template relays e.message verbatim" },
    "timing": { "exfil_possible": true, "bandwidth_bps": "low" }
  },
  "result": "accessible",
  "severity": "medium",
  "comparison": {},
  "note": "Egress control scoped to fetch() does not constrain response-path or error-path exfil. Operators must sanitize responses (a documented dispatch-Worker responsibility) — this probe shows why."
}
```

**Why it matters:** "Egress control" is commonly assumed to mean "data can't leave." This probe shows it means "*fetch()* is mediated," and that the response/error path is a parallel channel the operator must independently sanitize. Mirrors the D-NET-03 finding that motivated AI-INJ-03.

---

#### P-OUT-06: Egress Coverage Gaps — Beyond `fetch()`

**Description:** The documentation says the outbound Worker intercepts "any `fetch()` requests." Test whether non-`fetch` egress primitives are likewise mediated, blocked, or available at all: DNS resolution side effects, `WebSocket`, and raw TCP via `connect()` (Cloudflare Sockets API).

**Method:** From `tenant-prey`, attempt (a) `new WebSocket(...)` to the callback WS endpoint, (b) `connect()` TCP socket to the callback TCP listener, (c) DNS-observable lookups. For each, record availability and whether the outbound Worker saw/blocked it. Analogs of `D-NET-02/06`.

**Expected output:**
```json
{
  "test_id": "P-OUT-06",
  "track": "platform",
  "websocket": { "available": false, "intercepted_by_outbound": "n/a" },
  "tcp_connect": { "available": false, "error": "...", "intercepted_by_outbound": "n/a" },
  "dns_side_channel": { "observable": false },
  "result": "blocked",
  "severity": "informational",
  "note": "Documents whether 'any fetch()' is the complete egress surface or whether other primitives exist outside outbound-Worker mediation"
}
```

**Why it matters:** If any egress primitive exists that the outbound Worker does *not* see, the allowlist (and P-OUT-03's positive result) has a hole. This is the probe that would, if positive, become a responsible-disclosure item.

---

### Subcategory P-TEN — Cross-Tenant Isolation (novel multi-tenant findings)

#### P-TEN-01: Cross-Tenant Cache Visibility (Untrusted-Mode Differential)

**Description:** Validate the documented property that untrusted user Workers never share the zone Cache API. Two tenants attempt to use `caches.default` (and a named cache) as a shared channel.

**Method:** `tenant-victim` writes a marker to `caches.default` under a known key; `tenant-prey` attempts to read it. Repeat with `caches.open("shared")`. Run against untrusted and trusted namespaces. Extends `W-CACHE-02` to the cross-tenant case.

**Expected output:**
```json
{
  "test_id": "P-TEN-01",
  "track": "platform",
  "untrusted": { "cross_tenant_default_cache_read": false, "cross_tenant_named_cache_read": false },
  "trusted":   { "cross_tenant_default_cache_read": true, "note": "trusted mode shares zone cache — operators must not enable for mutually-distrusting tenants" },
  "result": "blocked",
  "severity": "informational",
  "note": "Confirms untrusted-mode cache isolation; documents trusted-mode as a footgun for multi-tenant operators"
}
```

**Why it matters:** Turns a documented sentence into measured evidence, and surfaces `trusted_workers = true` as a concrete misconfiguration risk for operators who flip it for performance without understanding the cache-sharing consequence.

---

#### P-TEN-02: Co-Tenancy / Isolate-Sharing Detection

**Description:** Determine whether two user Workers in the same namespace ever share a V8 isolate (which would make module-scope state a cross-tenant channel, à la the W-RUN series).

**Method:** Both tenants set a unique module-scope marker on load and expose it. Drive sustained interleaved traffic to both via the dispatch path; each checks whether the *other's* marker ever appears in its own global/module scope. Reuse the `W-RUN-01` persistence harness mode.

**Expected output:**
```json
{
  "test_id": "P-TEN-02",
  "track": "platform",
  "samples": 2000,
  "foreign_marker_observed": false,
  "shared_isolate_detected": false,
  "result": "blocked",
  "severity": "informational",
  "note": "No evidence of isolate sharing across tenants under load. A positive result here is a platform-level isolation break."
}
```

**Why it matters:** This is the deepest isolation claim WfP makes. A negative result is strong reassurance; a positive result is a critical, account-crossing vulnerability and an immediate disclosure item (see §8). **Restricted to the two self-owned tenants only.**

---

#### P-TEN-03: Cross-Tenant Binding Access

**Description:** Test whether `tenant-prey` can reach `tenant-victim`'s operator-provisioned bindings (KV/D1/R2) by guessing namespace IDs/names or by probing its own `env` for handles outside its scope. Analog of `D-CAP-02` + `W-BND-04`, multi-tenant.

**Method:** `tenant-prey` enumerates its `env`, attempts to construct/guess references to `VICTIM_KV`/`VICTIM_DO`/`VICTIM_*`, and attempts reads. The seeded canaries (`flag{p-ten-03-*}`) are the success indicators.

**Expected output:**
```json
{
  "test_id": "P-TEN-03",
  "track": "platform",
  "prey_env_keys": ["PREY_KV"],
  "victim_binding_guess_attempts": ["VICTIM_KV", "VICTIM_DO", "VICTIM_SECRET"],
  "victim_canary_read": false,
  "canaries_targeted": ["flag{p-ten-03-kv-canary}", "flag{p-ten-03-d1-canary}"],
  "result": "blocked",
  "severity": "critical",
  "note": "Bindings are per-Worker; a tenant cannot name/construct another tenant's binding. Positive result = critical cross-tenant data breach."
}
```

**Why it matters:** This is the cross-tenant data-breach question in its most direct form. Severity `critical` because a positive result is customer-data exposure across a trust boundary.

---

#### P-TEN-04: Cross-Tenant Durable Object Reach

**Description:** Test whether a user Worker can reach a *sibling tenant's* Durable Object by name/ID, composing the DO-DYN-03 cross-object finding with the multi-tenant boundary.

**Method:** `tenant-prey` attempts `idFromName("...")` / `idFromString("...")` against any DO namespace it can reference, targeting `tenant-victim`'s DO and its `flag{p-ten-04-do-canary}`. Confirm whether a DO binding to the victim's class is even constructible from prey's scope.

**Expected output:**
```json
{
  "test_id": "P-TEN-04",
  "track": "platform",
  "victim_do_binding_reachable": false,
  "id_construction_possible": false,
  "do_canary_read": false,
  "result": "blocked",
  "severity": "critical",
  "note": "Without a binding to the victim's DO class in prey's env, the namespace is unaddressable from prey"
}
```

---

### Subcategory P-CAP — Platform Capability & Secret Exposure

#### P-CAP-01: Operator Binding/Secret Bleed Into User `env`

**Description:** Determine whether the platform accidentally injects any of its *own* control-plane bindings or secrets into a user Worker's `env` (the dispatch namespace binding, outbound config/credentials, account API tokens, trace destinations). The WfP analog of `D-CAP-02`.

**Method:** Full `env` enumeration in `tenant-prey`, classifying each binding as expected-customer-scope vs suspicious-operator-scope. Specifically probe for anything dispatcher-, outbound-, or trace-shaped.

**Expected output:**
```json
{
  "test_id": "P-CAP-01",
  "track": "platform",
  "env_keys": ["PREY_KV"],
  "operator_bindings_leaked": [],
  "secrets_leaked": [],
  "result": "blocked",
  "severity": "critical",
  "note": "Only customer-scoped bindings present. Operator control-plane bindings absent from user env as expected."
}
```

---

#### P-CAP-03: Outbound-Worker Injected-Credential Exposure

**Description:** Outbound Workers commonly inject auth (e.g. mint a JWT, add an API key) on allowlisted requests. Test whether the *user Worker* can observe those injected credentials — i.e. does the credential get added in the outbound Worker (invisible to the user Worker) or anywhere the user Worker can read it back.

**Method:** Configure `wulf-outbound` to add an `Authorization` header to allowlisted fetches. `tenant-prey` fetches an allowlisted endpoint that echoes received headers (callback server `/relay`-style) and inspects whether the injected credential is visible in the response it gets back.

**Expected output:**
```json
{
  "test_id": "P-CAP-03",
  "track": "platform",
  "outbound_injects_header": "Authorization",
  "credential_visible_to_user_worker_via_echo": true,
  "result": "accessible",
  "severity": "high",
  "note": "If the allowlisted upstream reflects request headers, the user Worker can read back the operator-injected credential. Operators should inject only to non-reflecting upstreams / scope credentials per-tenant."
}
```

**Why it matters:** A subtle, realistic failure mode: credential injection assumes the user Worker can't see the credential, but an attacker-controlled-or-reflecting upstream defeats that assumption. Documents the safe pattern.

---

### Subcategory P-LIM — Custom Limits & Resource Governance

#### P-LIM-01: Custom-Limit Enforcement Baseline

**Description:** Confirm that `limits: { cpuMs, subRequests }` set on `get()` actually terminate the user Worker as documented.

**Method:** Dispatch `tenant-prey` with `{ cpuMs: 10, subRequests: 5 }`. Prey runs a tight compute loop (exceed cpuMs) and a subrequest fan-out (exceed subRequests). Capture the thrown exception and what the client receives. Analog of `AI-INJ-06` / `W-ERR-04`.

**Expected output:**
```json
{
  "test_id": "P-LIM-01",
  "track": "platform",
  "cpu_limit_ms": 10,
  "cpu_limit_enforced": true,
  "subrequest_limit": 5,
  "subrequest_limit_enforced": true,
  "exception_surfaced_to_dispatch": true,
  "result": "blocked",
  "severity": "informational"
}
```

---

#### P-LIM-03: Budget Amplification / Escape

**Description:** Custom limits are *per-invocation*. Test whether a user Worker can perform work *outside* that budget: scheduling DO alarms, enqueuing Queue messages, or (if P-DISP-01 were positive) dispatching further Workers — the WfP analog of the AI-INJ-06 Payload D fork-bomb question.

**Method:** Within a tightly-limited invocation, `tenant-prey` attempts to (a) `ctx.storage.setAlarm()` on any DO it can reach, (b) enqueue Queue messages, (c) chain dispatches. Measure whether deferred/parallel work executes off the per-invocation budget.

**Expected output:**
```json
{
  "test_id": "P-LIM-03",
  "track": "platform",
  "alarm_scheduling_available": false,
  "queue_enqueue_available": false,
  "secondary_dispatch_available": false,
  "off_budget_work_achieved": false,
  "result": "blocked",
  "severity": "medium",
  "note": "Whether per-invocation limits bound total tenant resource consumption, or only single-invocation consumption"
}
```

**Why it matters:** Per-invocation limits are a billing/abuse control. If a tenant can fan work out to alarms/queues/dispatches, the operator's cost-control assumption breaks even though each individual invocation is compliant.

---

### Subcategory P-OBS — Observability & Detection Surface (defender view)

#### P-OBS-01: Trace Worker Capture Completeness

**Description:** Map what the platform's trace Worker actually receives from a misbehaving user Worker: exceptions, `console` output, request/response metadata, outbound attempts, limit-termination events.

**Method:** `tenant-prey` performs a representative set of malicious-ish actions (blocked egress attempt, thrown error with marker, limit overrun, canary read). The trace Worker logs everything; the harness diffs what was captured vs what prey did. Mirrors `W-MON` / `DO-MON`.

**Expected output:**
```json
{
  "test_id": "P-OBS-01",
  "track": "platform",
  "events_emitted_by_prey": ["blocked_egress","thrown_error","cpu_limit_hit","canary_read"],
  "events_captured_by_trace": ["blocked_egress","thrown_error","cpu_limit_hit"],
  "tenant_attribution_present": true,
  "attribution_fields": ["scriptName","dispatchNamespace","tag"],
  "result": "informational",
  "severity": "informational",
  "note": "Trace Worker attributes events to the tenant; a pure in-memory canary read with no egress/error/log leaves no trace"
}
```

---

#### P-OBS-02: Trace Evasion

**Description:** Test whether a user Worker can perform sensitive actions invisibly to the trace Worker — swallow exceptions, avoid `console`, keep everything in-memory.

**Method:** `tenant-prey` reads a canary and exfils it via the response body (P-OUT-05 channel) while throwing nothing and logging nothing. Check whether the trace Worker recorded anything attributable.

**Expected output:**
```json
{
  "test_id": "P-OBS-02",
  "track": "platform",
  "silent_exfil_performed": true,
  "trace_recorded_anything": false,
  "result": "accessible",
  "severity": "medium",
  "note": "Response-path exfil with no error/log/egress is invisible to trace-based detection — reinforces P-OUT-05's response-sanitization recommendation"
}
```

---

## 6. Analysis Framework

### Scoring

Each probe yields a `ProbeResult` with `result ∈ {accessible, blocked, partial, error, informational}` and a `severity`. Track-5-specific roll-ups:

- **Cross-tenant isolation score** — fraction of P-TEN probes returning `blocked` (target: 100%; any `accessible` is critical).
- **Egress containment score** — fraction of egress channels (P-OUT-01/05/06) the outbound Worker actually mediates.
- **Residual closure** — does P-OUT-03 close the Track-4 `evade-b64-url` residual? (binary, headline).
- **Operator footgun catalogue** — configurations that flip a `blocked` to `accessible` (e.g. `trusted_workers = true` in P-TEN-01; request-derived policy in P-OUT-04; reflecting upstream in P-CAP-03).

### Comparison matrix addition

Add a **"CF Workers for Platforms (user Worker, untrusted)"** column to the §5.3 matrix in `PRD.md`:

| Dimension | … | CF Dynamic Workers | **CF WfP user Worker** |
|-----------|---|--------------------|------------------------|
| Execution model | | V8 isolate (sandboxed) | V8 isolate, untrusted mode |
| Cross-tenant cache | | n/a | isolated (untrusted) / shared (trusted) |
| `request.cf` | | present | **undefined** |
| Egress control | | `globalOutbound` (self-set) | **outbound Worker (operator-set)** |
| Per-invocation limits | | none built-in | **`cpuMs` / `subRequests`** |
| Sibling-tenant reach | | n/a | *(P-TEN result)* |

---

## 7. Implementation Notes

### Probe naming

| Prefix | Subcategory |
|--------|-------------|
| `P-DISP-` | Dispatch & namespace boundary |
| `P-OUT-` | Outbound Worker egress control |
| `P-TEN-` | Cross-tenant isolation |
| `P-CAP-` | Platform capability / secret exposure |
| `P-LIM-` | Custom limits / resource governance |
| `P-OBS-` | Observability / detection surface |

### `@wulf/shared` change

```ts
export type Track = "worker" | "dynamic" | "durable" | "ai" | "platform";
```

### Harness changes

- `--track platform`; route probe invocation through the dispatch hostname (full path), not a direct user-Worker call.
- `--namespace trusted|untrusted` for the differential probes (P-DISP-03, P-TEN-01).
- Post-probe outbound-log + callback poll to classify egress as allowed/blocked/unseen.
- `W-RUN`-style sequential mode reused by P-TEN-02 (sustained interleaved traffic).

### Deployment dependencies

- P-TEN-* require **both** tenants deployed and `tenant-victim` seeded.
- P-OUT-03 requires importing the AI-INJ-14 `evade-b64-url` generated artifact verbatim.
- P-OBS-* require `wulf-trace` attached to the namespace.
- The trusted/untrusted differential requires a second namespace `wulf-tenants-trusted`.

---

## 8. Ethical Considerations & Responsible Disclosure

Consistent with `PRD.md` §6, with one tightened rule specific to multi-tenancy:

- All tenants are **self-owned**. `tenant-prey` and `tenant-victim` are both the researcher's own user Workers in the researcher's own dispatch namespace. No probe targets any other Cloudflare customer's Worker, namespace, or account.
- **P-TEN-02, P-TEN-03, P-TEN-04, and P-OUT-06 are the account-crossing-sensitive probes.** They must only ever exercise the boundary between the two self-owned tenants. If any of them produces a positive result that implies reach across *Cloudflare account / namespace ownership boundaries* (i.e. a genuine platform isolation break rather than a within-account observation), testing stops and the finding goes to Cloudflare's security team via responsible disclosure **before** any publication — same standard as the Track 1–2 isolate-escape clause.
- Canary values are inert flags (`flag{p-ten-*}`) with no real secret content.
- The published tooling introspects the operator's *own* platform for self-assessment; it does not enable attacks against third-party platforms.

---

## 9. Priority Order

1. **P-DISP-01** — does customer code get a dispatcher handle? Single most consequential capability question; gates the severity of everything else.
2. **P-OUT-01** — egress baseline; validates the outbound rig end-to-end.
3. **P-OUT-03** — residual replay; the headline Track-4↔Track-5 result.
4. **P-TEN-03 / P-TEN-01** — cross-tenant data + cache; the novel multi-tenant findings.
5. **P-CAP-01** — operator binding bleed; critical and quick.
6. **P-OUT-05** — response/error-path exfil; reframes "egress control."
7. **P-TEN-02** — isolate-sharing; deepest isolation claim, needs sustained-traffic harness.
8. **P-LIM-01 / P-LIM-03** — limit enforcement and amplification.
9. **P-OUT-06** — egress coverage gaps beyond fetch().
10. **P-DISP-03 / P-DISP-02** — metadata disclosure + enumeration oracle.
11. **P-CAP-03 / P-OUT-04** — credential reflection + identity confusion (operator footguns).
12. **P-OBS-01 / P-OBS-02** — detection surface and evasion, run last.
