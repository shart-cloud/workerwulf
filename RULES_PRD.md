# Workerwulf — Wulf Rules PRD (Security Smell & Abuse-Pattern Corpus)

> **Status:** Draft v0.1 — planning artifact, not a finished ruleset.
> **Author:** Jared Gore
> **Context:** ISE 5901 (SANS MSISE). Backing for the `@wulf/codeshield` / `@wulf/llamafirewall` static layer and the harness probe suite.
> **Last updated:** 2026-05-29
>
> **What this is.** A research backlog disguised as a ruleset. Every entry is a *security* smell or abuse pattern on the Cloudflare developer platform (Workers, Dynamic Workers, Durable Objects, Workers for Platforms). Entries are organized by family. Within each family there are three kinds of entry:
>
> 1. **Rules** — patterns concrete enough to encode as an opengrep/semgrep rule or a config-lint check *today*.
> 2. **Probe-only findings** — exploitable platform behavior with no code to grep; only the harness can establish them.
> 3. **Open threads (parking lot)** — patterns that smell exploitable but aren't yet a rule or a probe, each tagged with an exploitability-confidence estimate so future-us can triage which branches are worth standing up infrastructure for.
>
> **Operating model.** This is an open corpus. Over the next 6–8 months the harness fills it with data; we then harvest the one or few findings that are most exploitable / easiest to find in the wild and write *those* up. The PRD's job is to capture generativity (every confirmed pattern tends to fork into two or three more) without obligating us to chase every fork before the paper ships. The parking lot is where forks live until they earn a probe.

---

## 1. Scope: security-only

We deliberately exclude correctness, performance, cost, and ergonomics guidance from Cloudflare's best-practices docs. Those are real and good advice, but they are not Wulf's contribution, and including them would dilute the security signal and inflate false positives. The single inclusion test for any entry:

> **Can we articulate a concrete attacker gain when this pattern is present?** If not, it is out of scope (see §9, Non-Goals).

A corollary discipline carried from the rest of Workerwulf:

- An entry is promoted from **open thread → probe** only when we can state the concrete attacker gain and a test that would demonstrate it.
- A rule is promoted from **advisory → full severity** only when a probe empirically confirms the pattern is exploitable (the "lint says maybe, probe says yes" handshake).

---

## 2. Why so little of the source guidance is security

The two primary sources — [Workers Best Practices](https://developers.cloudflare.com/workers/best-practices/workers-best-practices/) and [Rules of Durable Objects](https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/) — are roughly one-third security, two-thirds correctness/performance/cost. Workerwulf's value is in the security third *plus* the platform-native abuse patterns the docs don't frame as security at all (cross-request state as a leak channel, RPC/response returns as an exfil path, deletion incompleteness as remanence). The PRD makes that reframing explicit: where Cloudflare says "do X for correctness," we ask "what does an attacker gain when X is violated," and only the entries with an answer survive.

---

## 3. Detection substrates

Three engines, one severity model. The value is unifying their findings, not any one engine.

| Substrate | Catches | Engine |
|---|---|---|
| **AST / taint** | code shapes, source→sink data flow | opengrep (Semgrep-compatible, LGPL; `--taint-intrafile`) in the `codeshield`/`llamafirewall` container |
| **Config-lint** | binding graph, namespace settings, `.load()`/`.get()` call options | a `wrangler.toml`/`jsonc` parser (to build) |
| **Runtime** | platform behavior; confirmation of static candidates | the existing harness probe suite |

opengrep cannot see the binding graph; config-lint cannot see runtime behavior; neither can establish a platform property like isolate lifetime. The probe-only and open-thread sections exist precisely because the lint surface is smaller than the threat surface.

---

## 4. Rule metadata schema

Every rule carries this block so the catalog *is* the connective tissue between smell, surface, trust context, and evidence. The intended end state is a scoring layer that resolves `severity_base` × trust context; today, that multiplier is not operationalized and opengrep-native `severity` still controls scanner output severity.

```yaml
- id: wulf-sql-exec-concat
  pattern-either:
    - pattern: $DO.ctx.storage.sql.exec(`...${$X}...`)
    - pattern: $DO.ctx.storage.sql.exec("..." + $X)
  metadata:
    wulf_smell: sql-injection
    family: B
    surfaces: [durable, dynamic, ai, platform]   # where the smell applies
    trust_context: [first-party, loaded-untrusted, ai-generated, multi-tenant]
    validated_by: [DO-SQL-01, DO-SQL-02, DO-SQL-03, DO-SQL-04, DO-SQL-05]
    severity_base: high                            # critical once trust_context = ai-generated
    substrate: ast-taint
    precision_risk: low                            # honesty about FP/FN rate
    source: cloudflare-best-practices              # or wulf-probe-finding
```

**Trust contexts** (the severity multiplier):
`first-party` < `loaded-untrusted` (Dynamic Workers) < `ai-generated` (codegen pipeline) < `multi-tenant` (WfP user Workers). The same shape is materially worse the further right it sits — this is the operationalization of the trust-model inversion from `PLATFORM_SPEC.md` §1.

**Implementation status:** current rules list broad applicable trust contexts as metadata only. They do not yet restrict matches to a detected context, and no scoring layer currently upgrades/downgrades findings from `severity_base`. Until that layer exists, treat `severity_base` as catalog metadata and `severity:` as the scanner-enforced severity.

**Schema status:** legacy CodeShield carry-over signatures still use `metadata.wulf_category` instead of the newer `wulf_smell`/`family`/`validated_by` schema. They remain intentionally supported until a catalog-normalization pass either promotes them into families or marks them as scanner-local signatures.

---

## 5. Severity & exploitability-confidence scales

**Severity** (matches `ProbeResult.severity`): `informational | low | medium | high | critical`.

**Exploitability confidence** (parking-lot triage tag — how much we believe an attacker gains and how easily it's found in the wild):

| Tag | Meaning |
|---|---|
| **Confirmed** | A probe has demonstrated exploitation. |
| **High** | Clear attacker gain, plausible mechanism, likely common in real code/configs. Prioritize for a probe. |
| **Medium** | Plausible attacker gain but situational, or unclear prevalence. Worth a probe when capacity allows. |
| **Speculative** | Interesting; attacker value unproven. Documented hypothesis only; do not build infra yet. |

The parking lot is sorted by this tag. It is the document's most generative section, not a disclaimer.

---

## 6. Rule families

### Family A — Secrets & credentials  ·  `surfaces: all`

CF guidance: secrets must never appear in Wrangler config or source; use `wrangler secret`.

**Rules**

| ID | Smell | Substrate | Sev | validated_by | Precision |
|---|---|---|---|---|---|
| `wulf-secret-in-source` | secret-looking literal in source, or secret key under wrangler `vars` | ast + config | high | W-ENV-02 | med (entropy heuristic) |
| `wulf-hardcoded-conn-string` | DSN literal (`postgres://user:pass@…`) — the Hyperdrive "bad" example | ast | high | W-ENV-02 | low |
| `wulf-cf-api-token-in-worker` | `fetch` to `api.cloudflare.com` with a secret-derived `Bearer` token in Worker code, especially account-scoped or write-capable tokens where a binding/API-token split would reduce blast radius | ast | high | W-BND-01 | low |
| `wulf-secret-in-logs` | `console.log/error/warn` of `env.*` or a `token`/`secret`/`password`/`apiKey` variable — remanence into the durable, out-of-band observability plane | ast | medium | DO-MON-02; worker logging probe pending; P-OBS-01 pending | med |

**Open threads**

- *Secrets reachable via `wrangler types`-generated `Env` in error output* — if a thrown error serializes `env`, the generated typed bindings make the leak total. **Medium.**

---

### Family B — Injection & dynamic code  ·  `surfaces: durable, dynamic, ai, platform`

Every DO doc example uses parameterized `?`; string concatenation into `sql.exec` is the implicit anti-pattern, and our DO-SQL probes prove the blast radius.

**Rules**

| ID | Smell | Sev | validated_by | Precision |
|---|---|---|---|---|
| `wulf-sql-exec-concat` | template/`+` concatenation into `sql.exec` (taint: request/KV/D1 read → `sql.exec`) | high → **critical** if ai-generated | DO-SQL-01..05 | med (taint dependent) |
| `wulf-eval-reachable` | `eval(` / `new Function(` | high → critical (ai-generated) | W-DYN-01, W-DYN-02 | low |
| `wulf-dynamic-import-url` | `import()` of a non-literal / URL influenced by request, storage, AI output, or tenant-controlled config | high | W-DYN-03 | low |
| `wulf-wasm-from-bytes` | `WebAssembly.compile/instantiate` from runtime-constructed bytes (obfuscated-payload vector that defeats source-level analysis) | medium | W-WASM-01 | med |

**Open threads**

- *Decode-then-execute chains* — `atob()`/`fromCharCode`/hex → `eval`/`fetch`. The `evade-b64-url` residual (`RESULTS.md` §7) proves static can't decode at scan time; a Semgrep rule that flags the decode→sink **shape** (without decoding) is achievable. **Confirmed** (the gap is real); rule is **High** priority.

---

### Family C — Cross-request & isolate-reuse state  ·  `surfaces: worker, dynamic, platform`

CF: a variable set during one request is still present during the next, causing cross-request data leaks. The W-RUN series measures the persistence window and proves pollution survives isolate reuse.

**Rules**

| ID | Smell | Sev | validated_by | Precision |
|---|---|---|---|---|
| `wulf-global-request-state` | module-scope mutable `let` assigned from request data inside a handler | high | W-RUN-01, W-RUN-03, W-RUN-04 | med |
| `wulf-prototype-pollution` | `Object.prototype.X =`, `globalThis.fetch =`, intrinsic monkey-patch | high | W-RUN-05, W-RUN-06 | low |
| `wulf-module-scope-mutable-cache` | module-scope `const c = new Map()/[]/{}` written inside a handler — closure/cache retention accumulating prior requests' data (often benign memoization → static-flags / runtime-confirms candidate) | medium | W-RUN-04 | high (over-flags) |

**Probe-only findings** (no code to grep — platform behavior)

- **Isolate lifetime / persistence window** (W-RUN-02) — there is no smell; it's a platform property. Defines the blast window for any global-scope implant.
- **Cross-request secret residue** (W-RUN-03) — measures whether the *platform* leaks resolved secret values to a later request that never accessed them. A positive result is a platform finding, not a code defect.

**Open threads**

- *Infection-duration distribution under traffic shape* — compose W-RUN-02 (lifetime) × W-RUN-05/06 (pollution persists). Unknown: does steady load extend the window, does a burst force recycle, can an attacker **influence** recycle timing to prolong an implant or evade a defender's expected reset? **High** — novel, unpublished, and directly fundable as a probe.
- *Residue above the isolate* — does anything survive between requests at a layer the isolate doesn't own (cache, colo state)? On WfP this merges with the P-TEN cross-tenant question into one experiment. **High.**

---

### Family D — Crypto & comparison  ·  `surfaces: all`

CF: never use `Math.random()` for anything security-sensitive; use `crypto.subtle.timingSafeEqual()` for secret comparison — direct comparison leaks timing.

**Rules**

| ID | Smell | Sev | validated_by | Precision |
|---|---|---|---|---|
| `wulf-insecure-random` | `Math.random()` feeding a `token`/`id`/`key`/`secret`/`nonce` variable | high | W-CRY-03 | med (naming heuristic) |
| `wulf-non-constant-compare` | `===`/`!==` on a `token`/`secret`/`signature`/`hmac`/`apiKey`/`password` variable | medium | *(new: timing probe)* | med |

**Open threads**

- *Extractable key material* — `generateKey({extractable: true})` for keys that are never legitimately exported. **Medium**, maps W-CRY-02.

---

### Family E — Boundary returns & fail-open  ·  `surfaces: dynamic, durable, platform`

This family is the *defensive* sign-flip of the exfil probes: the rule and the abuse pattern are the same artifact viewed from two sides. Egress control (outbound Worker / `globalOutbound`) mediates `fetch()`, **not** the response path — so returning sensitive data outward is an unmediated channel.

**Rules**

| ID | Smell | Sev | validated_by | Precision |
|---|---|---|---|---|
| `wulf-env-in-response` | `env` (or spread/`JSON.stringify(env)`) reaching a `Response` or RPC return | high | D-NET-03; P-OUT-05 pending | med |
| `wulf-error-in-response` | `error.message`/`.stack` relayed to the caller (incl. the WfP dispatch `return new Response(e.message…)` pattern) | medium | W-ERR-01; P-OUT-05 pending | med |
| `wulf-passthrough-onexception` | `ctx.passThroughOnException()` — fail-open: routes to origin on unhandled exception | medium | *(new: fail-open probe)* | low |
| `wulf-sensitive-in-cache` | secret/PII written into `caches.default` — persists across invocations and isolate recycles, colo-scoped (remanence + covert channel) | medium | W-CACHE-01, W-CACHE-02 | med |

**Open threads**

- *Timing as a return channel* — modulating response latency to encode bits past an egress allowlist. **Medium**, maps D-NET-05.

---

### Family F — Concurrency & resource governance  ·  `surfaces: durable, worker, platform`

CF: `blockConcurrencyWhile()` across I/O is equivalent to holding a lock across I/O and severely degrades throughput; non-storage I/O lets requests interleave and cause races; the 128 MB memory limit makes unbounded body buffering a crash vector.

**Rules**

| ID | Smell | Sev | validated_by | Precision |
|---|---|---|---|---|
| `wulf-blockconcurrency-across-io` | `blockConcurrencyWhile` callback containing `fetch(` / `await env.*.get` / R2 — availability DoS; `AI-INJ-06` is indirect evidence until a dedicated DO contention probe lands | medium | AI-INJ-06, *(new: DO contention probe)* | low |
| `wulf-unbounded-body-read` | `request.text()/arrayBuffer()/json()` with no prior size check — OOM DoS | medium | W-ERR-03 | med |
| `wulf-do-toctou` | read → `await fetch()` → write without `transaction()`/CAS (the `processItem` race) | medium | *(new: DO race probe)* | high (cross-await flow) |

**Open threads**

- *Budget amplification* — per-invocation custom limits (WfP `cpuMs`/`subRequests`) bounded per-invocation, not per-tenant: escape via alarms/queues/secondary dispatch. **High**, maps P-LIM-03, AI-INJ-06 Payload D.
- *Subrequest/recursion limits as the only guardrail* — what an attacker can do inside the subrequest budget. **Medium**, maps W-SVC-03.

---

### Family G — Binding graph & namespace config (config-lint)  ·  `surfaces: dynamic, platform`

These are the rules opengrep cannot reach; they live in the `wrangler` parser. Several need no probe (the misconfiguration is self-evident); others join a config fact with a call-site. Status: the config-lint substrate exists as a fixture-backed skeleton for pure config checks, but the binding-graph joins and platform probe backing are not complete.

**Rules**

| ID | Smell | Substrate | Sev | validated_by |
|---|---|---|---|---|
| `wulf-loader-no-globaloutbound` | `LOADER.load({…})` with no `globalOutbound` key (untrusted child gets open egress) | ast + config | high | D-NET-01 |
| `wulf-loader-forwards-privileged-binding` | child `env` forwards privileged bindings absent from an explicit child-policy allowlist — join of load-site × toml binding privilege | ast + config | high | D-CAP-02 |
| `wulf-wfp-trusted-namespace` | dispatch namespace `trusted_workers = true` (shares zone cache + `request.cf` across mutually-distrusting tenants) | config | medium | P-TEN-01 pending |
| `wulf-wfp-no-outbound` | namespace with no outbound Worker configured (no egress control on user code) | config | medium | P-OUT-01/P-OUT-03 pending |
| `wulf-do-id-from-untrusted` | `idFromName()/getByName()` fed unsanitized request input (cross-object / IDOR) | ast-taint | high | DO-DYN-03, P-TEN-04 |

**Open threads**

- *Outbound policy keyed off request-derived fields* rather than the dispatcher `outbound` binding — tenant-identity confusion. **Medium**, maps P-OUT-04.
- *Outbound-injected credential reflected back* to the user Worker via a reflecting upstream. **Medium**, maps P-CAP-03.

---

### Family H — Data remanence & deletion  ·  `surfaces: durable, worker`

CF: deleting individual keys or dropping tables is not sufficient — internal metadata may remain; use `deleteAll()`. Pre-`2026-02-24` compat with an alarm set must `deleteAlarm()` first. This whole family is the security reframing of deletion guidance: "deleted" data that persists is a right-to-erasure failure, a forensics artifact, and potentially an information channel.

**Rules**

| ID | Smell | Substrate | Sev | validated_by | Precision |
|---|---|---|---|---|---|
| `wulf-incomplete-do-deletion` | a user-facing clear/reset/erase/delete-account path using per-key `delete()` or `DROP TABLE` without a complete cleanup primitive such as `deleteAll()` | ast | medium | DO-SQ3-04, *(new: deletion completeness probe)* | med |
| `wulf-orphaned-alarm-on-delete` | `deleteAll()` without `deleteAlarm()` on pre-2026-02-24 compat + alarm set — a "deleted" object keeps waking and firing (persistence) | ast + config | medium | DO-DYN-05 | low |
| `wulf-destructive-do-migration` | `deleted_classes` in a Wrangler migration ("removes all data!") | config | low | — | low |

**Probe-only findings**

- **PITR recoverability of "deleted" data** (DO-SQ3-08) — deletion presented as final while Point-in-Time Recovery makes it recoverable; access control on who can trigger PITR. No code to grep.
- **Residual-metadata observability after partial delete** — whether internal metadata that survives a non-`deleteAll()` delete is observable via SQL (`sqlite_master`, `__cf_*`).

**Open threads**

- *Deletion as an existence oracle* — if a partial/failed delete leaves observable residue, does it leak that a record *existed*? Deletion completeness becomes measurable, and measurable may mean an information channel. **High** — clean new probe family, no prior art, born from this theme.
- *Tombstone / data-remanence in KV/R2/D1 bindings* vs DO SQLite — does "deleted" data linger differently across storage primitives? **Medium.**

---

## 7. Probe-backing matrix

**Ship at current scanner severity now (probe-backed or self-evident config):**
A: `secret-in-source`, `hardcoded-conn-string`, `cf-api-token-in-worker` · B: `sql-exec-concat`, `eval-reachable`, `dynamic-import-url`, `wasm-from-bytes` · C: `global-request-state`, `prototype-pollution`, `module-scope-mutable-cache` · D: `insecure-random` · E: `env-in-response`, `error-in-response`, `sensitive-in-cache` · F: `blockconcurrency-across-io`, `unbounded-body-read` · H: `incomplete-do-deletion`, `orphaned-alarm-on-delete`.

**Advisory until a new probe lands:**
`secret-in-logs` on worker surfaces (worker logging probe missing) · `non-constant-compare` (timing) · `passthrough-onexception` (fail-open) · `do-toctou` (race) · `destructive-do-migration` · Family G binding graph and WfP namespace checks until the platform track and config-lint join are complete.

**Blocked on platform track / config-lint join:**
Family G's `loader-no-globaloutbound`, `loader-forwards-privileged-binding`, `wfp-trusted-namespace`, `wfp-no-outbound`, and `do-id-from-untrusted` need either P-* probe results, the binding-graph policy join, or both before they can be represented as full catalog rules.

**Probe-only (no rule will ever cover these — platform behavior):**
isolate lifetime (W-RUN-02) · secret residue (W-RUN-03) · PITR recoverability (DO-SQ3-08) · residual-metadata observability.

This matrix is itself a deliverable: the "advisory until" list is the exact set of *new* probes to add to back the rules we can't yet evidence.

---

## 8. Open-threads parking lot (consolidated, by confidence)

The harvest list. Sorted so future-us can triage which forks justify infrastructure.

**High** — prioritize for a probe:
- Infection-duration distribution under traffic shape (C).
- Residue above the isolate / merges with P-TEN (C).
- Budget amplification beyond per-invocation limits (F).
- Deletion as an existence oracle (H).

**Medium** — when capacity allows:
- Secrets via typed `Env` in error output (A).
- Extractable key material (D).
- Timing as a return channel (E).
- Outbound policy keyed off request fields; injected-credential reflection (G).
- Tombstone/remanence differences across storage primitives (H).

**Speculative** — documented hypotheses, no infra yet:
- (Add as they arise. Keep them here rather than starting work.)

---

## 9. Non-goals (explicitly excluded)

Documented so a reviewer sees the exclusion is deliberate, not an oversight. These are sound engineering practices with no direct attacker-gain story; where a linter already covers them, we defer to it rather than reimplement.

- Compatibility-date currency, `nodejs_compat`, `wrangler types`, deliberate environments, custom-domain/route setup.
- Response/request streaming for memory/TTFB; `waitUntil` ergonomics and `ctx` destructuring.
- Bindings-vs-REST, Queues-vs-Workflows, Hyperdrive, Static Assets, service-binding *preference* (the security-relevant slices of these are reframed into Families A/E, not adopted wholesale).
- Atom-of-coordination / sharding / global-singleton (availability/scaling, not security — though the singleton DoS angle may earn a Speculative thread).
- SQLite-backed preference, constructor migrations, indexes, in-memory-vs-persistent, input/output gate *correctness*.
- RPC-vs-fetch *ergonomics*, explicit `init()`, structured logging *format*, hibernatable WebSockets, `serializeAttachment`, `webSocketClose` reciprocation, alarm idempotency, write-incrementally-for-shutdown.
- **Floating promises / always-await:** correctness with a thin security edge (dropped audit work, unmonitored egress). Defer to `@typescript-eslint/no-floating-promises` / oxlint `typescript/no-floating-promises`; we do not own this. Documented here so the gap is intentional.

---

## 10. Next steps

1. Measure precision/recall for the implemented flagship rules against the probe-backed corpus, especially `wulf-sql-exec-concat` versus DO-SQL probes and `wulf-global-request-state` versus W-RUN probes.
2. Implement the scoring layer that resolves `severity_base` × detected trust context, or explicitly downgrade the PRD language to match opengrep-native severity-only behavior.
3. Normalize legacy `wulf_category` signatures into the rule metadata schema or document them as scanner-local detections outside the family catalog.
4. Extend the config-lint policy join for Family G, especially `wulf-loader-forwards-privileged-binding`, where "unneeded binding" must mean "not present in the child allowlist" rather than guessed from code alone.
5. Add the missing worker-side logging probe and the platform track probes referenced by P-* IDs.
6. Promote one advisory/open-thread item with a new probe design. Recommended first choices: *deletion-as-existence-oracle* for a clean storage-remanence story, or *infection-duration distribution* for a novel isolate-persistence story.
