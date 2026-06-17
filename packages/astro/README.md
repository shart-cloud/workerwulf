# @wulf/astro

Fuzzing/abuse probes for **Astro on the Cloudflare adapter** — focused on the
on-demand request surfaces that parse attacker-controlled bodies: **server
islands**, actions, and the shared body-size limiter. Same probe model as the
rest of workerwulf (`Record<test_id, Probe>`, `(ctx) => ProbeResult`, driven
over HTTP by the `harness` CLI), with an added **local oracle** that proves each
probe's expectation against the *real compiled Astro code* with no deploy.

## Two tiers

| Tier | What | Runs | Covers |
|---|---|---|---|
| **Local oracle** (`verify/`) | drives the real compiled `getRequestData` + `encryption` from a local Astro checkout | `node --test` — no wrangler, no Astro build of the target | body-parse logic, size limits, AAD crypto |
| **Probe worker** (`src/`) | fires crafted HTTP at a running Astro app, classifies into `ProbeResult` | `wrangler dev` + `harness` CLI | the same, end-to-end over HTTP |
| **Raw-socket driver** (planned) | byte-level HTTP/1.1 for CL/TE/chunked desync that `fetch()` forbids | node `net`/`tls` | request smuggling (`A-BODY-*`) |

## Probe catalog

| Test ID | Tests | Expected (secure) | Flags |
|---|---|---|---|
| `A-ISLAND-01` | server-island POST with `null`/scalar JSON bodies | all 4xx | **5xx** → uncaught parse-path exception |
| `A-ISLAND-02` | malformed JSON, plaintext slot/export smuggling, missing GET params | clean 4xx, no stack/path/key in body | 5xx or info leak |
| `A-ISLAND-03` | oversized POST body vs `serverIslandBodySizeLimit` | 413 | 200/5xx → limit not enforced |
| `A-ISLAND-04` | replay island A's encrypted props to island B's id | 400 (AAD `props:<id>` mismatch) | 200 → cross-island prop confusion |
| `A-ACTION-01` | action content-type / malformed-body battery | 4xx | **5xx** → uncaught parse-path exception |
| `A-ACTION-02` | oversized action body (CL + streamed) vs `actionBodySizeLimit` | 413 | 200/5xx → limit not enforced |
| `A-ACTION-03` | action-name path traversal (`__proto__`/`constructor`/…) | 4xx (NOT_FOUND) | 200 (resolved) / 5xx (uncaught) |
| `A-FORM-01` | form-action content-type/accept + CSRF matrix | same-origin 200; JSON→form 415; cross-origin form 403; missing field 400 | any mismatch |
| `A-FORM-02` | malformed multipart + abusive field names | 4xx (415); no pollution | **5xx** (uncaught) |

`A-FUZZ` (mutation fuzzer, `node fuzz/fuzz.mjs --seed N --iterations M`, not a worker
probe): seeded mutation of bodies + content-types against the island/action parsers,
flags 5xx / timeout, dedups + writes repros. ~1100 iterations across two seeds reduced
every 5xx to the two known robustness bugs below — no new crash class, no DoS.

`A-BODY-*` (raw-socket driver, `node raw/smuggle.mjs`, not a worker probe): duplicate
`Content-Length`, CL.TE desync, `Transfer-Encoding` obfuscation, malformed chunks.
Secure = 400 + single response. Against `astro preview` (workerd) all five are
rejected — the smuggling surface is closed at the platform parser, not Astro.

### Live results (against the local adapter via workerd)
- `A-ISLAND-01` **accessible/low** — `null` body → 500 (see below).
- `A-ACTION-01` **accessible/low** — malformed `application/json` → 500 (see below).
- `A-ISLAND-02/03/04`, `A-ACTION-02/03`, `A-BODY-00..04` — all **blocked** (handled correctly).

### Validated findings (low — robustness / error-oracle)
Two sibling body-parse inconsistencies where one specific malformed input yields
a **500 instead of a clean 4xx** (every other malformed input is handled):

1. **A-ISLAND-01**
`core/server-islands/endpoint.ts` does `JSON.parse(body)` then
`Object.hasOwn(data, 'slots')`. For the JSON literal `null`, `Object.hasOwn`
throws a `TypeError` that the catch block does **not** handle (only
`SyntaxError` / `BodySizeLimitError`), so it rethrows → the request **500s**
instead of returning a clean 400. Every other malformed body yields 400. The
oracle in `verify/` proves this against the real compiled endpoint. Low severity
(robustness / error-oracle), but a clean seed for the fuzzer.

2. **A-ACTION-01**
`actions/runtime/server.ts` `parseRequestBody` maps `TypeError`→`UNSUPPORTED_MEDIA_TYPE`
and `ActionError`→error, but a `SyntaxError` from `JSON.parse` of a malformed
`application/json` body falls through `throw e` (line 210) → propagates → **500**.
Confirmed live: `malformed-json → 500`, while wrong-shape/array/`null` → 400 and
non-JSON content-types → 415. (Note: for *actions*, body `null` is handled — 400
via zod — unlike the island endpoint.)

> The **form path is more robust than the JSON path**: malformed multipart throws a
> `TypeError`, which the handler maps to **415** (`server.ts:207`), whereas malformed
> JSON throws a `SyntaxError` that falls through to **500**. A-FORM-02 demonstrates the
> graceful behavior the two findings above lack — i.e. the fix is to treat the JSON/island
> parse failures the same way.

> Harness footnote: `A-ACTION-03`'s result map first used a plain `{}` keyed by
> `__proto__`, which set the prototype instead of a key and silently dropped that
> case — the same footgun the probe hunts. Fixed with `Object.create(null)`.

## Run it

### Local oracle (works now, no deploy)
```bash
# requires the Astro package built once: (cd /home/jg/git/astro/packages/astro && pnpm build)
pnpm --filter @wulf/astro verify
# or point at a different checkout:
ASTRO_PKG=/path/to/packages/astro node --test verify/island-endpoint.test.mjs
```

### Live, over HTTP (via the harness)
```bash
# 1. Build + serve the target Astro app (system under test) — links the LOCAL adapter.
cd packages/astro/target
pnpm install                 # installs linked astro + @astrojs/cloudflare (must be built)
pnpm build && pnpm preview   # serves on http://127.0.0.1:8788

# 2. In another shell, serve the probe worker.
cd packages/astro
pnpm dev                     # wrangler dev; reads ASTRO_TARGET_URL from wrangler.toml

# 3. Drive the probes with the harness CLI (from packages/harness).
pnpm start run --track astro --base-url http://127.0.0.1:8787 --output ./results
```

Set the target either via `ASTRO_TARGET_URL` in `wrangler.toml` or by binding
the target Worker as the `ASTRO` service (see the commented block in
`wrangler.toml`).

## Layout
```
src/index.ts            probe-worker fetch handler (/probe/{id})
src/probes/index.ts     registry: A-ISLAND-01..04
src/probes/_helpers.ts  base(), target resolution, island-blob harvesting
src/probes/a-island-*.ts the four probes
verify/                 local oracle against real compiled Astro
target/                 minimal Astro+Cloudflare app under test (two server islands)
```

## Notes
- The target app is intentionally **outside** the wulf pnpm workspace
  (`packages/*` matches one level only) so its Astro deps don't entangle the harness.
- Astro-only for now; a Next.js sibling (`@wulf/next`) can reuse the tiers later.
- Next probes to add: `A-ACTION-*` (multipart/devalue/oversized) and the
  `A-BODY-*` raw-socket smuggling driver.
