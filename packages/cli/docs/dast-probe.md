# `wulf probe` — black-box DAST for Cloudflare Workers

`wulf probe <url>` is the dynamic counterpart to `wulf audit` (static source) and
`wulf scan` (authenticated account API). It sees a deployed Worker only as an
HTTP client does: it sends benign requests, reads the responses, and reasons
about the platform and its weaknesses from observable behaviour. No credentials,
no source, no account access.

It reuses the same rule engine, finding schema, severity model and
JSON/markdown reporting as the other commands, so `--json`, `--save`, `--strict`,
`--severity` and `--ignore` behave identically and its output flows through
`wulf report`.

## Authorization model

This tool sends real, sometimes error-provoking, requests to a live host. It is
for Workers **you own or are explicitly authorized to test** (e.g. a HackerOne
program's in-scope assets). The code enforces three guardrails:

1. **Scope allowlist.** The target host is implicitly allowed. Every *other*
   host — a redirect target, or an extra `--paths` entry on a different origin —
   must be listed in `--scope <file>` (one `host` or `*.host` per line) or
   `--allow host1,host2`. A request to any host not in scope throws before it
   leaves the process, including during redirect following.
2. **Rate limit + budget.** `--rps` (default 5) paces requests; `--max-requests`
   (default 300) is a hard ceiling for the whole run. Hitting the ceiling stops
   the scan cleanly and notes it.
3. **Conservative actions.** Only GET/HEAD/OPTIONS by default. `--allow-post`
   is required before any POST (used only to send malformed bodies to the paths
   under test). WebSocket checks address nonce instance names, never guessed
   real ones. Secret values discovered in exposed files are redacted from the
   report — only a length is shown.

## How fingerprinting works

`src/dast/fingerprint.ts` collects **signals**, each voting for one hypothesis
(`cloudflare` / `worker` / `pages` / `origin` / `not-cloudflare`) with a weight.

- **Decisive signals (weight 100)** settle the verdict alone: a `*.workers.dev`
  or `*.pages.dev` hostname, a Cloudflare Workers error page (1101/1102/1027/1042),
  a `/cdn-cgi/trace` response, a Cloudflare Access redirect.
- **Graded signals** are summed into a worker-vs-origin score: absence of
  `cf-cache-status` on a Worker-built response (→ worker), a leaked origin server
  token (`nginx`/`apache`/…) or backend cookie (`PHPSESSID`/`JSESSIONID`) (→
  origin), `cf-placement` (Smart Placement, → worker), Hono's default 404 body,
  strong hex `ETag` without edge caching (Workers Static Assets), and so on.

The verdict is one of `cloudflare-workers`, `cloudflare-pages`,
`cloudflare-proxied-origin`, `cloudflare-unknown`, `celld`, or `not-cloudflare`,
with a `high`/`medium`/`low` confidence.

**celld** (the self-hosted Workers/Durable Objects runtime) is distinguished
from Cloudflare's edge by its public listener, which reserves
`/.well-known/celld/health` (returning `{"ok":true}` / `{"ok":false}`) and can
emit an `x-celld-overload` header — neither of which Cloudflare's edge produces.
This keeps a self-hosted node from being mis-reported as Cloudflare.

### celld operator / peer exposure (`WF-DAST-CELLD-01/02`)

celld runs two listeners: a **public** one that serves the Worker, and an
**internal** one that serves the peer protocol and an operator API. Per celld's
own `docs/security.md`, the operator routes — `/state`, `/cell/<scope>`,
`/evict/<scope>`, `/do/<id>`, `POST /shutdown` — **take no authentication**; the
entire design relies on that listener living on a trusted private network. If it
is reachable from an untrusted network, an unauthenticated attacker can read node
state, evict cells, send requests straight to Durable Objects (bypassing the
Worker), and gracefully shut the node down.

`WF-DAST-CELLD-01` confirms exposure using the **one read-only route**,
`GET /state` (matched by a quorum of celld-specific node-state keys), and
**never calls the destructive routes** — their exposure is inferred because they
share the same unauthenticated listener. It runs against:

- `--celld-internal <url>` — the node's advertised internal address, the
  realistic "is my internal listener reachable from outside?" check; its host is
  auto-added to scope. (`WF-DAST-CELLD-02` additionally flags when the
  HMAC-gated `/peer/probe` port answers at all — the peer transport is plaintext
  HTTP and must never face an untrusted network.)
- the **target origin itself**, but only when the fingerprint already identified
  celld — catching an obsolete single-listener / merged-port deployment without
  adding a `/state` request to every non-celld scan. `WF-DAST-FP-01` reports the verdict and lists
every signal as evidence so the call can be audited — it is never a vulnerability
on its own.

Framework detection (Next.js/OpenNext, Astro, SvelteKit, Nuxt, Remix, Hono, …)
runs off low-ambiguity markers and is surfaced in the fingerprint.

## The checks

Each probe rule is grounded in a workerwulf research finding (the `probe:` field
back-references it, same as the static rules).

| Rule | Severity | What it detects |
|---|---|---|
| `WF-DAST-FP-01` | info | Platform / colo / framework fingerprint + signal trail |
| `WF-DAST-ACCESS-01` | info | Access-gated host — reminder that workers.dev/preview routes bypass the gate |
| `WF-DAST-EXPOSE-01` | critical | `.dev.vars` / `.env*` / `.git` served as a static asset (redacted) |
| `WF-DAST-EXPOSE-02` | medium | `wrangler.toml`/`.json` / project config served as a static asset |
| `WF-DAST-EXPOSE-03` | high | Worker source (`src/index.ts`, `_worker.js`, …) served as a static asset |
| `WF-DAST-EXPOSE-04` | low/medium | Production source maps public (medium if `sourcesContent` embedded) |
| `WF-DAST-ERR-01` | medium | Malformed input returns a V8 stack trace / raw exception message |
| `WF-DAST-ERR-02` | low | Unauthenticated input triggers an uncaught throw (Error 1101) |
| `WF-DAST-CORS-01` | high/med/info | `Access-Control-Allow-Origin` reflects an attacker Origin (high if credentialed) |
| `WF-DAST-CACHE-01` | high/low | Unkeyed request header (`X-Forwarded-Host`, …) reflected (high if it persists) |
| `WF-DAST-CACHE-02` | critical | Authenticated response served to an anonymous caller from cache (W-WC-04) |
| `WF-DAST-WS-01` | medium/high | Durable Object / Agents SDK WebSocket accepts an unauthenticated upgrade (high if `cf_agent_state` leaks) |
| `WF-DAST-CELLD-01` | critical | celld operator API (`/state`) reachable unauthenticated → `/evict`, `/do`, `/shutdown` exposed too |
| `WF-DAST-CELLD-02` | high | celld peer-protocol port reachable from the scanner (plaintext transport off a private network) |

### False-positive controls

- Every exposure check validates **content** (`.dev.vars` must contain
  `KEY=value` lines; Worker source must contain `export default … fetch(`), and
  compares against the target's response to a random missing path, so a catch-all
  SPA that answers `200 + index.html` for everything is not mistaken for file
  exposure (`isSoft404`).
- `WF-DAST-ERR-01` is suppressed if the baseline page itself already contains
  stack-trace-like text (a docs/blog page about errors).
- `WF-DAST-CACHE-01/02` run on URLs carrying a fresh `wulfcb=<nonce>` query
  parameter, so a poisoned entry lives under a key no real user requests; markers
  are inert `*.invalid` hostnames.
- `WF-DAST-CACHE-02` first proves the route is actually personalised
  (authenticated body ≠ anonymous body) before claiming a cross-caller leak.

## Flags

```
--scope <file>        host allowlist (one host or *.host per line)
--allow <hosts>       extra in-scope hosts, comma-separated
--paths <paths>       extra same-origin paths to test, comma-separated
--passive             fingerprint only; skip every active check
--auth-header "N: v"  credential for WF-DAST-CACHE-02 (e.g. "Cookie: session=…")
--celld-internal <url> suspected celld internal/operator listener to check for exposure
--allow-post          permit POST requests with malformed bodies
--rps <n>             requests per second (default 5)
--max-requests <n>    hard request budget (default 300)
--timeout-ms <n>      per-request timeout (default 10000)
--json --strict --severity <level> --ignore <ids> --save <dir>
```

## Limitations

- Fingerprinting is best-effort. A Worker that `fetch()`es a conventional origin
  and passes its headers through can read as `cloudflare-proxied-origin`; a bare
  Cloudflare zone with no framework markers reads as low-confidence. The signal
  trail in `WF-DAST-FP-01` is there so you can judge the call.
- The scanner never brute-forces paths beyond a small, high-signal built-in set
  plus whatever you pass in `--paths`. It is a focused confirmation tool, not a
  content-discovery fuzzer.
- WebSocket checks need Node ≥ 22 (global `WebSocket`). Without it, `WF-DAST-WS-01`
  degrades to no-finding rather than a false negative claim.
