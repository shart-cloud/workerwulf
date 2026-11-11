# @wulf/cli — Workerwulf Cloudflare Workers Security Scanner

`wulf` turns the workerwulf research findings into a static scanner anyone can run
against their own Cloudflare Workers. It detects binding misconfigurations,
fail-open guards, hardcoded secrets, and dynamic-code sinks — every rule
back-references the workerwulf probe that empirically demonstrated the weakness.

See [`CLI_PRD.md`](../../CLI_PRD.md) for the full specification.

## Install

```sh
# One-off, no install:
npx @wulf/cli audit .

# Or install the `wulf` binary:
npm i -g @wulf/cli
wulf audit . --source --strict
```

Requires Node.js 20.19+ or 22.12+. No external tools — `oxc-parser` (Rust/WASM) ships as an
npm dependency, so there is no Semgrep/Python/Docker requirement.

## Status — Phases 1–4 complete (PRD fully implemented)

Implemented:

- **`wulf audit`** — offline config + source scanning, with `--source`, `--json`,
  `--strict`, `--severity`, `--ignore`.
- **wrangler parser** — `.toml` / `.json` / `.jsonc`, typed config model,
  `[env.*]` override resolution.
- **Rule engine** — rule interface + registry, runner, finding schema, JSON and
  human-readable table output.
- **AST engine** — oxc-parser wrapper, generic AST walker, single-pass binding
  map, full §7.5 predicate helper set.
- **Config rules** — `WF-CFG-01/02`, `WF-BIND-01..08`, `WF-EGR-01/02`,
  `WF-WFP-01/02`.
- **Source rules — families A–G complete:**
  - **A Secrets** — `WF-SEC-01` (hardcoded secrets), `WF-SEC-02` (secret logged),
    `WF-SEC-03` (secret in response).
  - **B Injection** — `WF-INJ-01` (eval), `WF-INJ-02` (`new Function`),
    `WF-INJ-03` (string `setTimeout`), `WF-INJ-04` (dynamic `import()`).
  - **C State** — `WF-STATE-01` (module-scope `let`/`var`), `WF-STATE-02`
    (module-scope const mutable container).
  - **D Crypto** — `WF-CRYPTO-01` (timing-unsafe secret compare), `WF-CRYPTO-02`
    (`Math.random` in security context).
  - **E Fail-open** — `WF-FAIL-01` (catch returns success), `WF-FAIL-02` (empty
    catch), `WF-FAIL-03` (guard try swallows).
  - **F Resource** — `WF-RES-01` (fetch in loop, no signal), `WF-RES-02` (SQL via
    template interpolation).
  - **G Binding-use** — `WF-BUSE-01` (Hyperdrive cred), `WF-BUSE-02` (browser
    SSRF), `WF-BUSE-03` (service-binding SSRF), `WF-BUSE-04` (SQL via concat).
- **`wulf scan`** — live Cloudflare account analysis via the API, with
  `--account-id`/`--api-token` (or `CLOUDFLARE_ACCOUNT_ID`/`CLOUDFLARE_API_TOKEN`),
  `--source` (drift), `--namespace`, `--json`, `--strict`, `--severity`,
  `--ignore`.
  - **Least-privilege** — `WF-PRIV-01` (declared-but-unused binding, severity
    inherits blast radius), `WF-PRIV-02` (high-blast-radius binding on a publicly
    routed script).
  - **Drift** — `WF-DRIFT-01` (deployed bundle vs local source).
  - **WfP namespace** — `WF-NS-01` (trusted mode), `WF-NS-02` (no outbound),
    `WF-NS-03` (no custom limits), `WF-NS-04` (scripts not untrusted).

- **`wulf probe`** — black-box DAST against a live Worker URL (no credentials, no
  source). Fingerprints the platform from HTTP behaviour, then runs network
  vulnerability checks. Scope-gated and rate-limited. See
  [`docs/dast-probe.md`](docs/dast-probe.md).
  - **Fingerprint** — `WF-DAST-FP-01` (platform/colo/framework verdict with audit
    trail), `WF-DAST-ACCESS-01` (Access gate vs. open workers.dev/preview routes).
  - **Static-asset exposure** — `WF-DAST-EXPOSE-01` (`.dev.vars`/`.env`/`.git`
    served as assets, values redacted), `-02` (wrangler/project config), `-03`
    (Worker source), `-04` (production source maps).
  - **Error disclosure** — `WF-DAST-ERR-01` (stack trace / exception to client),
    `-02` (uncaught exception / Error 1101 from unauthenticated input).
  - **Behavioural** — `WF-DAST-CORS-01` (reflected/`null` Origin), `WF-DAST-CACHE-01`
    (unkeyed-header cache poisoning), `WF-DAST-CACHE-02` (W-WC-04 cross-caller leak,
    needs `--auth-header`), `WF-DAST-WS-01` (unauthenticated Durable Object / Agents
    SDK WebSocket, with `cf_agent_state` leak detection).
  - **celld** (self-hosted Workers runtime) — `WF-DAST-CELLD-01` (unauthenticated
    operator API `/state` reachable → evict/`/do`/`/shutdown` also exposed),
    `WF-DAST-CELLD-02` (peer-protocol port reachable). Probes the target only when
    it fingerprints as celld, or an explicit `--celld-internal <url>`.

- **`wulf report`** — aggregate persisted run reports and render the coverage
  matrix, with `--results-dir`, `--run-id`, `--format markdown|json`, `--output`,
  `--matrix`, `--include-probes`.
  - Persistence: `wulf audit/scan --save <dir>` writes per-run JSON; `report`
    aggregates and dedupes findings across runs.
  - `--matrix` renders the rule → probe traceability table and validates that
    every rule cites a probe (§14); `--include-probes <harness results>` adds a
    probe-coverage table with explicit **gap** rows for probes no rule detects.

The PRD is now fully implemented (Phases 1–4).

### `wulf report` usage

```sh
wulf audit . --source --save ./results          # persist a run
wulf report --results-dir ./results             # aggregated markdown report
wulf report --matrix                            # rule → probe traceability
wulf report --matrix --include-probes ../harness/results   # + gap analysis
```

### `wulf probe` usage

```sh
# Fingerprint + full vuln sweep of a single Worker you own
wulf probe https://my-worker.example.workers.dev/

# Fingerprint only (passive signals + reserved paths), no active checks
wulf probe https://my-worker.example.workers.dev/ --passive

# Multiple hosts/paths, authenticated cache-leak check, CI gate
wulf probe https://app.example.com/ \
  --scope ./scope.txt --paths /api,/dashboard \
  --auth-header "Cookie: session=…" --strict --json

# Throttle and bound the run
wulf probe https://app.example.com/ --rps 2 --max-requests 150

# Check whether a celld node's internal/operator listener is exposed
wulf probe https://my-node.example.com/ --celld-internal https://my-node.example.com:9000
```

**Authorization.** `wulf probe` only scans hosts you are allowed to test. The
target host is implicitly in scope; any additional host (for redirects or extra
`--paths`) must be listed in a `--scope` file (`one-host-per-line`, `*.sub`
wildcards) or `--allow`. Requests are capped at `--rps` (default 5) and
`--max-requests` (default 300). POSTs with malformed bodies are off unless
`--allow-post` is set. Secret values found in exposed files are redacted from
the report.

### `wulf scan` usage

```sh
wulf scan --account-id <id> --api-token <token>
wulf scan --source ./my-worker --strict --json     # add drift detection
wulf scan --namespace tenants                       # one WfP namespace
```

Collection goes through `@wulf/core`'s typed `CfApi` service: 401/403, 404,
429 and 5xx are distinct errors, and 429/5xx are retried with backoff. Only failing
to list scripts stops a scan. Any other read that doesn't complete (a script's
bindings, routes or content, or WfP namespaces) is reported as a **coverage gap**,
not treated as empty:

```text
note: script:prey bindings: denied (HTTP 403 on …/settings); binding and least-privilege rules ran on partial data
```

With `--json`, those gaps are listed in a top-level `coverage` array. It is empty
when every read completed. A missing finding next to a coverage gap means "not
checked", not "clean".

A promise-shaped `CfClient` (`src/cf/client.ts`) can still be injected, which is
how the account rules are tested offline with a fake client.

## Usage

```sh
# Scan the current directory's wrangler config(s)
npx tsx src/index.ts audit .

# Also AST-scan Worker source, fail CI on high/critical
npx tsx src/index.ts audit . --source --strict

# Machine-readable output
npx tsx src/index.ts audit . --source --json

# Only show medium and above; suppress a rule
npx tsx src/index.ts audit . --severity medium --ignore WF-BIND-03
```

`pnpm --filter @wulf/cli audit .` is wired as a shortcut.

## Implementation notes

- **oxc-parser AST shape.** The rule engine lives in `@wulf/analyze`
  (`packages/analyze`, bundled into this CLI) and targets `oxc-parser@0.158.0`
  (pinned), which emits ESTree with UTF-16 offsets. Rules go through the
  predicates in `packages/analyze/src/ast/nodes.ts` rather than matching node
  shapes directly. Pin the version before upgrading, since the AST can change
  between releases (PRD §17).
- **Single parse, focused passes.** Each source file is parsed once. The binding
  map is built in its own pass; source rules currently walk the shared AST per
  rule (cheap for Worker-sized files). Collapsing to a single dispatched walk is
  a Phase 2 optimization.
- **Honest limitations.** Binding references through arbitrary aliasing/indirection
  and bundled/minified code are not tracked — false negatives are possible
  (PRD §12.1). WfP trusted-mode and per-dispatch limits largely live in the
  Cloudflare API; the offline rules catch only what is expressible in config and
  `wulf scan` (Phase 3) will cover the rest.

## Development

```sh
pnpm --filter @wulf/cli dev audit . --source   # run from source via tsx
pnpm --filter @wulf/cli typecheck
pnpm --filter @wulf/cli test
pnpm --filter @wulf/cli build                   # bundle to dist/ via tsup
```

## Build & publish

The package bundles to a single `dist/index.js` (ESM, Node ≥ 18 shebang) with
[tsup](https://tsup.egoist.dev/); runtime deps (`commander`, `oxc-parser`,
`smol-toml`) stay external and install from `package.json`. Only `dist/` and the
README ship (`files` allowlist); `npm pack --dry-run` confirms.

```sh
pnpm --filter @wulf/cli build
npm publish --workspace @wulf/cli   # prepublishOnly re-runs the build
```

**Distribution** (PRD §17): npm is the primary channel — `npx @wulf/cli` needs no
install and pulls `oxc-parser` automatically. A self-contained binary via
`bun build --compile` is a possible future addition for non-Node users; it is not
built today because oxc-parser's native/WASM artifact complicates single-file
compilation.
