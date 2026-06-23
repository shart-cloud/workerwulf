# @wulf/cli — Workerwulf Cloudflare Workers Security Scanner

`wulf` turns the workerwulf research findings into a static scanner anyone can run
against their own Cloudflare Workers. It detects binding misconfigurations,
fail-open guards, hardcoded secrets, and dynamic-code sinks — every rule
back-references the workerwulf probe that empirically demonstrated the weakness.

See [`CLI_PRD.md`](../../CLI_PRD.md) for the full specification.

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

### `wulf scan` usage

```sh
wulf scan --account-id <id> --api-token <token>
wulf scan --source ./my-worker --strict --json     # add drift detection
wulf scan --namespace tenants                       # one WfP namespace
```

The Cloudflare client sits behind a small `CfClient` interface (`src/cf/client.ts`),
so the account rules and orchestration are unit-tested offline with a fake client.
The live `RestCfClient` is best-effort: WfP namespace introspection (trusted mode,
outbound, limits) and per-script routes depend on the account's API capabilities
and degrade to no-finding rather than a false claim (PRD §12.1).

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

- **oxc-parser AST shape.** This package targets `oxc-parser@0.40.1` (pinned),
  which emits the **oxc-native** AST (`StaticMemberExpression`,
  `ComputedMemberExpression`, `ObjectProperty`, `FunctionBody.statements`), *not*
  the ESTree shape the PRD's examples assumed. The walker is generic over node
  shape and rules target the real node names; see `src/ast/parse.ts`. Pin the
  version before upgrading — the AST can change between releases (PRD §17).
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
pnpm --filter @wulf/cli typecheck
pnpm --filter @wulf/cli test
```
