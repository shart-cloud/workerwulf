# @wulf/analyze-poc

The analyzer Worker for `POSTURE_PLAN.md` slice 2. It runs `@wulf/analyze`, the same rule engine the `wulf` CLI uses, inside workerd, and its tests show the results match the CLI's byte for byte.

It is never deployed from this config: `workers_dev` and `preview_urls` are both off. The memory measurements below came from a temporary, token-gated deploy that was deleted afterwards.

## How it works

- `@wulf/analyze` holds the rules, the oxc AST helpers and wrangler parsing, and uses no Node APIs. The CLI and this Worker both call its `auditProject` and `analyzeAccount`, so there is one code path. The Worker needs no `nodejs_compat`.
- `@wulf/analyze` imports `oxc-parser`. In the Worker, `wrangler.jsonc` aliases that to `src/oxc-shim.worker.ts`, which loads the **same version's** official workerd build, `@oxc-parser/binding-wasm32-wasip1/workerd`. The `.wasm` compiles to a `WebAssembly.Module` at build time, and one instance is created per isolate.
- `src/oxc-loader.ts` wraps the WASM binding with `oxc-parser`'s own result wrapper (`src-js/wrap.js`), so `parseSync` returns exactly what the native binding returns.

## Endpoints

| Endpoint | Body | Returns |
|---|---|---|
| `POST /analyze` | `configPath`, `configText`, `sources` (path and text, in scan order), `files` (path → text next to the config, ancestors as `../`), optional `severity`, `ignore` | `{ report, notes }`, the same report `wulf audit --json` prints |
| `POST /scan` | `snapshot` (an `AccountSnapshot`, decoded with core's Schema), optional `localSources` (script name → path and text), `severity`, `ignore` | `{ report, notes }`, the same report `wulf scan --json` prints, coverage included |
| `POST /parse` | `path`, `text` | the raw AST, or sizes only with `?summary=1` |
| `GET /memory` | | the isolate's current WASM memory |

When the `WULF_TOKEN` secret is set, every request needs `Authorization: Bearer <token>`.

## What the tests prove

`pnpm test`:

| Test | Checks |
|---|---|
| `ast-equivalence` | The workerd WASM build against the native binding, over 281 files (every package's TS plus Effect's large JS bundles). The AST and diagnostics are **identical, with no exceptions**. |
| `workerd`: audit | Starts `wrangler dev`, posts each CLI fixture (config, sources and every other file, plus ancestor lockfiles) to `/analyze`, and compares the report with `wulf audit . --source --json` from the real CLI **as JSON text**, minus run id and timestamp. All 66 findings match, the 5 supply-chain ones included. |
| `workerd`: scan | The CLI scans a canned account (`test/account-fixture.ts`) that fires every account rule and has two coverage gaps. The Worker gets the same account as a snapshot and must return the same report text. A malformed snapshot gets a 400. |
| `workerd`: AST | The AST returned over HTTP from workerd equals the native AST for every fixture source |
| `workerd`: bundle | A 356 KiB real bundle parses in workerd with no errors |

As a one-off, the Worker also matched the CLI byte for byte on 16 real projects: every workerwulf Worker package and the CLI fixtures.

## Numbers from a real deployment (2026-11-11)

| Bundle | Size | CPU time | WASM memory after | Outcome |
|---|---|---|---|---|
| (idle isolate) | | | 64 MiB | |
| Effect `Schema.js`, first parse | 0.35 MB | 143 ms | 72 MiB | ok |
| Effect `Schema.js`, nine more | 0.35 MB | 45–73 ms | 78 MiB | ok, no further growth |
| a 1.5 MB Worker bundle | 1.47 MB | 582 ms | 104 MiB | ok |
| a 3.4 MB Worker bundle | 3.44 MB | 1,450 ms | 141 MiB | responded, then the isolate was killed: `exceededMemory` |
| a 5.7 MB bundle | 5.74 MB | | 226 MiB | `RangeError: Invalid array buffer length` |
| `typescript.js` | 8.72 MB | | 139 MiB | oxc panicked (`unreachable`) |
| a 25 MB bundle | 25.3 MB | | | 503, Worker exceeded resource limits |

- **Bundle size:** 661 KiB gzipped (WASM 501 KiB), against the 3 MB budget. CI fails above it. Startup time is 29 ms.
- **Memory ceiling:** about **1.5 MB of JavaScript per parse** is safe. WASM memory starts at 64 MiB, grows with the largest file parsed and never shrinks, so one big parse costs the isolate that memory for life. A 3.4 MB bundle already pushes past the 128 MB limit.
- **CPU:** 0.15–0.4 ms per KB of source, rising with size. Even small bundles exceed the Free plan's 10 ms, so the analyzer needs Workers Paid (30 s of CPU per request by default) or a Workflow step.

## Known gaps

- A file the Worker can't parse becomes a note, as in the CLI, but it isn't yet recorded in the report's coverage. Slice 3 should make "too large to analyze in a Worker" a coverage entry and send those bundles to a Container.
- `wrangler dev` doesn't enforce the memory limit, so only a real deployment catches the ceiling above.

## Run

```sh
pnpm test                 # equivalence suites (starts wrangler dev itself)
pnpm dev                  # wrangler dev on :8787
pnpm bundle               # wrangler deploy --dry-run --outdir dist, for sizes
```
