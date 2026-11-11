# @wulf/analyze-poc

Proof of concept for `POSTURE_PLAN.md` slice 2: can the `wulf` rule engine and its oxc parser run inside workerd, and give exactly the CLI's results?

**Answer: yes.** This package is local-only and is never deployed (`workers_dev` and `preview_urls` are both off).

## How it works

- `wrangler.jsonc` aliases `oxc-parser` to `src/oxc-shim.worker.ts`. That shim loads `@oxc-parser/wasm@0.40.1`, the WASM build at the same version as the CLI's native parser. The `.wasm` import compiles at build time, so start-up is synchronous and nothing is fetched at runtime.
- `src/oxc-api.ts` adapts the WASM call to the native call shape. The native call is `parseSync(filename, source, { lang })`; the WASM call is `parseSync(source, { sourceFilename })`. The adapter also frees the result's WASM memory.
- `src/analyze.ts` is `wulf audit --source` without a filesystem: config text and source files come in as strings. It imports the CLI's parser, rules, runner and report code **unchanged**.
- `src/worker.ts` exposes `POST /analyze` (returns findings) and `POST /parse` (returns the raw AST).

## What the tests prove

`pnpm test`:

| Test | Checks |
|---|---|
| `ast-equivalence` | WASM against native AST for 272 files (every package's TS plus Effect's large JS bundles). They are identical except the `sourceType.variant` label on JavaScript files. |
| `workerd`: findings | Starts `wrangler dev`, posts each CLI fixture to `/analyze`, and deep-compares the result with `wulf audit . --source --json` run by the real CLI with the native parser. Supply-chain `WF-SC-*` findings are excluded, because they read files from disk. |
| `workerd`: AST | The AST returned over HTTP from workerd equals the native AST for every fixture source |
| `workerd`: bundle | A 356 KiB real bundle parses in workerd with no errors |

## Numbers

| | |
|---|---|
| Bundle | 1,049 KiB raw / **347 KiB gzipped** (WASM 275 KiB, JS 77 KiB) |
| Parse, 150–350 KB bundle | about 55–62 ms WASM vs 20–25 ms native (Node); about 200 ms round trip in `wrangler dev` |
| Parse, typical source file | about 0 ms |

Large bundles need Workers Paid or a Workflow step. They exceed the Free plan's 10 ms CPU limit.

## Known gaps

- `@oxc-parser/wasm` is deprecated. Current `oxc-parser` ships an official `oxc-parser/workerd` entry, but its AST shape differs from 0.40's. The equivalence tests here are the safety net for that upgrade.
- Supply-chain rules need file text passed in, not disk reads.
- Account rules (`WF-PRIV`, `WF-DRIFT`, `WF-NS`) aren't exercised here yet.

## Run

```sh
pnpm test                 # equivalence suites (starts wrangler dev itself)
pnpm dev                  # wrangler dev on :8787
pnpm bundle               # wrangler deploy --dry-run --outdir dist, for sizes
```
