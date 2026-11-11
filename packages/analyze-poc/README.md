# @wulf/analyze-poc

Proof of concept for `POSTURE_PLAN.md` slice 2: can the `wulf` rule engine and its oxc parser run inside workerd, and give exactly the CLI's results?

**Answer: yes, on oxc-parser's official workerd build.** This package is local-only and is never deployed (`workers_dev` and `preview_urls` are both off).

## How it works

- The CLI uses `oxc-parser@0.158.0` (native binding in Node). In the Worker, `wrangler.jsonc` aliases `oxc-parser` to `src/oxc-shim.worker.ts`. The shim loads the **same version's** official workerd build, `@oxc-parser/binding-wasm32-wasip1/workerd`. The `.wasm` compiles to a `WebAssembly.Module` at build time, and one instance is created per isolate when the module loads.
- `src/oxc-loader.ts` wraps the WASM binding with `oxc-parser`'s own result wrapper (`src-js/wrap.js`), so `parseSync` returns exactly what the native binding returns.
- `src/analyze.ts` is `wulf audit --source` without a filesystem: config text and source files come in as strings. It imports the CLI's parser, rules, runner and report code **unchanged**.
- `src/worker.ts` exposes `POST /analyze` (returns findings) and `POST /parse` (returns the raw AST).

## What the tests prove

`pnpm test`:

| Test | Checks |
|---|---|
| `ast-equivalence` | The workerd WASM build against the native binding, over 274 files (every package's TS plus Effect's large JS bundles). The AST and diagnostics are **identical, with no exceptions**. |
| `workerd`: findings | Starts `wrangler dev`, posts each CLI fixture to `/analyze`, and deep-compares the result with `wulf audit . --source --json` run by the real CLI. Supply-chain `WF-SC-*` findings are excluded, because they read files from disk. |
| `workerd`: AST | The AST returned over HTTP from workerd equals the native AST for every fixture source |
| `workerd`: bundle | A 356 KiB real bundle parses in workerd with no errors |

## Numbers

| | |
|---|---|
| Bundle | 2,398 KiB raw / **658 KiB gzipped** (WASM 501 KiB, JS 165 KiB including the napi/WASI runtime) |
| Parse, 356 KiB bundle | about 119 ms round trip in `wrangler dev` |
| WASM memory | **64 MiB minimum.** The module declares 1024 initial pages and refuses less. It grew to 84 MiB after 20 parses of a 356 KiB bundle and does not shrink. |

## Risks

- **Memory.** A 64–84 MiB WASM heap sits inside a Worker's 128 MB isolate limit, alongside the JS heap holding the AST. `wrangler dev` doesn't enforce the limit, so headroom has to be measured on a real deployment. If it's too tight, bundle analysis moves to a Container.
- **CPU.** Large bundles exceed the Free plan's 10 ms CPU limit; they need Workers Paid or a Workflow step.

## Known gaps

- Supply-chain rules need file text passed in, not disk reads.
- Account rules (`WF-PRIV`, `WF-DRIFT`, `WF-NS`) aren't exercised here yet.

## Run

```sh
pnpm test                 # equivalence suites (starts wrangler dev itself)
pnpm dev                  # wrangler dev on :8787
pnpm bundle               # wrangler deploy --dry-run --outdir dist, for sizes
```
