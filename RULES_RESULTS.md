# Workerwulf Rules — Initial Validation Notes

> Last updated: 2026-05-29

This file records the first static-rule validation pass for the flagship Wulf rules from `RULES_PRD.md`.

## Rule source of truth

The canonical ruleset is `rules/wulf-rules.yml`.

The container-local copies are generated/synced runtime copies:

- `packages/llamafirewall/container/wulf-rules.yml`
- `packages/codeshield/container/wulf-rules.yml`

Sync copies after editing canonical rules:

```bash
pnpm rules:sync
```

Check for drift:

```bash
pnpm rules:check-sync
```

Run the complete local rule gate:

```bash
pnpm rules:check
```

## How to run

Self-checking fixture test:

```bash
pnpm rules:test
```

`rules:test` runs `scripts/check-wulf-rules.mjs`, which executes OpenGrep in JSON mode and verifies fixture annotations:

- `// ruleid: <rule>` must have a matching finding in the same file.
- `// ok: <rule>` must not have a matching finding in the same file.
- OpenGrep rule/config errors fail the test.

Fixture plus probe-backed corpus scan:

```bash
pnpm rules:scan
```

`rules:scan` prints a finding-count summary and fails on OpenGrep rule/config errors.

Both commands use local `opengrep` and read from canonical `rules/wulf-rules.yml`. OpenGrep 1.22.0 exits with code `2` when findings are present, so the checker and package scripts treat exit codes `0` and `2` as successful scan completion. The deployed containers still use their synced local copies plus the pinned Python `semgrep` package from container requirements until the container images are migrated to opengrep.

Current fixture test result:

```text
Wulf rule fixture check passed: 79 expected positives, 39 expected negatives, 88 findings.
```

Current config-lint fixture result:

```text
Wulf config-lint fixture check passed: 6 annotations, 3 findings.
```

Current corpus scan summary:

```text
Wulf corpus scan completed: 141 findings, 0 errors.
- wulf-blockconcurrency-across-io: 2
- wulf-cf-api-token-in-worker: 3
- wulf-decode-then-execute: 3
- wulf-destructive-do-migration: 1
- wulf-do-toctou: 1
- wulf-dynamic-import-url: 3
- wulf-env-enumeration: 6
- wulf-env-in-response: 3
- wulf-error-in-response: 7
- wulf-eval-reachable: 16
- wulf-global-request-state: 8
- wulf-hardcoded-conn-string: 3
- wulf-incomplete-do-deletion: 2
- wulf-insecure-random: 2
- wulf-module-scope-mutable-cache: 3
- wulf-non-constant-compare: 6
- wulf-orphaned-alarm-on-delete: 2
- wulf-passthrough-onexception: 1
- wulf-prototype-pollution: 5
- wulf-secret-in-logs: 10
- wulf-secret-in-source: 4
- wulf-secret-in-wrangler-vars: 2
- wulf-sensitive-in-cache: 2
- wulf-sql-exec-concat: 12
- wulf-sql-exec-dynamic-identifier: 10
- wulf-unbounded-body-read: 21
- wulf-wasm-from-bytes: 3
```

## Initial results

### `wulf-sql-exec-concat`

Corpus scan command:

```bash
pnpm rules:scan
```

Observed matches:

- `test-fixtures/wulf-rules/sql-exec-concat/positive-*.ts`: 6/6 expected positives.
- `test-fixtures/wulf-rules/sql-exec-concat/negative-*.ts`: 0/2 expected negatives.
- `packages/durable/src/durable/vulnerable.ts`: 6 matches across the confirmed `DO-SQL-01..05` user-value injection paths.
- `packages/durable/src/durable/secure.ts`: 0 matches after splitting identifier/file-operation dynamic SQL into the advisory rule below.

Precision note:

The high-severity rule is still intentionally narrow, but now covers the fixture-backed source-name vocabulary `input`, `username`, `userInput`, `body`, `payload`, and `id` when interpolated or concatenated into SQL before `sql.exec()`. This avoids counting sanitized identifier-only dynamic SQL as confirmed injection.

Next tuning step:

Add sanitizer-aware taint mode or more source naming coverage only with new positive and negative fixtures. `packages/durable/src/durable/secure.ts` should remain at 0 high-severity `wulf-sql-exec-concat` findings.

### `wulf-sql-exec-dynamic-identifier`

Observed matches:

- `test-fixtures/wulf-rules/sql-exec-dynamic-identifier/positive-*.ts`: 2/2 expected positives.
- `test-fixtures/wulf-rules/sql-exec-dynamic-identifier/negative-*.ts`: 0/1 expected negatives.
- `packages/durable/src/durable/secure.ts`: 4 advisory matches on sanitized dynamic SQLite identifier/file-operation statements.
- `packages/durable/src/durable/vulnerable.ts`: 4 advisory matches on the corresponding unsanitized SQLite-specific attack-surface statements.

Precision note:

This is a warning-tier advisory rule, not a confirmed SQL-injection verdict. It captures dynamic SQL areas where parameter binding does not apply cleanly: `PRAGMA`, `ATTACH DATABASE`, `load_extension`, `writefile`, and `readfile`. Sanitization may make a specific instance acceptable, but the shape still deserves review because the sink is outside normal value binding.

Next tuning step:

Add fixtures for allowlisted identifiers and split warning/advisory severity if the rule proves too noisy against real Durable Object code.

### `wulf-eval-reachable`

Observed matches:

- `test-fixtures/wulf-rules/eval-reachable/positive-*.ts`: 3/3 expected positives.
- `test-fixtures/wulf-rules/eval-reachable/negative-*.ts`: 0/1 expected negatives.
- `test-fixtures/wulf-rules/decode-then-execute/positive-*.ts`: 3 additional expected positives because decoded payloads flow into eval/function sinks.
- Corpus scan: 16 findings. This replaces the prior legacy `wulf-eval` and `wulf-function-constructor` IDs with one PRD-backed rule carrying full metadata.

Precision note:

This rule is sink-oriented rather than fully reachability-tainted: any `eval`, `globalThis.eval`, `window.eval`, `Function`, or `new Function` is treated as reachable dynamic code execution. In Workerwulf's target contexts, that is a low-noise security smell, especially for generated or loaded-untrusted code.

Next tuning step:

If this proves too broad in external corpora, split into `eval-reachable` for tainted sources and a lower-severity advisory for constant-only dynamic code construction.

### `wulf-dynamic-import-url`

Observed matches:

- `test-fixtures/wulf-rules/dynamic-import-url/positive-*.ts`: 3/3 expected positives.
- `test-fixtures/wulf-rules/dynamic-import-url/negative-*.ts`: 0/1 expected negatives.
- Corpus scan: 3 findings, all from the positive fixtures in the current scan set.

Precision note:

The first version requires `import($SPEC)` where `$SPEC` is assigned from request URL search params, `env.*`, or a storage read. Literal imports are not flagged.

Next tuning step:

Add fixtures for tenant config, AI output variables, and re-export/helper wrappers before widening to arbitrary non-literal imports.

### `wulf-wasm-from-bytes`

Observed matches:

- `test-fixtures/wulf-rules/wasm-from-bytes/positive-*.ts`: 3/3 expected positives.
- `test-fixtures/wulf-rules/wasm-from-bytes/negative-*.ts`: 0/1 expected negatives.
- Corpus scan: 3 findings, all from the positive fixtures in the current scan set.

Precision note:

The rule catches `WebAssembly.compile()` / `WebAssembly.instantiate()` when the bytes are assigned from request bodies, env bindings, or storage reads. It does not flag instantiation of an already-constructed `WebAssembly.Module`.

Next tuning step:

Add fixtures for R2 reads, D1/KV encoded payloads, and `Uint8Array` construction chains before widening beyond direct byte variables.

### `wulf-decode-then-execute`

Observed matches:

- `test-fixtures/wulf-rules/decode-then-execute/positive-*.ts`: 3/3 expected positives.
- `test-fixtures/wulf-rules/decode-then-execute/negative-*.ts`: 0/1 expected negatives.
- Corpus scan: 3 findings, all from the positive fixtures in the current scan set.

Precision note:

This implements the confirmed Family B open-thread shape for base64 decode flowing into dynamic execution. The existing legacy `wulf-b64-decode-fetch` remains for decode-to-fetch exfil obfuscation; this new rule covers decode-to-`eval`/`Function` execution.

Next tuning step:

Add fixtures for `String.fromCharCode`, hex decoding, `TextDecoder`, and decoded dynamic import before widening beyond `atob`.

### `wulf-global-request-state`

Observed matches:

- `test-fixtures/wulf-rules/global-request-state/positive-*.ts`: 6/6 expected positives.
- `test-fixtures/wulf-rules/global-request-state/negative-*.ts`: 0/3 expected negatives.
- `packages/worker/src/probes/w-run-01.ts`: catches module-scope request ID retention.
- `packages/worker/src/probes/w-run-04.ts`: catches module-scope array retention of request IDs.
- Corpus scan: 8 findings.

Precision note:

The rule is deliberately narrower than arbitrary module-scope mutation: module-scope state plus exported Worker/probe entrypoints plus request-derived values from headers, URL params, request body text, cookies, or `request.cf`.

Next tuning step:

Add fixtures for JSON body fields and auth/cookie aliases before widening beyond the current source set.

### `wulf-prototype-pollution`

Observed matches:

- `test-fixtures/wulf-rules/prototype-pollution/positive-*.ts`: 4/4 expected positives.
- `test-fixtures/wulf-rules/prototype-pollution/negative-*.ts`: 0/1 expected negatives.
- Corpus scan: 5 findings, including the W-RUN-05 probe-backed `Object.prototype` pollution shape.

Precision note:

The rule now carries full PRD metadata and covers `Object.prototype` / `__proto__` mutation plus selected runtime intrinsic monkey-patches such as `globalThis.fetch`, `globalThis.crypto`, `Array.prototype.*`, `Request.prototype.*`, and `Response.prototype.*`.

Next tuning step:

Add fixtures for other high-impact intrinsics only when there is a clear cross-request attacker-gain story.

### `wulf-module-scope-mutable-cache`

Observed matches:

- `test-fixtures/wulf-rules/module-scope-mutable-cache/positive-*.ts`: 3/3 expected positives.
- `test-fixtures/wulf-rules/module-scope-mutable-cache/negative-*.ts`: 0/1 expected negatives.
- Corpus scan: 3 findings, all from positive fixtures in the current scan set.

Precision note:

This is intentionally advisory and narrower than arbitrary module-scope containers. It flags module-scope `cache`, `memo`, `store`, or `mutableCache` variables backed by `Map`, array, or object storage when written inside a request handler. The name restriction avoids duplicating the higher-confidence `wulf-global-request-state` rule.

Next tuning step:

If this is useful in external corpora, add fixture-backed names and handler forms; keep it warning-tier because module-scope caches are often intentional.

### `wulf-secret-in-logs`

Observed matches:

- `test-fixtures/wulf-rules/secret-in-logs/positive-*.ts`: 10/10 expected positives.
- `test-fixtures/wulf-rules/secret-in-logs/negative-*.ts`: 0/4 expected negatives.
- Corpus scan: 10 findings, all from the positive fixtures in the current scan set.

Precision note:

The rule is intentionally concrete: it catches `env.*`, `JSON.stringify(env)`, env aliases serialized with `JSON.stringify`, common secret-like variable names (`token`, `secret`, `password`, `apiKey`, `authorization`, `cookie`), object logging forms such as `{ token }` or `{ token: authToken }`, and narrow logger wrappers (`logger.*` / `log.*`) for token and env-serialization cases.

Next tuning step:

Add fixtures for destructured env secrets, nested object logging, and additional logger-wrapper variable names before widening beyond the current `logger.*` / `log.*` coverage.

### `wulf-secret-in-source`

Observed matches:

- `test-fixtures/wulf-rules/secret-in-source/positive-*.ts`: 4/4 expected positives.
- `test-fixtures/wulf-rules/secret-in-source/negative-*.ts`: 0/3 expected negatives.
- Corpus scan: 4 findings, all from the positive fixtures in the current scan set.

Precision note:

The initial rule is intentionally name-context driven. It catches string literals assigned to or stored under explicitly secret-like names (`token`, `secret`, `password`, `apiKey`, `privateKey`, `bearer`) and does not flag env-derived secrets, documentation field-name strings, or unrelated example strings.

Next tuning step:

Add fixtures before expanding into high-entropy heuristics, broader credential literal prefixes, or more naming variants such as snake_case and screaming-snake env-style local constants.

### `wulf-secret-in-wrangler-vars`

Observed matches:

- `test-fixtures/wulf-rules/secret-in-wrangler-vars/wrangler-positive-*.toml`: 2/2 expected positives.
- `test-fixtures/wulf-rules/secret-in-wrangler-vars/wrangler-negative-*.toml`: 0/2 expected negatives.
- Corpus scan: 2 findings, both from the positive fixtures in the current scan set.

Precision note:

This is the config half of the PRD's `wulf-secret-in-source` entry. It uses OpenGrep's `generic` mode for Wrangler-style TOML and catches secret-like upper-case variable names assigned to committed string literals. It is deliberately narrower than a full config-lint parser and excludes obvious field-name/example placeholders.

Next tuning step:

Move this into the future config-lint engine once Family G policy parsing exists, so the rule can reason about actual `[vars]` scope, environments, and binding privilege classes.

### `wulf-hardcoded-conn-string`

Observed matches:

- `test-fixtures/wulf-rules/hardcoded-conn-string/positive-*.ts`: 3/3 expected positives.
- `test-fixtures/wulf-rules/hardcoded-conn-string/negative-*.ts`: 0/2 expected negatives.
- Corpus scan: 3 findings, all from the positive fixtures in the current scan set.

Precision note:

The first version catches obvious PostgreSQL/MySQL DSNs with inline `user:pass@host` credentials and Redis URLs with `:pass@host`. It excludes a documentation-style `user:pass@example.com` placeholder to avoid treating examples as real secrets.

Next tuning step:

Add fixtures before expanding to additional schemes or high-entropy credential heuristics.

### `wulf-cf-api-token-in-worker`

Observed matches:

- `test-fixtures/wulf-rules/cf-api-token-in-worker/positive-*.ts`: 3/3 expected positives.
- `test-fixtures/wulf-rules/cf-api-token-in-worker/negative-*.ts`: 0/2 expected negatives.
- Corpus scan: 3 findings, all from the positive fixtures in the current scan set.

Precision note:

The rule requires both a Cloudflare API URL and an Authorization bearer value derived from `env.CF_API_TOKEN` or a direct local alias. It intentionally does not flag public Cloudflare API calls without auth or bearer tokens sent to non-Cloudflare services.

Next tuning step:

Add fixtures for `Headers` objects, lower-case `authorization`, account-scoped token naming variants, and helper wrappers before widening beyond direct `fetch()` calls.

## Legacy scanner rule tightening

While adding the Cloudflare API-token fixtures, the legacy URL scanner rules were found to over-match unrelated `fetch()` calls because their URL regex filters were not scoped inside each `pattern-either` arm. `wulf-fetch-callback-host` and `wulf-fetch-exfil-path` now attach the metavariable regex to each fetch pattern, removing the previous false-positive corpus findings.

## Metadata validation

`scripts/check-wulf-rules.mjs` also validates metadata for every rule carrying `wulf_smell`. Required fields:

- `wulf_smell`
- `family`
- `surfaces`
- `trust_context`
- `validated_by`
- `severity_base`
- `substrate`
- `precision_risk`
- `source`
