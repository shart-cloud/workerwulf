# Astro v6 on-demand body-parser findings

Surface: Astro v6.4.4 on-demand request parsers (server islands, actions/RPC,
forms) running on the local `@astrojs/cloudflare` adapter (`middlewareMode:
'classic'`) via workerd. Tested with `@wulf/astro` — fixed-case probes
(`A-ISLAND/ACTION/FORM`), a raw-socket framing driver (`A-BODY`), and a seeded
mutation fuzzer (~2,700 iterations across seeds and modes). All findings
confirmed live over HTTP and against the real compiled code (`verify/`).

## Findings (2 — both Low)

Both are the **same root cause**: a parse-failure exception in a body parser is
not normalized to a 4xx, so one specific malformed input yields **500** where
every sibling input yields a clean 4xx. Impact is robustness / error-oracle —
no RCE, no data exposure, no DoS (size limits hold). In production this is a
generic 500; in dev it can surface a stack trace.

### F-1 — Server-island POST `null` body → 500
`POST /_server-islands/<name>` with body `null`. `getRequestData`
(`core/server-islands/endpoint.ts:84-87`) does `JSON.parse(body)` then
`Object.hasOwn(data, 'slots')`; `Object.hasOwn(null, …)` throws a `TypeError`
that the catch handles only for `SyntaxError`/`BodySizeLimitError`, so it
rethrows → 500. Scalars (`123`, `"x"`, `[]`) are fine (they reach a 404/decrypt
path); only `null` trips it.
Repro: `curl -X POST $T/_server-islands/x -H 'content-type: application/json' --data-raw 'null'`

### F-2 — Action malformed JSON → 500
`POST /_actions/<name>` with `Content-Type: application/json` and a body that
isn't valid JSON. `parseRequestBody` (`actions/runtime/server.ts:289`) calls
`JSON.parse`; the resulting `SyntaxError` is neither `ActionError` nor
`TypeError`, so the handler's catch (`server.ts:203-210`) rethrows → 500. Other
malformed inputs are handled: wrong-shape/array/`null` → 400 (zod), non-JSON
content-types → 415.
Repro: `curl -X POST $T/_actions/echo -H 'origin: $T' -H 'content-type: application/json' --data-raw '</script>'`

### Suggested fix
Treat parse failures in both JSON paths the way the **form path already does**:
`getFormServerHandler` / `parseRequestBody` map a malformed-multipart `TypeError`
to `415` (`server.ts:207`). Catch `SyntaxError` (and non-object JSON) in the
island endpoint and the action JSON path and return `400`/`415` instead of
letting it propagate.

## Verified secure (no issue found)

- **Server-island prop crypto** — AES-GCM with AAD `props:<componentId>`;
  cross-island ciphertext replay (incl. valid-export + foreign-props) → 400.
- **Body-size limits** — `serverIslandBodySizeLimit` / `actionBodySizeLimit`
  enforced via both `Content-Length` and the streamed byte counter → 413.
- **Action-name path resolution** — `__proto__`/`constructor`/`prototype`/
  `toString`/`hasOwnProperty` → 404 (`FORBIDDEN_PATH_KEYS`); no prototype walk.
- **Forms** — cross-origin form POST → 403 (origin check); JSON→form-action →
  415; malformed/empty/truncated multipart → 415 (graceful); abusive field names
  (`__proto__`, dotted) don't pollute (keys are schema-bound).
- **HTTP framing / smuggling** — workerd rejects duplicate `Content-Length`,
  CL.TE, header obfuscation, and malformed chunks with 400, single response.

## Methodology notes / confounders handled

- ~2,700 fuzz iterations (island/action/form, JSON + multipart + urlencoded,
  multiple seeds): every 5xx reduced to F-1/F-2. No new crash class, no timeout/DoS.
- `astro preview` interposes a **Node→workerd HTTP proxy** that can transiently
  500 with a Node error page (`TypeError: fetch failed`). These are dev-tooling
  artifacts, not worker/adapter bugs — the fuzzer now detects and buckets them
  (`proxyArtifact`). For proxy-free fuzzing, target the built worker via
  `wrangler dev` on the build output instead of `astro preview`.
- Other fuzzer false-positives fixed: a NUL byte in a content-type literal and
  client-unsendable header values (those framing cases belong to the raw driver).
