# Wave 3 — disclosure-scoped capability-binding probes (W-CAP-*)

Capability-binding blast-radius probes whose backing resources need an account
resource and (for email) a disclosure decision. Same pattern as W-CAP-01: the
probe is `blocked` locally and `accessible` only once the binding + resource
exist. All tagged `misconfig:binding`.

## W-CAP-04 — Vectorize (RAG poisoning) — IMPLEMENTED

A Vectorize binding grants unrestricted `upsert`+`query`. The probe writes a
vector whose metadata carries an injection payload (the write-side of the Track 4
indirect-injection finding) and reads the store back.

```bash
# 1. Create the index (dimension must match DIM=768 in w-cap-04.ts)
wrangler vectorize create wulf-embeddings --dimensions=768 --metric=cosine

# 2. Uncomment the [[vectorize]] stanza in packages/worker/wrangler.toml
# 3. Deploy + run
pnpm --filter @wulf/worker deploy
cd packages/harness && pnpm start run --test W-CAP-04 --base-url https://wulf-worker.<subdomain>.workers.dev
```
Expected: `accessible`/`high` with `can_write`+`can_read` true. The poison vector
persists (Vectorize indexing is async, so an immediate `getByIds` read-back may be
empty — capability is proven by the calls succeeding).

## W-CAP-05 — Browser Rendering (SSRF-with-a-browser) — PLANNED

A Browser Rendering binding lets a Worker drive a headless Chromium to fetch and
render arbitrary URLs — a powerful SSRF/exfil primitive. Needs the `browser`
binding + `@cloudflare/puppeteer`. To be implemented next.

## W-CAP-03 — send_email — NEEDS A DISCLOSURE DECISION FIRST

A `send_email` binding turns a compromised Worker into a phishing/exfil channel.
**This sends real email from your domain.** For a HackerOne/SANS-framed project,
decide before building:
- Target **only** a researcher-owned, verified destination address.
- Keep payloads benign (a canary marker), never spoof third parties.
- Or skip it and document the capability without exercising it.

Not implemented pending that decision.
