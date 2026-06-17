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

## W-CAP-05 — Browser Rendering (SSRF-with-a-browser) — IMPLEMENTED

A Browser Rendering binding lets a Worker drive a headless Chromium to fetch and
render arbitrary URLs — a stronger SSRF/exfil primitive than `fetch()` (JS exec,
redirects, screenshots from CF egress). Account-level binding, no resource to create.

```bash
# 1. Uncomment the [browser] stanza in packages/worker/wrangler.toml
# 2. Deploy + run (pass ?target=<url>; defaults to https://example.com/)
pnpm --filter @wulf/worker deploy
cd packages/harness && pnpm start run --test W-CAP-05 --base-url https://wulf-worker.<subdomain>.workers.dev
```
Expected: `accessible`/`high` with `http_status`/`page_title`/`content_preview`
populated. Point `?target=` at an internal/metadata endpoint to demonstrate SSRF
reach. Uses `@cloudflare/puppeteer` (bundles cleanly under nodejs_compat).

## W-CAP-03 — send_email (exfil/phishing channel) — IMPLEMENTED

A `send_email` binding turns a compromised Worker into a phishing/exfil channel.
Built with the responsible posture: delivery is **pinned to one researcher-owned
verified address** via the binding's `destination_address` (the platform enforces
this), the payload is a **benign canary**, and no third party is targeted or spoofed.

```bash
# 1. Email Routing verified on your domain; destination address verified.
# 2. Uncomment the [[send_email]] stanza in packages/worker/wrangler.toml and set
#    destination_address to your verified address. Add to [vars]:
#      WULF_EMAIL_FROM = "wulf@<your-verified-domain>"
#      WULF_EMAIL_TO   = "<= destination_address>"
# 3. Deploy + run
pnpm --filter @wulf/worker deploy
cd packages/harness && pnpm start run --test W-CAP-03 --base-url https://wulf-worker.<subdomain>.workers.dev
```
Expected: `accessible`/`high` with `sent: true`; a canary email
(`flag{w-cap-03-send-email-canary}`) arrives at the pinned address. If the vars
aren't set, the probe returns `partial` without sending.
