# Wave 4 — capability-binding blast-radius probes (W-CAP-02/06/07/08)

Second batch of the `misconfig:binding` family (Wave 3 covered Hyperdrive,
Vectorize, Browser Rendering, send_email). Same pattern as every W-CAP probe: the
probe returns `blocked` locally and goes `accessible` only once the binding +
backing resource exist and the Worker is deployed. All tagged `misconfig:binding`.
Each carries a benign, run-tagged canary and exercises **one** capability — no
floods, no third-party targets.

Wire-up for all four lives commented in `packages/worker/wrangler.toml`. After
uncommenting a stanza:

```bash
pnpm --filter @wulf/worker deploy
cd packages/harness && pnpm start run --test W-CAP-0X \
  --base-url https://wulf-worker.<subdomain>.workers.dev
```

> **Deploy-verify status (2026-06-22):** W-CAP-02/04/06/08/09 all confirmed
> `accessible` against `wulf-worker.sharted.workers.dev` (latest version
> `1cf42136`). W-CAP-05 (Browser) confirmed `accessible` (fetched example.com,
> HTTP 200). Raw results in `packages/harness/results/w-cap-0*-wave4*.json`.
>
> **Update (2026-07-08): all capability probes now DEPLOY-VERIFIED.**
> - **W-CAP-07** (mTLS) → `accessible`/`high`; the `MTLS_FETCHER` binding is drivable by
>   any isolate code (see the W-CAP-07 section for the Cloudflare-egress caveat that
>   blocks the *authenticated-reach* half of the demo).
> - **W-CAP-01** (Hyperdrive) → `accessible`/`critical`; exfil'd the canary from a private
>   CNPG Postgres over a dedicated `wulf-vpc` Workers VPC tunnel — see
>   `docs/wave2-hyperdrive.md`.
> - **W-CAP-03** (send_email) → `accessible`/`high`; canary emailed via **Email Sending**
>   (not Email Routing) — see `docs/wave3-capability-bindings.md`.

## W-CAP-09 — Workers AI (unmetered inference / financial DoS) — VERIFIED accessible/high

An `[ai]` binding (account-level, no resource) lets any code in the isolate run
arbitrary Workers AI models at the account's expense via `env.AI.run()` — the
unmitigated "Workers AI quota exhaustion" line in the threat model, plus free
arbitrary model execution. The probe runs one tiny canary completion.

```bash
# Uncomment [ai] in wrangler.toml; deploy; run W-CAP-09.
```
Expected: `accessible`/`high` with `inference_ran:true`. NOTE: pin a *current*
model — `@cf/meta/llama-3.1-8b-instruct` was deprecated 2026-05-30; the probe uses
`@cf/meta/llama-3.2-3b-instruct`.

## W-CAP-02 — Secrets Store (plaintext creds in the env) — VERIFIED accessible/critical

The purest Serverless-Prey analog: a Secrets Store binding returns the plaintext
secret to any code in the isolate via `env.SECRET.get()`. The probe resolves the
secret and reports retrieval with the value redacted to a 6-char prefix; an
exact-substring match against a planted `flag{w-cap-02-...}` canary proves exfil.

```bash
wrangler secrets-store store create wulf-secrets
wrangler secrets-store secret create wulf-secrets --name WULF_CANARY \
  --value 'flag{w-cap-02-secrets-store-canary}' --scopes workers
# Uncomment [[secrets_store_secrets]] in wrangler.toml; set store_id + secret_name.
```
Expected: `accessible`/`critical` with `secret_retrieved:true`, `is_canary:true`.

## W-CAP-06 — Queues producer (pipeline injection / lateral) — VERIFIED accessible/high

A producer binding is unauthenticated write access to a consumer's input.
`env.PREY_QUEUE.send()` forges a message that reaches whatever the consumer trusts
— storage writes, downstream calls, fan-out — with none of the producer's normal
validation. The probe sends a single run-tagged canary message.

```bash
wrangler queues create wulf-prey-queue
# Uncomment [[queues.producers]] in wrangler.toml.
```
Expected: `accessible`/`high` with `message_sent:true`. (A consumer Worker is not
required to prove the producer capability; acceptance into the queue is the
finding. Bind a consumer separately if you want to observe downstream effect.)

## W-CAP-07 — mTLS client certificate (authenticated SSRF) — DEPLOY-VERIFIED accessible/high (2026-07-07)

An `mtls_certificates` binding attaches a client cert to outbound requests through
`env.MTLS_FETCHER.fetch()`. A compromised Worker borrows the cert's identity to
reach an mTLS-protected origin — strictly stronger than the bare `fetch()` of
W-NET-* because the request arrives already trusted.

```bash
# The public badssl client cert (PKCS#12, password "badssl.com") was used as
# cert material — a known cert that client.badssl.com itself accepts.
curl -sL https://badssl.com/certs/badssl.com-client.p12 -o badssl.p12
openssl pkcs12 -in badssl.p12 -clcerts -nokeys -out cert.pem -passin pass:badssl.com -legacy
openssl pkcs12 -in badssl.p12 -nocerts -nodes  -out key.pem  -passin pass:badssl.com -legacy
wrangler mtls-certificate upload --cert cert.pem --key key.pem --name wulf-mtls-badssl
# Uncomment [[mtls_certificates]] in wrangler.toml; set certificate_id; deploy.
```

**Result — binding accessible/high, authenticated reach blocked by Cloudflare egress.**
The binding is present and any isolate code can drive it:

| `?target=` | Origin TLS / trust | Result |
|---|---|---|
| `https://example.com/` | 1.3, no client-cert request | `accessible`/`high`, **HTTP 200** — fetcher usable at will |
| `https://client.badssl.com/` | **1.2**, requests cert, **trusts our cert** (`curl --cert` → 200) | **HTTP 500** (`server: cloudflare`, empty body) |
| `https://prod.idrix.eu/secure/`, `https://certauth.cryptomix.com/json/` | 1.3, require *their own* client CA | HTTP 500 (origin TLS-rejects our cert — expected) |

The **blast-radius thesis is confirmed**: `env.MTLS_FETCHER` is freely drivable by
any code in the isolate (example.com → 200), exactly like the other W-CAP bindings.

The **authenticated-reach half could not be demonstrated end-to-end** against public
mTLS reflectors, for a Cloudflare-platform reason rather than a probe defect:

- The 500s carry `server: cloudflare` + `cf-ray` + empty body — they are **edge-synthesized
  handshake failures at Cloudflare's egress**, not the origin's response (badssl's own
  200/400 carry `Server: nginx`). Not the documented **520** proxied-zone case (none of
  these origins are CF-proxied); server certs are publicly trusted (Full-strict passes);
  and the cert is requested in the *initial* handshake (not the documented TLS-1.3
  no-renegotiation case).
- The one public origin that **accepts our client cert** is `client.badssl.com`, and it is
  **TLS 1.2**-only. Cloudflare's egress 500s when presenting the client cert there even
  though the origin trusts it (`curl --cert` → 200) — the failure is isolated to
  **CF egress client-cert presentation over TLS 1.2**.
- The TLS 1.3 reflectors (idrix, cryptomix) require their *own* client CA, so they
  legitimately TLS-reject the badssl cert; we don't hold their cert. No public origin
  exists that both accepts our cert **and** runs TLS 1.3.
- Corroborated by multiple Cloudflare community reports of outbound "mTLS fetch not
  working on Workers" against external servers.

**To obtain the textbook `200-with / reject-without` proof** (deferred), stand up a
non-CF-proxied origin with a public (Let's Encrypt) server cert running nginx TLS 1.3
`ssl_verify_client on` trusting our client CA — the documented-supported configuration —
and confirm whether CF's egress completes it or fails even there.

> Cert `wulf-mtls-badssl` id `52a8fbc3-4878-4979-88a1-8e0074620154`; deployed version
> under `wulf-worker.sharted.workers.dev`. The badssl client cert is public and expires
> 2028-07-06 — no secret material committed.

## W-CAP-08 — Workers Analytics Engine (telemetry poisoning) — VERIFIED accessible/medium

An Analytics Engine binding accepts unauthenticated, unschematized writes via
`env.AE.writeDataPoint()`. This is the dataset DO-MON-03 maps as the SQL-op
detection channel, so the binding is a **detection-integrity** blast radius: flood
to bury real signal, or forge points to fabricate evidence. The probe writes one
run-tagged canary point.

```bash
# No resource to create — the dataset is named inline, created on first write.
# Uncomment [[analytics_engine_datasets]] in wrangler.toml.
```
Expected: `accessible`/`medium` with `data_point_written:true`. `writeDataPoint`
returns void, so acceptance (no throw) is the verdict; query the dataset via the
Analytics Engine SQL API to confirm the canary landed.
