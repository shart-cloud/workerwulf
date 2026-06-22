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
> Still pending: **W-CAP-01** (Hyperdrive — waiting on CNPG Postgres backing),
> **W-CAP-03** (send_email — needs verified domain/address), **W-CAP-07** (mTLS —
> needs cert material + backend).

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

## W-CAP-07 — mTLS client certificate (authenticated SSRF) — IMPLEMENTED (not yet deployed)

An `mtls_certificates` binding attaches a client cert to outbound requests through
`env.MTLS_FETCHER.fetch()`. A compromised Worker borrows the cert's identity to
reach an mTLS-protected origin — strictly stronger than the bare `fetch()` of
W-NET-* because the request arrives already trusted.

```bash
wrangler mtls-certificate upload --cert cert.pem --key key.pem --name wulf-mtls
# Uncomment [[mtls_certificates]] in wrangler.toml; set certificate_id.
```
Expected: `accessible`/`high` with `http_status` populated. Pass
`?target=https://<mtls-protected-backend>/` to demonstrate authenticated reach;
defaults to `https://example.com/` to prove the fetcher works.

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
