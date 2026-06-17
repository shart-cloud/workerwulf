# Workerwulf

Empirical security research on the **Cloudflare Workers** platform — runtime
introspection, Dynamic Worker sandbox boundaries, SQLite-backed Durable Object
attack surface, and AI-agent prompt injection.

Workerwulf extends the published **Serverless Prey** methodology (Evans &
Johnson, Puma Security / SANS Institute) — which documented the runtime
environments, secret storage, and exfiltration paths of container-based FaaS
(AWS Lambda, Azure Functions, GCP Cloud Functions) — to Cloudflare's
V8-isolate execution model, for which no equivalent introspection research
exists.

It is the research backing for a **SANS Technology Institute MSISE practicum
(ISE 5901)** and will be published as an academic paper and as interactive
content on [shart.cloud](https://shart.cloud).

> **Ethics & authorization.** All testing targets the researcher's own
> Cloudflare account. Findings are disclosed to Cloudflare via HackerOne under
> their coordinated disclosure policy. This work is supervised as part of SANS
> MSISE ISE 5901.

---

## Research questions

1. What can an attacker with code execution inside a Cloudflare Worker observe
   about the runtime, and how does the blast radius compare to container-based
   FaaS?
2. Can untrusted code in a Dynamic Worker escape its granted capabilities —
   binding scope, network restrictions, or the RPC security boundary?
3. What is the practical attack surface of SQLite-backed Durable Objects, and
   what does SQL-injection blast radius look like when each object owns a
   private, co-located database?

## Test tracks

| Track | Focus | Probe families |
|---|---|---|
| **1 — Workers runtime introspection** | Global scope, network reachability, binding discovery, isolation side-channels | `W-ENV`, `W-NET`, `W-BND`, `W-ISO`, `W-RUN` |
| **2 — Dynamic Worker sandbox** | Capability escape from generated/untrusted code | `W-DYN` |
| **3 — Durable Object attack surface** | SQLi blast radius, monitoring gaps | `D-DO`, `DO-MON` |
| **4 — AI-agent prompt injection** | Injection against a Workers AI + Dynamic Worker agent, and defense effectiveness | `AI-INJ-01` … `AI-INJ-14` |

Track 4 is the most developed: an AI agent generates code from a user task and
executes it in a Dynamic Worker, with **LlamaFirewall** scanning input, output,
and execution trace. See [`AI_SPEC.md`](AI_SPEC.md) and
[`GUARD_COMPARISON_PLAN.md`](GUARD_COMPARISON_PLAN.md).

## Repository layout

A pnpm workspace monorepo.

| Package | Purpose |
|---|---|
| [`@wulf/ai-agent`](packages/ai-agent/) | **The orchestrator.** Worker with `env.AI` (Workers AI), `env.LOADER` (Dynamic Worker Loader), service bindings to the guard containers, and KV/R2/D1/DO canary bindings. Hosts the code-gen pipeline and all AI-INJ probes. |
| [`@wulf/llamafirewall`](packages/llamafirewall/) | Container Durable Object running Meta's LlamaFirewall. FastAPI server with four scanners: PromptGuard 2 (86M BERT), CodeShield (Semgrep + custom `wulf-rules.yml`), a regex scanner for callback/exfil patterns, and AlignmentCheck (routed at Workers AI Llama 3.3 70B). Exposes `/scan-input`, `/scan-output`, `/scan-trace`, `/report`, `/health`. |
| [`@wulf/prompt-guard`](packages/prompt-guard/) | Standalone PromptGuard 2 container DO, kept as a baseline control. |
| [`@wulf/codeshield`](packages/codeshield/) | Standalone CodeShield container (image built, consolidated into LlamaFirewall in practice). |
| [`@wulf/harness`](packages/harness/) | CLI test harness — runs probes and collects results to `packages/harness/results/`. |
| [`@wulf/shared`](packages/shared/) | Shared types (`ProbeResult`, `Track`, …). |
| [`@wulf/astro`](packages/astro/) | Astro frontend for the shart.cloud lab. |
| [`@wulf/worker`](packages/worker/), [`@wulf/durable`](packages/durable/), [`@wulf/dynamic-parent`](packages/dynamic-parent/), [`@wulf/platform`](packages/platform/) | Track 1–3 introspection workers and supporting infrastructure. |
| [`callbackd`](packages/callbackd/) | Go callback server (receives exfil/callback probes). Infra in [`infra/`](infra/). |

## Getting started

```bash
pnpm install
pnpm -r typecheck
```

### Run the harness

```bash
# From repo root
pnpm harness

# Or target a track / probe directly
cd packages/harness && pnpm start -- --track ai --probe AI-INJ-14
```

### Deploy a Worker

```bash
cd packages/ai-agent && pnpm deploy
cd packages/llamafirewall && pnpm deploy
```

### Build the LlamaFirewall container

Requires an `HF_TOKEN` for the gated PromptGuard 2 model.

```bash
cd packages/llamafirewall/container
docker build --build-arg HF_TOKEN=hf_xxx -t wulf-llamafirewall:v1 .

# Push to the Cloudflare registry (see AGENTS.md for the account ID)
npx wrangler containers push \
  registry.cloudflare.com/<account-id>/wulf-llamafirewall:v1
```

### Custom rules

The CodeShield scanner uses a custom Semgrep ruleset.

```bash
pnpm rules:check     # sync check + tests + config + scan
pnpm rules:sync      # regenerate derived rule artifacts
```

## The guard pipeline

The AI agent runs a multi-stage pipeline that LlamaFirewall can gate:

```
1. scan-input   → if blocked, STOP (never call Workers AI)
2. generate     → env.AI.run() produces code
3. scan-output  → if blocked, STOP (never load into Dynamic Worker)
4. validate     → AST check; if rejected, STOP
5. execute      → env.LOADER.load() runs the code in a Dynamic Worker
6. scan-trace   → post-execution alignment check
```

Each scan stage takes a per-request `policy`:

- `"block"` — gate is active; stop on a block verdict.
- `"log"` — observe only; record the verdict but continue.
- `"pass"` — skip the scan.

This lets the same `runAiAgent()` back both the research probes (observability
mode, for backward-compatible results) and the interactive shart.cloud lab
(enforcement mode). Per-stage verdicts, timings, and scanner breakdowns are
returned in `AiAgentRunResult.guard_results`.

## Key documents

| Document | Contents |
|---|---|
| [`PRD.md`](PRD.md) | Full product requirements — all tracks and probe IDs |
| [`AI_SPEC.md`](AI_SPEC.md) | Track 4 probe specifications (AI-INJ-01 … AI-INJ-14) |
| [`GUARD_COMPARISON_PLAN.md`](GUARD_COMPARISON_PLAN.md) | LlamaFirewall vs. Llama Guard 3 comparison design |
| [`PLATFORM_SPEC.md`](PLATFORM_SPEC.md) | shart.cloud lab platform spec |
| [`RESULTS.md`](RESULTS.md) / [`RULES_RESULTS.md`](RULES_RESULTS.md) | Findings |
| [`AGENTS.md`](AGENTS.md) | Detailed contributor/agent guide — bindings, file map, conventions |

## License & disclosure

Academic security research. Vulnerabilities are reported to Cloudflare through
coordinated disclosure before public release.
