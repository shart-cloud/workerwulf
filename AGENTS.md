# AGENTS.md — Workerwulf

You are reviewing an academic security research project conducted as part of a SANS Technology Institute MSISE practicum (ISE 5901). This project extends the published Serverless Prey methodology (Evans & Johnson, Puma Security / SANS Institute) to the Cloudflare Workers platform. All testing is conducted against the researcher's own Cloudflare account. Your role is to review code quality, test methodology rigor, and completeness of findings documentation."

## Project Overview

Workerwulf is an empirical security research project investigating the Cloudflare Workers platform — runtime introspection, Dynamic Worker sandbox boundaries, Durable Object attack surface, and AI agent prompt injection. It is the research backing for a SANS MSISE practicum (ISE 5901) and will be published as both an academic paper and interactive content on [shart.cloud](https://shart.cloud).

The monorepo lives at `/home/jg/git/shart-cloud-gh/workerwulf` and uses pnpm workspaces. Key documents:

- `PRD.md` — full product requirements, all test tracks and probe IDs
- `AI_SPEC.md` — Track 4 (AI Agent Prompt Injection) probe specifications: AI-INJ-01 through AI-INJ-12
- `GUARD_COMPARISON_PLAN.md` — LlamaFirewall vs Llama Guard 3 comparison design, AI-INJ-13 redesign
- `NEW_TESTS.md` — exte

## Ethics & Authorization
- All testing targets the researcher's own Cloudflare account (account ID: [redacted])
- This research follows the Serverless Prey methodology published by SANS Institute
- Findings will be disclosed to Cloudflare via HackerOne per their coordinated disclosure policy
- This project is supervised as part of SANS MSISE ISE 5901nded probe specs (W-RUN, W-DYN, D-DO series)

## Packages

| Package | Path | Purpose |
|---|---|---|
| `@wulf/ai-agent` | `packages/ai-agent/` | **The orchestrator.** Worker with `env.AI` (Workers AI), `env.LOADER` (Dynamic Worker Loader), `env.LLAMAFIREWALL` (service binding to LlamaFirewall container DO), `env.PROMPT_GUARD` (service binding to PG2 container DO), KV/R2/D1/DO bindings for canary data. Hosts the code-gen pipeline and all AI-INJ probes. |
| `@wulf/llamafirewall` | `packages/llamafirewall/` | Container DO running Meta's LlamaFirewall framework. FastAPI server with four scanners: PromptGuard 2 86M (local BERT classifier), CodeShield (Semgrep + custom `wulf-rules.yml`), RegexScanner (WULF callback/exfil patterns), WulfAlignmentCheckScanner (AlignmentCheck routed at Workers AI Llama 3.3 70B via OpenAI-compat endpoint). Exposes `/scan-input`, `/scan-output`, `/scan-trace`, `/report`, `/health`. SQLite logging in the DO. |
| `@wulf/prompt-guard` | `packages/prompt-guard/` | Standalone PG2 86M container DO. Kept as a baseline control — demonstrates that PG2 alone scores 0/15 on the AI-INJ payload set. |
| `@wulf/codeshield` | `packages/codeshield/` | Standalone CodeShield container. Image built and pushed but NOT deployed as a separate Worker — consolidated into LlamaFirewall. |
| `@wulf/harness` | `packages/harness/` | CLI test harness. Runs probes, collects results to `packages/harness/results/`. |
| `@wulf/shared` | `packages/shared/` | Shared types (`ProbeResult`, `Track`, etc.). |
| Other packages | `packages/worker/`, `packages/durable/`, `packages/dynamic-parent/`, `packages/callbackd/` | Track 1–3 introspection workers, callback server, etc. |

## Current State

### What works

- All 13 AI-INJ probes (AI-INJ-01 through AI-INJ-13) are implemented and have results in `packages/harness/results/callback-full-ai-1779902675/`.
- The LlamaFirewall container is deployed and scanning. PG2, CodeShield, Regex all work. AlignmentCheck has a known issue with Workers AI structured output compatibility (see below).
- The ai-agent Worker has all bindings wired: `env.AI`, `env.LOADER`, `env.LLAMAFIREWALL`, `env.PROMPT_GUARD`, `env.PREY_KV`, `env.PREY_R2`, `env.PREY_D1`, `env.PREY_DO`.
- `llamafirewall.ts` exposes typed helpers: `lfScanInput()`, `lfScanOutput()`, `lfScanTrace()`, `lfReport()`.
- `guard.ts` exposes PG2 helpers: `guardClassify()`, `guardClassifyBoth()`, `guardReport()`.
- `guard-llg3.ts` exposes Llama Guard 3 helpers: `llg3ClassifyInput()`, `llg3ClassifyOutput()`, `llg3ClassifyBoth()`.

### AlignmentCheck on Workers AI — RESOLVED

`WulfAlignmentCheckScanner` in `packages/llamafirewall/container/wulf_scanners.py` now uses a custom `WulfLLMClient` that bypasses LlamaFirewall's `LLMClient.call()` structured-output path:

- Uses `response_format={"type": "json_object"}` (universally supported on Workers AI) instead of `.beta.chat.completions.parse()` with a Pydantic `response_format`.
- Embeds the Pydantic schema in the system prompt so the model knows what to emit.
- Handles dict-vs-string content (CF sometimes pre-parses the JSON) and coerces string booleans (`"True"` → `True`).
- No fork of llamafirewall — `WulfLLMClient` subclasses `LLMClient` and the scanner subclass swaps it in after `super().__init__()`.

Latest probe run (AI-INJ-13, v6, 2026-05-28) confirms AlignmentCheck runs end-to-end against Workers AI's Llama 3.3 70B and returns valid `AlignmentCheckOutputSchema` instances in ~5–9s per call. For our payload set it returned `Conclusion: False` (no misalignment) on every trial, including `replay-09` — the indirect-via-poisoned-data case. That's the correct verdict for our setup: the injection lives in KV data we didn't seed during the run, so the agent's *actions* matched the user's *stated intent*. AlignmentCheck only flags when retrieved data manifests in misaligned agent action.

Background — what was failing before the fix:

1. LlamaFirewall's `LLMClient.call()` uses the OpenAI SDK's `.beta.chat.completions.parse()` which sends `response_format` in OpenAI's wire shape (`{"type":"json_schema","json_schema":{"name":"...","strict":true,"schema":{...}}}`).
2. Workers AI's OpenAI-compat endpoint uses a different shape — the raw JSON Schema goes directly under `json_schema`, not wrapped in `{name, strict, schema}`.
3. The SDK's `.parse()` also calls `model_validate_json(content)` which expects a JSON string, but Workers AI sometimes returns `content` as a pre-parsed dict.
4. `CustomCheckScanner._evaluate_with_llm` catches the exception and returns `_get_default_error_response()`, which produces `decision: "human_in_the_loop_required"` — a false positive on every call.

---

## The Next Major Milestone: Gated Pipeline

### Problem

The current `agent.ts` pipeline runs LlamaFirewall scanners as **parallel observability** — the probes call `lfScanInput()`, `lfScanOutput()`, `lfScanTrace()` alongside code generation and execution, then compare verdicts after the fact. The scanners never actually *prevent* execution. The pipeline in `runAiAgent()` is:

```
1. env.AI.run() → generate code
2. validateGeneratedCode() → AST check (only in "defense" tier)
3. env.LOADER.load() → Dynamic Worker executes generated code
4. return result
```

### Goal

Refactor `runAiAgent()` so LlamaFirewall acts as a **blocking gate** between code generation and Dynamic Worker execution. The pipeline becomes:

```
1. lfScanInput(env, userTask) → if decision === "block", STOP. Do not call Workers AI.
2. env.AI.run() → generate code
3. lfScanOutput(env, generatedCode) → if decision === "block", STOP. Do not load into Dynamic Worker.
4. validateGeneratedCode() → AST check. If rejected, STOP.
5. ALL GATES PASSED → env.LOADER.load() → Dynamic Worker executes
6. lfScanTrace(env, conversationHistory) → post-execution alignment check. Flag for next turn.
```

Each gate's verdict, timing, and scanner breakdown MUST be included in the `AiAgentRunResult` so downstream consumers (probes, the future shart.cloud lab UI) can show exactly what happened at each stage.

### Design constraints

- **The gate behavior must be toggleable per-request.** The existing probes need to run with gates OFF (observability mode) to maintain backward compatibility with the AI-INJ-01–12 results. New probes and the shart.cloud lab will run with gates ON.
- **Do not break the existing `AiAgentRunResult` interface.** Extend it with new optional fields for gate verdicts. Existing fields (`generated_code`, `code_contains_fetch`, `validator_rejected`, `sandbox_result`, etc.) must remain.
- **The `policy` parameter on each scan call controls enforcement.** `policy: "block"` means the gate is active (stop on block verdict). `policy: "log"` means observe-only (scan runs, verdict is recorded, but execution continues regardless). `policy: "pass"` means skip the scan entirely.
- **Latency is acceptable.** PG2 ~300ms, CodeShield ~1s, AlignmentCheck ~3-8s. For the research harness this is fine. For the shart.cloud lab, we'll run scan-input + scan-output synchronously (they're fast) and scan-trace can run post-response.

### Implementation guidance

**Extend `AiAgentRunParams`:**
```typescript
interface AiAgentRunParams {
  // ... existing fields ...
  guard?: {
    scanInput?: "block" | "log" | "pass";   // default: "pass" (backward compat)
    scanOutput?: "block" | "log" | "pass";  // default: "pass"
    scanTrace?: "block" | "log" | "pass";   // default: "pass"
    astValidator?: boolean;                  // default: only true for "defense" tier
  };
}
```

**Extend `AiAgentRunResult`:**
```typescript
interface AiAgentRunResult {
  // ... existing fields ...
  guard_results?: {
    scan_input?: LlamaFirewallScanResult & { gate_action: "blocked" | "allowed" | "skipped" };
    scan_output?: LlamaFirewallScanResult & { gate_action: "blocked" | "allowed" | "skipped" };
    scan_trace?: LlamaFirewallScanResult & { gate_action: "flagged" | "allowed" | "skipped" };
    pipeline_blocked: boolean;
    blocked_at?: "scan_input" | "scan_output" | "ast_validator";
    total_guard_latency_ms: number;
  };
}
```

**Refactor `runAiAgent()`:**

The function should execute the pipeline stages sequentially, checking each gate. If a gate with `policy: "block"` returns `decision: "block"`, the function should:
1. Record the gate verdict in `guard_results`
2. Set `pipeline_blocked: true` and `blocked_at` to the stage name
3. Return immediately — do NOT proceed to later stages
4. The `generated_code` field should still be populated if code gen ran (i.e., scan-input passed but scan-output blocked)
5. The `sandbox_result` field should be undefined/absent if execution was gated

**New probe: AI-INJ-14 (Gated Pipeline Effectiveness)**

Create `packages/ai-agent/src/probes/ai-inj-14.ts` that runs the same payload set as AI-INJ-13 but with gates ON (`scanInput: "block"`, `scanOutput: "block"`, `scanTrace: "block"`). This produces the headline metric: "With LlamaFirewall as a blocking gate, X/15 previously-successful injections are stopped before code ever executes in the Dynamic Worker."

Compare the AI-INJ-14 results against the AI-INJ-13 results (observability mode) to confirm the same verdicts — the gates shouldn't change what the scanners detect, only whether execution proceeds.

### Future context: shart.cloud lab

This gated pipeline is the backend for an interactive lab on shart.cloud where users toggle defense layers and try prompt injection attacks against a chatbot backed by Workers AI + Dynamic Workers. The lab will call the same `runAiAgent()` function with user-configurable `guard` options. The existing `packages/llamafirewall/` container and all the `ai-agent` infrastructure will be reused — the shart.cloud platform's `lab-worker` will make service-binding calls to the ai-agent or host its own copy of the pipeline with the same bindings.

This means the gated pipeline must be clean, well-typed, and the `AiAgentRunResult.guard_results` must contain everything the frontend needs to render a scanner trace panel (per-scanner decisions, scores, latencies, reasons, and the overall gate action).

---

## Code Style & Conventions

- TypeScript strict mode, no `any` unless interfacing with Workers AI types that lack proper definitions (mark with `// @ts-expect-error` or `as any` + comment explaining why)
- Plain `Worker.fetch` handlers with manual path routing in the LlamaFirewall and prompt-guard Workers (no Hono).
- pnpm workspaces; shared types in `@wulf/shared`
- All probe results follow the `ProbeResult` interface from `@wulf/shared`
- Probe files named `ai-inj-XX.ts`, exported from `probes/index.ts`
- Helper functions in `probes/_helpers.ts`
- Guard/scanner helpers in separate files: `llamafirewall.ts`, `guard.ts`, `guard-llg3.ts`
- Container Python code: FastAPI + Pydantic, standard Python conventions
- Semgrep rules in YAML following Semgrep's rule schema

## Build & Deploy

```bash
# From repo root
pnpm install
pnpm -r typecheck

# Deploy a specific package
cd packages/ai-agent && pnpm deploy
cd packages/llamafirewall && pnpm deploy

# Build llamafirewall container (needs HF_TOKEN for gated PG2 model)
cd packages/llamafirewall/container
docker build --build-arg HF_TOKEN=hf_xxx -t wulf-llamafirewall:v1 .

# Push container image
CLOUDFLARE_ACCOUNT_ID=11caecd272df7dbdcc636034c25b1f1c \
  npx wrangler containers push registry.cloudflare.com/11caecd272df7dbdcc636034c25b1f1c/wulf-llamafirewall:v1

# Run harness
cd packages/harness && pnpm start -- --track ai --probe AI-INJ-14
```

## File Locations Quick Reference

| What | Where |
|---|---|
| AI agent orchestrator | `packages/ai-agent/src/agent.ts` |
| System prompt tiers | `packages/ai-agent/src/prompts.ts` |
| AST validator | `packages/ai-agent/src/validator.ts` |
| Dynamic Worker loader types | `packages/ai-agent/src/loader.ts` |
| LlamaFirewall helpers | `packages/ai-agent/src/llamafirewall.ts` |
| PG2 helpers | `packages/ai-agent/src/guard.ts` |
| Llama Guard 3 helpers | `packages/ai-agent/src/guard-llg3.ts` |
| Probe implementations | `packages/ai-agent/src/probes/ai-inj-*.ts` |
| Probe helpers | `packages/ai-agent/src/probes/_helpers.ts` |
| Probe registry | `packages/ai-agent/src/probes/index.ts` |
| LlamaFirewall container server | `packages/llamafirewall/container/server.py` |
| Custom scanners (AlignmentCheck fix) | `packages/llamafirewall/container/wulf_scanners.py` |
| Custom Semgrep rules | `packages/llamafirewall/container/wulf-rules.yml` |
| LlamaFirewall DO (TypeScript) | `packages/llamafirewall/src/index.ts` |
| Harness results | `packages/harness/results/` |
| AI-INJ probe spec | `AI_SPEC.md` |
| Guard comparison plan | `GUARD_COMPARISON_PLAN.md` |
| Wrangler config (ai-agent) | `packages/ai-agent/wrangler.toml` |
| Wrangler config (llamafirewall) | `packages/llamafirewall/wrangler.toml` |
