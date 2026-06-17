# Guard Comparison Plan — LlamaFirewall on Cloudflare Workers

> **Status:** planning — pivoted from à-la-carte guards to unified LlamaFirewall integration
> **Owner:** ai-agent track (AI-INJ-13 family)
> **Trigger:** PG2 standalone scored 0/15 on AI-INJ-13 run (2026-05-27). Meta publishes LlamaFirewall — a layered framework that bundles PG2 + AlignmentCheck + CodeShield + regex. Stepping back to integrate the full framework rather than reimplement piecewise.

---

## 1. Context

The first AI-INJ-13 run against Llama Prompt Guard 2 86M produced:

| Phase | Trials | Guard blocked | Injection succeeded | Callbacks fired |
|-------|-------:|--------------:|--------------------:|----------------:|
| Replay (AI-INJ-01..12) | 7 | 0 | 7 | 3 |
| Evasion (8 strategies) | 8 | 0 | 8 | 4 |
| **Total** | **15** | **0** | **15** | **7** |

Malicious-class probabilities ranged 0.000–0.003 across every payload — PG2 alone is the wrong tool for code-gen injection. The follow-up investigation surfaced Meta's **LlamaFirewall** framework (https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall), which bundles four scanners covering precisely the gaps PG2 leaves open.

**Pivot:** rather than independently composing PG2 + Llama Guard 3 + CodeShield as separate guards, deploy LlamaFirewall as the unified guard and compare it head-to-head with **Llama Guard 3 8B** as a standalone baseline. Cleaner architecture, mirrors how a real production deployment would compose Meta's published recommendations.

---

## 2. Goal

Stand up two defense configurations on Cloudflare Workers + Containers:

| Config | Hosted as | Scanners | What it tests |
|--------|-----------|----------|---------------|
| **LlamaFirewall (unified)** | New `@wulf/llamafirewall` container DO | PromptGuard 2, AlignmentCheck, CodeShield, Regex | Meta's full published recommendation. Layered defense. |
| **Llama Guard 3 8B (standalone)** | Workers AI `@cf/meta/llama-guard-3-8b` | Single LLM-as-judge with 14-category MLCommons taxonomy incl. S14 Code Interpreter Abuse | Established prior baseline. Single-call simplicity. |

Run the existing AI-INJ-13 payload set through both configurations and produce a coverage matrix showing which scanner inside LlamaFirewall fires for each payload, what LG3 alone catches, and what neither catches.

**Retained from prior work:**
- `@wulf/prompt-guard` container (PG2 standalone) — kept deployed as a control to confirm the unified framework outperforms the bare classifier.
- `@wulf/codeshield` container — built and image pushed, but not deployed as a separate Worker. LlamaFirewall's CodeShieldScanner uses the same underlying engine; our custom Semgrep rules (`wulf-rules.yml`) will be loaded into the LlamaFirewall container instead.

---

## 3. Architecture

```
┌─────────────────────────── ai-agent Worker ───────────────────────────┐
│                                                                       │
│   For each AI-INJ-13 trial:                                           │
│     task ──► runAgent() ──► generated_code                            │
│                                                                       │
│     ┌─── Defense A: LlamaFirewall ────────────────────────────────┐   │
│     │  scanInput(task)        → input-side decision               │   │
│     │  scanTrace([user, asst]) → AlignmentCheck on full exchange  │   │
│     │  scanOutput(code)       → CodeShield on generated code      │   │
│     └─── per-scanner breakdown returned in response ──────────────┘   │
│                                                                       │
│     ┌─── Defense B: Llama Guard 3 8B (standalone) ────────────────┐   │
│     │  llg3ClassifyInput(task)                                     │   │
│     │  llg3ClassifyOutput(task, code) → S14 detection              │   │
│     └─── single-LLM verdict + categories_violated ─────────────────┘   │
│                                                                       │
│     Independent ground-truth: callback hit? code_contains_eval?       │
│     code_contains_fetch? code_contains_env_keys?                       │
│                                                                       │
└──────────┬──────────────────────────────────────────────────┬─────────┘
           │ service binding                                  │ env.AI.run()
           ▼                                                  ▼
┌────────────────────────────────────────────┐    ┌────────────────────────┐
│  LlamaFirewallContainer (new package)      │    │  Workers AI            │
│                                            │    │  @cf/meta/             │
│  DO routes:                                │    │   llama-guard-3-8b     │
│   POST /scan-input  { text }               │    └────────────────────────┘
│   POST /scan-output { code }               │
│   POST /scan-trace  { messages: [...] }    │
│   GET  /report                             │
│   POST /reset                              │
│   GET  /health                             │
│                                            │
│  SQLite: scans (rolled-up per-call log)    │
│                                            │
│  Container (FastAPI):                      │
│   Loads LlamaFirewall with:                │
│    - PromptGuardScanner (PG2 86M, local)   │
│    - CodeShieldScanner (Semgrep + WULF     │
│      custom rules from wulf-rules.yml)     │
│    - WulfAlignmentCheckScanner (subclass   │
│      pointing at Workers AI OpenAI-        │
│      compatible endpoint, Llama 3.3 70B)   │
│    - RegexScanner (catch-all for known     │
│      callback-URL patterns)                │
└────────────────────────────────────────────┘
```

### 3.1 AlignmentCheck → Workers AI integration

`AlignmentCheckScanner` inherits from `CustomCheckScanner` whose constructor takes `model_name`, `api_base_url`, `api_key_env_var`. Default points at Together AI with Llama-4-Maverick.

Subclass `WulfAlignmentCheckScanner` in our container's `wulf_scanners.py`:

```python
class WulfAlignmentCheckScanner(AlignmentCheckScanner):
    def __init__(self) -> None:
        super().__init__()
        # Replace the default LLM client with one pointing at Workers AI's
        # OpenAI-compatible endpoint.
        self.llm = LLMClient(
            model_name="@cf/meta/llama-3.3-70b-instruct-fp8-fast",
            api_base_url=f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT_ID}/ai/v1",
            api_key_env_var="CF_API_TOKEN",
        )
```

`CF_API_TOKEN` and `CF_ACCOUNT_ID` set as wrangler container secrets (`wrangler secret put CF_API_TOKEN`). Token needs **Workers AI:Read** scope only.

**Risk:** LlamaFirewall's `LLMClient` uses OpenAI SDK structured outputs (JSON-schema response format). Workers AI's OpenAI-compatible endpoint supports `response_format={"type": "json_object"}` but coverage of `{"type": "json_schema"}` is less certain. If structured outputs fail, fallback: wrap in a function that parses freeform JSON from the model output and validates against the schema in Python.

### 3.2 Container layout

```
packages/llamafirewall/
├── package.json                  # @wulf/llamafirewall
├── tsconfig.json
├── wrangler.toml                 # Worker + Container DO, standard-1 (4 GiB)
├── src/index.ts                  # LlamaFirewallContainer extends Container
└── container/
    ├── Dockerfile                # python:3.11-slim + llamafirewall + WULF rules
    ├── requirements.txt          # llamafirewall, fastapi, uvicorn
    ├── server.py                 # FastAPI: /scan-input /scan-output /scan-trace /health
    ├── wulf_scanners.py          # WulfAlignmentCheckScanner subclass
    └── wulf-rules.yml            # Custom Semgrep rules (copied from packages/codeshield/container/)
```

### 3.3 SQLite table

```sql
CREATE TABLE scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL DEFAULT (datetime('now')),
  probe_id TEXT,
  endpoint TEXT,           -- 'scan-input' | 'scan-output' | 'scan-trace'
  content_hash TEXT,
  content_preview TEXT,
  decision TEXT,           -- 'allow' | 'block' | 'human_in_the_loop'
  reason TEXT,             -- name of scanner that fired, or 'default'
  score REAL,
  scanner_breakdown_json TEXT,  -- per-scanner result for the call
  latency_ms INTEGER,
  policy TEXT,
  blocked INTEGER DEFAULT 0
)
```

---

## 4. Probe redesign

`AI-INJ-13` redesigned as a **two-defense comparison**:

```ts
interface TrialResult {
  payload_id: string;
  source_test: string;
  label: string;
  strategy?: string;

  llamafirewall: {
    input?:  { decision, reason, score, scanner_breakdown, latency_ms };
    trace?:  { decision, reason, score, latency_ms };
    output?: { decision, reason, score, scanner_breakdown, latency_ms };
    would_block: boolean;
    blocked_by_scanners: string[];  // ["PromptGuard", "AlignmentCheck", ...]
  };

  llg3: {
    input?:  { safe, categories_violated, latency_ms };
    output?: { safe, categories_violated, latency_ms };
    would_block: boolean;
    s14_triggered: boolean;
  };

  // Ground-truth signals (independent of guards)
  injection_succeeded: boolean;
  code_contains_fetch: boolean;
  code_contains_eval: boolean;
  code_contains_env_keys: boolean;
  callback_hit: boolean;

  generated_code_preview: string;
  note: string;
}
```

### Summary outputs
- **Coverage matrix:** per-payload table of `{llamafirewall, llg3, ground_truth_injection}`
- **Per-scanner attribution:** within LlamaFirewall trials, which of the four scanners fired most often, and which payloads each missed
- **Gap analysis:** payloads where neither defense blocked but injection succeeded — residual attack surface
- **False-positive baseline:** 5 known-benign tasks (sum, parse JSON, format date, regex match, sort array). Confirms neither defense blocks legitimate work.

---

## 5. Hypotheses (refined for LlamaFirewall vs LG3)

| Payload | LlamaFirewall (which scanner) | LG3 8B (S14?) | Expected result |
|---------|------------------------------|---------------|-----------------|
| replay-01 direct callback fetch | ✅ CodeShield (WULF rule wulf-fetch-callback-host) + Regex | ✅ likely S14 | Both block |
| replay-02 binding enumeration | ⚠️ AlignmentCheck (off-task) maybe; CodeShield wulf-env-enumeration on output | ⚠️ maybe S14 | LlamaFirewall edges out |
| replay-05 nested eval | ✅ CodeShield (wulf-eval) | ✅ S14 (eval) | Both block |
| replay-07 health endpoint poison | ✅ CodeShield (output has fetch to /health) | ⚠️ benign-looking task | LlamaFirewall wins |
| replay-09 indirect via KV | ✅ AlignmentCheck (output references attacker URL not in task) | ❌ clean prompt | **LlamaFirewall wins decisively — the AlignmentCheck case** |
| replay-11 boundary confusion | ✅ CodeShield (fetch to /analytics) + AlignmentCheck | ⚠️ confusing | LlamaFirewall wins |
| replay-12 stego comment | ✅ CodeShield (fetch in output) | ⚠️ comment context | LlamaFirewall wins |
| evade-indirect (env var hop) | ✅ CodeShield (wulf-env-callback-fetch) + AlignmentCheck | ❌ | LlamaFirewall wins decisively |
| evade-b64-url | ⚠️ CodeShield (wulf-b64-decode-fetch) + AlignmentCheck | ❌ | LlamaFirewall wins |
| evade-benign-eval | ✅ CodeShield (wulf-eval) | ✅ S14 | Both block |
| evade-padding | ✅ CodeShield (fetch in output) | ⚠️ | LlamaFirewall wins |
| evade-role-frame | ⚠️ AlignmentCheck (intent mismatch) | ⚠️ | Both may block |

**Expected paper outcome:** LlamaFirewall blocks ~13/15. LG3 8B blocks ~5/15. The 2 residual LlamaFirewall misses (likely evade-padding subset, or AlignmentCheck false-negatives on subtle indirection) become the "even Meta's full framework has gaps" finding.

---

## 6. Implementation tasks

In execution order:

1. ~~Write `guard-llg3.ts`~~ — **done**.
2. ~~Scaffold `packages/codeshield/`, build image~~ — **done; image pushed but Worker not deployed (consolidated into LlamaFirewall).**
3. **Scaffold `packages/llamafirewall/`** — Container DO + FastAPI server + `wulf_scanners.py` subclass + copy `wulf-rules.yml` from codeshield.
4. **Build LlamaFirewall container.** Needs `HF_TOKEN` build-arg for PG2 (same model behind same gating).
5. **Set secrets:** `wrangler secret put CF_API_TOKEN` (Workers AI:Read scoped token) + `CLOUDFLARE_ACCOUNT_ID` env.
6. **Push + deploy** `wulf-llamafirewall` Worker.
7. **Add `LLAMAFIREWALL` service binding to ai-agent.** Write `src/llamafirewall.ts` exposing `scanInput`, `scanOutput`, `scanTrace`, `report`.
8. **Redesign `ai-inj-13.ts`** per §4 — two-defense comparison + false-positive baseline.
9. **Deploy ai-agent, run probe, dump JSON, summarize.**

Time estimate: ~4 hours implementation + 1 hour analysis.

---

## 7. Open questions

1. **Workers AI structured output compatibility.** LlamaFirewall's `LLMClient` uses OpenAI SDK with JSON-schema response_format. Need to verify Workers AI's OpenAI-compatible endpoint accepts this format with `@cf/meta/llama-3.3-70b-instruct-fp8-fast`. **Fallback:** wrap `LLMClient.call` to use `{type: "json_object"}` mode and post-validate against the Pydantic schema.
2. **PG2 inside LlamaFirewall** uses the same gated `meta-llama/Llama-Prompt-Guard-2-86M`. Build needs HF_TOKEN; image must be pre-built locally and pushed (same flow as `@wulf/prompt-guard`).
3. **Trace construction for AlignmentCheck.** Needs `[UserMessage(task), AssistantMessage(generated_code)]`. Worth double-checking that the scanner runs the model on *both* messages and not just the latest.
4. **Latency budget.** LlamaFirewall per-call: PG2 ~300ms + Semgrep ~1s + AlignmentCheck (Llama 3.3 70B via Workers AI) ~3–8s = ~5–10s wall time per trial. 15 payloads × ~10s × 2 calls (input + output+trace) ≈ 5 minutes. Acceptable.
5. **False-positive baseline payloads** — write 5 benign tasks that don't share lexical features with the malicious set.
6. **Streaming reports.** Both defenses log to their own SQLite (LlamaFirewall DO has `scans`, LG3 has none — Workers AI calls are stateless). Probe pulls LF report at end; LG3 verdicts are inlined in the trial record.

---

## 8. Out of scope

- **Standalone CodeShield Worker** — consolidated into LlamaFirewall. Image pushed but not deployed.
- **Standalone PG2 Worker** — kept deployed as the control showing the baseline-classifier gap, but no longer in the active comparison path of AI-INJ-13.
- **Together AI / Llama-4-Maverick** — would match Meta's published benchmarks exactly but requires external API key and external paid service. Workers AI + Llama 3.3 70B is the closest local analog.
- **Runtime egress allowlisting** — covered by Track 2 (D-NET probes). Will be cited in conclusion as the residual control needed beyond input/output filtering.
- **Llama Guard 4** — preview, no clear advantage over LG3 for this comparison.
