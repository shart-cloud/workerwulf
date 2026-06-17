# Research Prompt — LlamaFirewall AlignmentCheck on Cloudflare Workers AI

> Hand this to another agent or researcher who has not seen our conversation.
> Self-contained — includes goal, prior work, the actual error, and what we need.

## Goal

We're integrating Meta's [LlamaFirewall](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall) (v1.0.3 from PyPI) into a research project on Cloudflare Workers + Containers. Three scanners (PromptGuard 2, CodeShield, a regex scanner) work fine. The fourth — **AlignmentCheckScanner** — needs an OpenAI-compatible LLM backend and we want to point it at Cloudflare's Workers AI instead of the default Together AI.

After working around one quirk, AlignmentCheck still fails. We need to know what's actually breaking and the cleanest fix.

## Setup

- **Package**: `llamafirewall==1.0.3` (pypi). Source: https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall/src/llamafirewall
- **Scanner**: `llamafirewall.scanners.experimental.alignmentcheck_scanner.AlignmentCheckScanner`
- **Default model**: `meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8` via Together AI
- **Target model**: `@cf/meta/llama-3.3-70b-instruct-fp8-fast` via Cloudflare Workers AI OpenAI-compatible endpoint at `https://api.cloudflare.com/client/v4/accounts/<acct>/ai/v1`
- **Auth**: Bearer token (`CF_API_TOKEN`), `Workers AI:Read` scope
- **SDK**: `openai` Python package (whatever version `llamafirewall==1.0.3` pulls in; `>=1.76.0` per its constraint)

## What we've already confirmed works

1. **Raw Workers AI call** via OpenAI SDK works fine — `client.chat.completions.create(model="@cf/meta/llama-3.3-70b-instruct-fp8-fast", messages=[{"role":"user","content":"Say READY"}])` returns `READY` in ~1.9s with HTTP 200.
2. **All other LlamaFirewall scanners run normally** in the same container. PromptGuard 2 loads from HF and classifies. CodeShield runs Semgrep. RegexScanner matches.

## Quirk #1 (worked around): Workers AI returns dict, not JSON string

LlamaFirewall's `LLMClient.call` uses `self.client.beta.chat.completions.parse(model=..., messages=..., response_format=<PydanticModel>, ...)`. Inside the OpenAI SDK, `.parse()` eventually calls `model.model_validate_json(message.content)`, which expects a JSON *string*.

Workers AI's OpenAI-compat endpoint returns `message.content` as **a parsed dict** instead of a JSON string. The SDK then errors:

```
pydantic_core._pydantic_core.ValidationError: 1 validation error for TestSchema
  JSON input should be string, bytes or bytearray [type=json_type, input_value={'observation': 'hi', 'conclusion': True}, input_type=dict]
```

Our workaround: subclass `LLMClient` with a `WulfLLMClient` that bypasses `.parse()` — calls plain `.create()` with `response_format=type_to_response_format_param(schema)`, then handles either dict or string content manually:

```python
from openai.lib._parsing._completions import type_to_response_format_param
from llamafirewall.utils.base_llm import LLMClient

class WulfLLMClient(LLMClient):
    async def call(self, prompt, system_prompt, output_schema, temperature=0.0, additional_messages=None):
        messages = [{"role": "system", "content": system_prompt}, {"role": "user", "content": prompt}]
        if additional_messages:
            messages.extend(additional_messages)
        response_format = type_to_response_format_param(output_schema)
        # NOTE: LlamaFirewall's LLMClient uses a sync OpenAI client; do not await.
        resp = self.client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            response_format=response_format,
            temperature=temperature,
        )
        content = resp.choices[0].message.content
        if isinstance(content, dict):
            return output_schema(**content)
        if isinstance(content, str):
            try:
                return output_schema.model_validate_json(content)
            except Exception:
                stripped = content.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
                return output_schema(**json.loads(stripped))
        raise ValueError(f"Unexpected content type: {type(content)!r}")
```

Direct probe of `WulfLLMClient.call(...)` with `AlignmentCheckOutputSchema`: **still fails**. We don't have the actual exception because `CustomCheckScanner._evaluate_with_llm` catches and swallows it, returning `_get_default_error_response()` which produces:

```json
{
  "decision": "human_in_the_loop_required",
  "reason": "Observation: Error occurred during evaluation\nThought: Due to an error, treating as potentially compromised for safety\nConclusion: True",
  "score": 1.0
}
```

(That `human_in_the_loop_required` is LlamaFirewall's *default error response* — it's not actually requesting human review; it's the scanner saying "the LLM call blew up, I am bailing safely.")

## What we need

1. **Capture the actual exception** raised inside `WulfLLMClient.call` when invoked with `AlignmentCheckOutputSchema`. The exception is currently being eaten by `CustomCheckScanner._evaluate_with_llm`'s try/except. Options:
   - Monkey-patch `_evaluate_with_llm` to re-raise / write to stderr with traceback.
   - Add explicit logging *inside* `WulfLLMClient.call` (top of try block, before each method call) and capture container stderr.
   - Add a `/debug/wulf-llm` endpoint that calls `WulfLLMClient` directly without going through the scanner.

   The first failure path will tell us whether it's:
   - Workers AI rejecting the `response_format={"type":"json_schema", ...}` shape entirely
   - Returning a different content shape than dict/string (e.g., None, or wrapped in `tool_calls`)
   - Returning a malformed dict that doesn't conform to the schema
   - A timeout / rate-limit / 4xx we're not handling

2. **Verify Workers AI's structured output behavior**. Does the OpenAI-compat endpoint at `https://api.cloudflare.com/client/v4/accounts/<acct>/ai/v1` support:
   - `response_format={"type": "json_object"}` (loose JSON mode)?
   - `response_format={"type": "json_schema", "json_schema": {"name": "...", "schema": {...}, "strict": true}}` (strict structured outputs)?
   - With `@cf/meta/llama-3.3-70b-instruct-fp8-fast` specifically?

   Sources: Cloudflare's OpenAI-compatibility docs at https://developers.cloudflare.com/workers-ai/configuration/open-ai-compatibility/, plus any changelog notes on structured-output rollout for individual models.

3. **Recommend the cleanest fix**. Options to evaluate:
   - Keep the `WulfLLMClient` subclass approach — once we know the actual failure, patch around it.
   - Skip structured output entirely: use `response_format={"type": "json_object"}` + parse content as JSON manually + validate against Pydantic.
   - Free-form prompt with the schema embedded in `system_prompt`, then `json.loads` + `model_validate` locally.
   - Bypass the OpenAI-compat endpoint and call Workers AI's native REST API (`/run/@cf/meta/llama-3.3-70b-instruct-fp8-fast`) directly. Native API has different request/response shapes; we'd lose drop-in compatibility but might dodge the structured-output issues.

4. **Bonus**: Is there a known-good combination (model + response_format mode) on Workers AI that supports strict structured outputs as of 2026-05-28?

   *(Note: Llama-4-Maverick is NOT available on Workers AI, so matching Meta's published AlignmentCheck benchmarks exactly via Workers AI is off the table. Our options are Workers AI alternatives — Llama 3.3 70B, Llama 3.1 8B, etc. — or Together AI as a side comparison.)*

## Constraints
- We're calling from inside a Cloudflare Container fronted by a Durable Object. The container's egress reaches the public Workers AI endpoint over HTTPS. The token is passed in via container env var `CF_API_TOKEN` (read from a Worker secret by the DO at container startup).
- The fix should not require us to fork or vendor `llamafirewall`. A subclass / monkey-patch in our own `wulf_scanners.py` is fine.
- Bonus points if the fix doesn't require switching off Workers AI (we want the research story to be "we deployed LlamaFirewall on the Cloudflare stack end-to-end").

## Deliverables
1. The exact exception raised during `WulfLLMClient.call(...)` with `AlignmentCheckOutputSchema`, with full traceback.
2. A short determination of which `response_format` modes Workers AI actually supports (citing CF docs).
3. A working `WulfLLMClient.call` (or alternative) that returns valid `AlignmentCheckOutputSchema` instances when given a real trace.
4. Brief recommendation on whether to stick with structured output, fall back to JSON-object mode, or call native Workers AI.
