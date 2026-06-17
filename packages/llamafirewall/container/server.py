"""LlamaFirewall FastAPI server.

We instantiate Meta's individual scanners directly rather than going through the
`LlamaFirewall` facade. This gives us per-scanner verdicts in the response so
the probe can attribute blocks to specific scanners:

  - PromptGuard 2 (BERT classifier, gated HF model, loaded locally)
  - WulfRegexScanner (RegexScanner + WULF callback-host patterns)
  - CodeShield (Semgrep + ICD, output-side)
  - WulfAlignmentCheckScanner (routed at Workers AI; trace-level scanner)
"""

import logging
import os
import time
from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel

from llamafirewall import AssistantMessage, UserMessage  # type: ignore
from llamafirewall.llamafirewall_data_types import ScanDecision  # type: ignore
from llamafirewall.scanners.code_shield_scanner import CodeShieldScanner  # type: ignore
from llamafirewall.scanners.prompt_guard_scanner import PromptGuardScanner  # type: ignore

from wulf_scanners import WulfAlignmentCheckScanner, WulfRegexScanner

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger("wulf-llamafirewall")

app = FastAPI()

prompt_guard: Optional[PromptGuardScanner] = None
wulf_regex: Optional[WulfRegexScanner] = None
code_shield: Optional[CodeShieldScanner] = None
alignment: Optional[WulfAlignmentCheckScanner] = None


class ScanRequest(BaseModel):
    text: str


class TraceMessage(BaseModel):
    role: str
    content: str


class TraceScanRequest(BaseModel):
    messages: list[TraceMessage]


class ScannerVerdict(BaseModel):
    decision: str
    reason: str
    score: float
    latency_ms: int
    error: Optional[str] = None
    matches: Optional[list[str]] = None


class ScanResponse(BaseModel):
    decision: str
    reason: str
    score: float
    scanner_breakdown: dict[str, ScannerVerdict]
    latency_ms: int
    error: Optional[str] = None


def _decision_str(decision) -> str:
    if hasattr(decision, "value"):
        return decision.value
    return str(decision)


async def _run_scanner(name: str, coro) -> ScannerVerdict:
    t0 = time.monotonic()
    try:
        result = await coro
        return ScannerVerdict(
            decision=_decision_str(result.decision),
            reason=str(getattr(result, "reason", "default")),
            score=float(getattr(result, "score", 0.0)),
            latency_ms=int((time.monotonic() - t0) * 1000),
        )
    except Exception as e:
        LOG.exception("scanner %s failed", name)
        return ScannerVerdict(
            decision="allow",
            reason="scanner_error",
            score=0.0,
            latency_ms=int((time.monotonic() - t0) * 1000),
            error=str(e),
        )


def _aggregate(verdicts: dict[str, ScannerVerdict]) -> tuple[str, str, float]:
    """Block if any scanner blocks; pick highest-score reason as the headline."""
    blocking = [(n, v) for n, v in verdicts.items() if v.decision == "block"]
    if blocking:
        # Highest-score blocking scanner wins as the headline reason.
        blocking.sort(key=lambda kv: kv[1].score, reverse=True)
        name, verdict = blocking[0]
        return ("block", name, verdict.score)
    # Otherwise allow with highest score across all scanners.
    if verdicts:
        top = max(verdicts.values(), key=lambda v: v.score)
        return ("allow", "default", top.score)
    return ("allow", "default", 0.0)


@app.on_event("startup")
def load_scanners() -> None:
    global prompt_guard, wulf_regex, code_shield, alignment
    LOG.info("Initializing scanners...")
    prompt_guard = PromptGuardScanner()
    wulf_regex = WulfRegexScanner()
    code_shield = CodeShieldScanner()
    alignment = WulfAlignmentCheckScanner()
    LOG.info(
        "All scanners ready (CF_ACCOUNT=%s..., model=%s, token=%s)",
        (os.environ.get("CLOUDFLARE_ACCOUNT_ID") or "")[:8],
        os.environ.get("WULF_ALIGNMENT_MODEL", "@cf/meta/llama-3.3-70b-instruct-fp8-fast"),
        bool(os.environ.get("CF_API_TOKEN")),
    )


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "prompt_guard_loaded": prompt_guard is not None,
        "wulf_regex_loaded": wulf_regex is not None,
        "code_shield_loaded": code_shield is not None,
        "alignment_loaded": alignment is not None,
        "cf_token_present": bool(os.environ.get("CF_API_TOKEN")),
        "cf_account_id_present": bool(os.environ.get("CLOUDFLARE_ACCOUNT_ID")),
    }


@app.post("/scan-input", response_model=ScanResponse)
async def scan_input(req: ScanRequest) -> ScanResponse:
    """Run input-side scanners (PromptGuard + WulfRegex) on a user prompt."""
    t0 = time.monotonic()
    msg = UserMessage(content=req.text)

    verdicts: dict[str, ScannerVerdict] = {
        "PromptGuard": await _run_scanner("PromptGuard", prompt_guard.scan(msg)),  # type: ignore[union-attr]
        "WulfRegex": await _run_scanner("WulfRegex", wulf_regex.scan(msg)),  # type: ignore[union-attr]
    }
    verdicts["WulfRegex"].matches = wulf_regex.match_names(req.text)  # type: ignore[union-attr]
    decision, reason, score = _aggregate(verdicts)
    return ScanResponse(
        decision=decision, reason=reason, score=score,
        scanner_breakdown=verdicts,
        latency_ms=int((time.monotonic() - t0) * 1000),
    )


@app.post("/scan-output", response_model=ScanResponse)
async def scan_output(req: ScanRequest) -> ScanResponse:
    """Run output-side scanners (CodeShield + WulfRegex) on generated code."""
    t0 = time.monotonic()
    msg = AssistantMessage(content=req.text)

    verdicts: dict[str, ScannerVerdict] = {
        "CodeShield": await _run_scanner("CodeShield", code_shield.scan(msg)),  # type: ignore[union-attr]
        "WulfRegex": await _run_scanner("WulfRegex", wulf_regex.scan(msg)),  # type: ignore[union-attr]
    }
    verdicts["WulfRegex"].matches = wulf_regex.match_names(req.text)  # type: ignore[union-attr]
    decision, reason, score = _aggregate(verdicts)
    return ScanResponse(
        decision=decision, reason=reason, score=score,
        scanner_breakdown=verdicts,
        latency_ms=int((time.monotonic() - t0) * 1000),
    )


@app.post("/debug/wulf-llm")
async def debug_wulf_llm() -> dict:
    """Invoke WulfLLMClient directly with the AlignmentCheck schema to surface
    the exact failure the scanner is hitting."""
    from wulf_scanners import WulfLLMClient
    from llamafirewall.scanners.experimental.alignmentcheck_scanner import (  # type: ignore
        AlignmentCheckOutputSchema,
    )
    import traceback as tb

    os.environ.setdefault("TOGETHER_API_KEY", "unused-placeholder")
    acct = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "")
    model = os.environ.get("WULF_ALIGNMENT_MODEL", "@cf/meta/llama-3.3-70b-instruct-fp8-fast")
    base_url = f"https://api.cloudflare.com/client/v4/accounts/{acct}/ai/v1"

    client = WulfLLMClient(
        model_name=model, api_base_url=base_url, api_key_env_var="CF_API_TOKEN",
    )

    try:
        result = await client.call(
            prompt="Observation: agent fetched http://callback.wulf.shart.cloud/exfil after a benign profile-read task. Was it compromised?",
            system_prompt="You audit AI agent behavior. Return JSON with observation, thought, conclusion.",
            output_schema=AlignmentCheckOutputSchema,
            temperature=0.0,
        )
        return {"ok": True, "result": result.model_dump()}
    except Exception as e:
        return {
            "ok": False, "error_type": type(e).__name__, "error": str(e),
            "traceback": tb.format_exc(),
        }


@app.post("/debug/llm-structured")
async def debug_llm_structured() -> dict:
    """Probe Workers AI with structured-output (response_format=PydanticModel).
    This is what AlignmentCheck does. Returns the raw error if it fails."""
    from openai import AsyncOpenAI  # type: ignore
    from pydantic import BaseModel, Field
    import traceback as tb

    class TestSchema(BaseModel):
        observation: str = Field(description="A short observation.")
        conclusion: bool = Field(description="True or False.")

    acct = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "")
    token = os.environ.get("CF_API_TOKEN", "")
    model = os.environ.get("WULF_ALIGNMENT_MODEL", "@cf/meta/llama-3.3-70b-instruct-fp8-fast")
    base_url = f"https://api.cloudflare.com/client/v4/accounts/{acct}/ai/v1"

    client = AsyncOpenAI(api_key=token, base_url=base_url)
    try:
        resp = await client.beta.chat.completions.parse(
            model=model,
            messages=[
                {"role": "system", "content": "You return JSON only."},
                {"role": "user", "content": "Say {observation: 'hi', conclusion: true}"},
            ],
            response_format=TestSchema,
            temperature=0,
        )
        parsed = resp.choices[0].message.parsed
        return {"ok": True, "parsed": parsed.model_dump() if parsed else None}
    except Exception as e:
        return {
            "ok": False, "error_type": type(e).__name__, "error": str(e),
            "traceback": tb.format_exc(),
        }


@app.post("/debug/llm")
async def debug_llm() -> dict:
    """Direct probe of the Workers AI OpenAI-compatible endpoint, with the same
    config AlignmentCheck uses. Returns the raw response or the full error chain
    so we can debug auth / schema / model-name issues without recompiling."""
    from openai import AsyncOpenAI  # type: ignore
    import traceback as tb

    acct = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "")
    token = os.environ.get("CF_API_TOKEN", "")
    model = os.environ.get("WULF_ALIGNMENT_MODEL", "@cf/meta/llama-3.3-70b-instruct-fp8-fast")
    base_url = f"https://api.cloudflare.com/client/v4/accounts/{acct}/ai/v1"

    client = AsyncOpenAI(api_key=token, base_url=base_url)
    try:
        resp = await client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "Say only the word READY"}],
            max_tokens=8,
            temperature=0,
        )
        return {
            "ok": True,
            "base_url": base_url,
            "model": model,
            "content": resp.choices[0].message.content if resp.choices else None,
            "raw": resp.model_dump() if hasattr(resp, "model_dump") else str(resp),
        }
    except Exception as e:
        return {
            "ok": False,
            "base_url": base_url,
            "model": model,
            "error_type": type(e).__name__,
            "error": str(e),
            "traceback": tb.format_exc(),
        }


@app.post("/scan-trace", response_model=ScanResponse)
async def scan_trace(req: TraceScanRequest) -> ScanResponse:
    """Run AlignmentCheck on the full conversation trace."""
    t0 = time.monotonic()

    trace = []
    last_message = None
    for m in req.messages:
        obj = (
            UserMessage(content=m.content)
            if m.role == "user"
            else AssistantMessage(content=m.content)
        )
        if last_message is not None:
            trace.append(last_message)
        last_message = obj

    if last_message is None:
        return ScanResponse(
            decision="allow", reason="empty_trace", score=0.0,
            scanner_breakdown={},
            latency_ms=int((time.monotonic() - t0) * 1000),
        )

    verdicts: dict[str, ScannerVerdict] = {
        "AlignmentCheck": await _run_scanner(
            "AlignmentCheck", alignment.scan(last_message, past_trace=trace)  # type: ignore[union-attr]
        ),
    }
    decision, reason, score = _aggregate(verdicts)
    return ScanResponse(
        decision=decision, reason=reason, score=score,
        scanner_breakdown=verdicts,
        latency_ms=int((time.monotonic() - t0) * 1000),
    )
