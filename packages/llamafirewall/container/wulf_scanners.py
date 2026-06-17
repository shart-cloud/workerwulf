"""WULF-specific scanner subclasses for LlamaFirewall.

  - WulfAlignmentCheckScanner: AlignmentCheckScanner pointed at Workers AI.
  - WulfRegexScanner: RegexScanner with extra patterns for WULF callback hosts.
  - WulfLLMClient: LLMClient using Workers AI in `json_object` mode with the
    response schema embedded in the system prompt. See
    docs/research-alignmentcheck.md for the rationale: Workers AI's
    OpenAI-compat endpoint does NOT accept the SDK's
    {name, strict, schema}-wrapped response_format that .parse() sends, so
    structured outputs via beta.chat.completions.parse fail. json_object mode
    works reliably; we hand-validate the response against Pydantic.
"""

import json
import logging
import os
import re
from typing import Optional, Type, TypeVar

from llamafirewall.scanners.experimental.alignmentcheck_scanner import (  # type: ignore
    AlignmentCheckScanner,
)
from llamafirewall.scanners.regex_scanner import RegexScanner  # type: ignore
from llamafirewall.utils.base_llm import LLMClient  # type: ignore
from openai import OpenAI  # type: ignore
from pydantic import BaseModel

LOG = logging.getLogger("wulf-scanners")

OutputSchemaT = TypeVar("OutputSchemaT", bound=BaseModel)


CF_ACCOUNT_ID = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "")
WORKERS_AI_BASE_URL = (
    f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT_ID}/ai/v1"
    if CF_ACCOUNT_ID
    else "https://api.cloudflare.com/client/v4/accounts/MISSING_ACCOUNT_ID/ai/v1"
)
WORKERS_AI_MODEL = os.environ.get(
    "WULF_ALIGNMENT_MODEL", "@cf/meta/llama-3.3-70b-instruct-fp8-fast"
)


WULF_PATTERNS = {
    "WULF callback host": r"(callback\.wulf|x\.wulf|wulf\.shart\.cloud)",
    "WULF exfil path": r"/exfil/ai-inj-\d+",
    # `eval()` and `new Function(string)` — arbitrary code execution sinks.
    # CodeShield's default JS ruleset doesn't flag these (verified 2026-05-28).
    "WULF eval": r"\beval\s*\(",
    "WULF Function constructor": r"\bnew\s+Function\s*\(",
    # Binding enumeration: iterating over `env` reveals available bindings/secrets.
    # Matches Object.keys(env), Object.entries(env), Reflect.ownKeys(env), for…in env.
    "WULF env enumeration": r"(Object\.(keys|values|entries)|Reflect\.ownKeys)\s*\(\s*env\s*\)|for\s*\(\s*(const|let|var)\s+\w+\s+(in|of\s+Object\.keys\s*\(\s*env\s*\))\s+env\s*\)",
}


class WulfRegexScanner(RegexScanner):
    def __init__(self) -> None:
        super().__init__(scanner_name="WULF Regex Scanner")
        for name, pattern in WULF_PATTERNS.items():
            try:
                self.patterns[name] = re.compile(pattern, re.IGNORECASE | re.DOTALL)
            except re.error as e:
                print(f"[WulfRegexScanner] Invalid pattern {name!r}: {e}")

    def match_names(self, text: str) -> list[str]:
        """Return regex pattern names that match `text` for report attribution."""
        matches: list[str] = []
        for name, pattern in self.patterns.items():
            if pattern.search(text):
                matches.append(name)
        return matches


class WulfLLMClient(LLMClient):
    """Workers AI client using json_object mode + schema-in-prompt.

    AlignmentCheck calls `self.llm.call(prompt, system_prompt, output_schema, ...)`
    expecting a Pydantic instance back. We satisfy that contract without going
    through OpenAI SDK's `.parse()` (which sends a `response_format` shape that
    Workers AI rejects).
    """

    def __init__(self) -> None:
        # Bypass LLMClient.__init__: it constructs an OpenAI client around an
        # api_key_env_var check that we don't want. We build our own client.
        self.model_name = WORKERS_AI_MODEL
        api_key = os.environ.get("CF_API_TOKEN", "")
        self.client = OpenAI(api_key=api_key, base_url=WORKERS_AI_BASE_URL)
        LOG.info(
            "[WulfLLMClient] initialized model=%s base=%s token_present=%s",
            self.model_name, WORKERS_AI_BASE_URL, bool(api_key),
        )

    async def call(  # type: ignore[override]
        self,
        prompt: str,
        system_prompt: str,
        output_schema: Type[OutputSchemaT],
        temperature: float = 0.0,
        additional_messages: Optional[list[dict[str, str]]] = None,
    ) -> OutputSchemaT:
        schema_json = json.dumps(output_schema.model_json_schema(), indent=2)
        augmented_system = (
            f"{system_prompt}\n\n"
            f"You MUST respond with ONLY a valid JSON object matching this schema:\n"
            f"```json\n{schema_json}\n```\n"
            f"Do not include any other text, markdown fences, or explanation. "
            f"For boolean fields, use true/false (not strings)."
        )

        messages: list[dict[str, str]] = [
            {"role": "system", "content": augmented_system},
            {"role": "user", "content": prompt},
        ]
        if additional_messages:
            messages.extend(additional_messages)

        LOG.info(
            "[WulfLLMClient] calling %s (prompt_len=%d, schema=%s)",
            self.model_name, len(prompt), output_schema.__name__,
        )

        # LlamaFirewall's LLMClient is synchronous; do not await.
        resp = self.client.chat.completions.create(
            model=self.model_name,
            messages=messages,  # type: ignore[arg-type]
            response_format={"type": "json_object"},
            temperature=temperature,
        )
        content = resp.choices[0].message.content
        LOG.info(
            "[WulfLLMClient] response type=%s preview=%s",
            type(content).__name__, str(content)[:200] if content else "(None)",
        )

        if content is None:
            raise ValueError("Workers AI returned None content")

        # CF sometimes returns dict (their OpenAI-compat layer pre-parses JSON).
        if isinstance(content, dict):
            return _coerce_and_build(output_schema, content)

        if isinstance(content, str):
            # Direct validation first.
            try:
                return output_schema.model_validate_json(content)
            except Exception:
                pass
            # Strip optional markdown fences.
            cleaned = (
                content.strip()
                .removeprefix("```json")
                .removeprefix("```")
                .removesuffix("```")
                .strip()
            )
            data = json.loads(cleaned)
            return _coerce_and_build(output_schema, data)

        raise ValueError(f"Unexpected content type: {type(content)!r}")


def _coerce_and_build(schema: Type[OutputSchemaT], data: dict) -> OutputSchemaT:
    """Coerce common LLM JSON quirks (string booleans, etc.) before Pydantic validation."""
    # Stringy booleans → bool. Common from Llama models.
    for k, v in list(data.items()):
        if isinstance(v, str) and v.strip().lower() in {"true", "yes", "1"}:
            data[k] = True
        elif isinstance(v, str) and v.strip().lower() in {"false", "no", "0"}:
            data[k] = False
    return schema(**data)


class WulfAlignmentCheckScanner(AlignmentCheckScanner):
    """AlignmentCheckScanner routed at Workers AI via WulfLLMClient."""

    def __init__(self) -> None:
        # AlignmentCheckScanner → CustomCheckScanner constructs an LLMClient at
        # init time and verifies api_key_env_var. We don't use it; satisfy the
        # check with a placeholder, then swap in WulfLLMClient.
        os.environ.setdefault("TOGETHER_API_KEY", "unused-placeholder")
        super().__init__()
        self.llm = WulfLLMClient()
