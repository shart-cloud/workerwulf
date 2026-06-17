"""CodeShield + custom Semgrep rules — static analysis of LLM-generated code."""

import asyncio
import json
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel

# Meta's Purple Llama CodeShield. Wraps Insecure Code Detector (rule-based).
try:
    from codeshield.cs import CodeShield  # type: ignore
    CODESHIELD_AVAILABLE = True
except Exception as e:  # pragma: no cover
    CODESHIELD_AVAILABLE = False
    CODESHIELD_IMPORT_ERR = str(e)

app = FastAPI()

WULF_RULES_PATH = Path(__file__).parent / "wulf-rules.yml"


class ScanRequest(BaseModel):
    code: str
    language: Optional[str] = "javascript"


class Issue(BaseModel):
    rule_id: str
    severity: str   # "info" | "warning" | "error"
    line: Optional[int] = None
    message: str
    cwe: Optional[str] = None
    source: str     # "codeshield" | "wulf-semgrep"


class ScanResponse(BaseModel):
    issues: list[Issue]
    severity_max: Optional[str] = None
    count_by_severity: dict[str, int]
    latency_ms: int


SEV_RANK = {"info": 1, "warning": 2, "error": 3}


def _normalize_severity(s: str) -> str:
    s = (s or "").lower()
    if s in ("error", "high", "critical"):
        return "error"
    if s in ("warning", "medium", "warn"):
        return "warning"
    return "info"


async def _scan_codeshield(code: str) -> list[Issue]:
    if not CODESHIELD_AVAILABLE:
        return []
    try:
        result = await CodeShield.scan_code(code)
        out: list[Issue] = []
        for issue in getattr(result, "issues_found", []) or []:
            sev = _normalize_severity(getattr(issue, "severity", "warning"))
            out.append(
                Issue(
                    rule_id=str(getattr(issue, "pattern_id", "codeshield-unknown")),
                    severity=sev,
                    line=getattr(issue, "line", None),
                    message=str(getattr(issue, "description", "")) or "CodeShield issue",
                    cwe=getattr(issue, "cwe_id", None),
                    source="codeshield",
                )
            )
        return out
    except Exception as e:  # pragma: no cover
        return [
            Issue(
                rule_id="codeshield-error",
                severity="info",
                message=f"CodeShield scan failed: {e}",
                source="codeshield",
            )
        ]


def _scan_wulf_semgrep(code: str, language: str) -> list[Issue]:
    """Run our custom rules via Semgrep CLI."""
    ext = {"javascript": ".js", "typescript": ".ts"}.get(language, ".js")
    with tempfile.NamedTemporaryFile("w", suffix=ext, delete=False) as tmp:
        tmp.write(code)
        tmp_path = tmp.name

    try:
        proc = subprocess.run(
            [
                "semgrep",
                "scan",
                "--config", str(WULF_RULES_PATH),
                "--json",
                "--quiet",
                "--no-git-ignore",
                "--disable-version-check",
                "--metrics", "off",
                tmp_path,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return [Issue(rule_id="wulf-semgrep-timeout", severity="info",
                      message="Semgrep timed out", source="wulf-semgrep")]
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    if not proc.stdout:
        return []

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return [Issue(rule_id="wulf-semgrep-parse-error", severity="info",
                      message="Failed to parse semgrep JSON output", source="wulf-semgrep")]

    out: list[Issue] = []
    for r in data.get("results", []):
        meta = r.get("extra", {}).get("metadata", {}) or {}
        sev = _normalize_severity(r.get("extra", {}).get("severity", "warning"))
        out.append(
            Issue(
                rule_id=str(r.get("check_id", "wulf-unknown")).split(".")[-1],
                severity=sev,
                line=r.get("start", {}).get("line"),
                message=r.get("extra", {}).get("message", "match"),
                cwe=meta.get("cwe"),
                source="wulf-semgrep",
            )
        )
    return out


@app.on_event("startup")
def on_startup():
    if not CODESHIELD_AVAILABLE:
        print(f"WARN: codeshield not available: {CODESHIELD_IMPORT_ERR}", flush=True)
    print(f"WULF rules path: {WULF_RULES_PATH} (exists={WULF_RULES_PATH.exists()})", flush=True)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "codeshield_available": CODESHIELD_AVAILABLE,
        "wulf_rules_loaded": WULF_RULES_PATH.exists(),
    }


@app.post("/scan", response_model=ScanResponse)
async def scan(req: ScanRequest):
    t0 = time.monotonic()

    cs_task = asyncio.create_task(_scan_codeshield(req.code))
    # Run Semgrep in a thread since it's a blocking subprocess.
    wulf_task = asyncio.to_thread(_scan_wulf_semgrep, req.code, req.language or "javascript")

    cs_issues, wulf_issues = await asyncio.gather(cs_task, wulf_task)
    issues = cs_issues + wulf_issues

    count_by_severity = {"info": 0, "warning": 0, "error": 0}
    for i in issues:
        count_by_severity[i.severity] = count_by_severity.get(i.severity, 0) + 1

    severity_max: Optional[str] = None
    max_rank = 0
    for i in issues:
        r = SEV_RANK.get(i.severity, 0)
        if r > max_rank:
            max_rank = r
            severity_max = i.severity

    latency_ms = int((time.monotonic() - t0) * 1000)

    return ScanResponse(
        issues=issues,
        severity_max=severity_max,
        count_by_severity=count_by_severity,
        latency_ms=latency_ms,
    )
