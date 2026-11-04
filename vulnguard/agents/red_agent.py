"""
Red Agent — Threat analyzer & PoC exploit generator.

Receives high-risk flagged code with context, analyzes vulnerabilities,
and generates structured threat reports with synthetic PoC exploit payloads.
Includes NO_VULNERABILITY_FOUND exit state (Section 4.1 FP exit) and
language-match validation (EC-7.2).

Generation is split into two bounded model calls:

  1. **Diagnosis** — a compact JSON object (type, CWE, severity, short
     explanation). Its output is small, so reasoning-enabled models cannot
     burn the whole budget before the diagnosis is complete.
  2. **Harness** — a minimal proof of concept, produced only when a defect is
     reported. If this step truncates or produces an invalid harness, the
     diagnosis is preserved and the exploit is reported as unavailable — it is
     never invented and never discarded silently.
"""

from __future__ import annotations

import ast
import json
import logging
import re
import time
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field
from typing import Optional

from vulnguard.agents.state import VulnGuardState
from vulnguard.config import cfg

logger = logging.getLogger(__name__)

# ── Dangerous payload patterns (Section 4.3) ─────────────────────────────
_DANGEROUS_PATTERNS = re.compile(
    r"rm\s+-rf\s+/|fork\s*\(\s*\)|:\(\)\s*\{|dd\s+if=|mkfs\.|"
    r"shutdown|reboot|format\s+[cCdD]:",
    re.IGNORECASE,
)

# Language → expected code markers for exploit validation (EC-7.2)
_LANGUAGE_MARKERS = {
    "c": [r"#include|int\s+main|printf|malloc|free"],
    "cpp": [r"#include|int\s+main|std::|cout|cin"],
    "python": [r"def\s+|import\s+|print\s*\(|if\s+__name__"],
    "java": [r"public\s+class|System\.out|import\s+java"],
    "javascript": [r"const\s+|let\s+|var\s+|function\s+|require\s*\(|console\.log"],
}

# A parse failure is retried once with a corrective prompt. Provider-level
# retries/truncation escalation already happen inside `_call_llm`, so this
# keeps the total number of paid calls bounded.
_PARSE_ATTEMPTS = 2


# ── Pydantic output schemas ──────────────────────────────────────────────

class RedAgentDiagnosis(BaseModel):
    """Compact vulnerability diagnosis — no code in the response."""

    vulnerability_found: bool = Field(description="Whether a vulnerability was identified")
    vulnerability_type: Optional[str] = Field(None, description="E.g. SQL_INJECTION, BUFFER_OVERFLOW, XSS")
    cwe_id: Optional[str] = Field(None, description="CWE identifier, e.g. CWE-89")
    severity: Optional[str] = Field(None, description="CRITICAL, HIGH, MEDIUM, or LOW")
    affected_lines: Optional[list[int]] = Field(None, description="Line numbers containing the defect")
    explanation: Optional[str] = Field(None, description="Short technical explanation of the defect")
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0, description="Confidence score 0.0-1.0")


class RedAgentHarness(BaseModel):
    """Minimal executable proof of concept for a diagnosed defect."""

    exploit_type: Optional[str] = Field(None, description="Language of the exploit: python_script, c_harness, shell_command")
    exploit_code_harness: Optional[str] = Field(None, description="Executable proof-of-concept code")
    expected_stdout_regex: Optional[str] = Field(None, description="Regex matching the success marker")


class RedAgentReport(RedAgentDiagnosis):
    """Merged report persisted on the pipeline state.

    Kept as the single normalized shape consumed by the Blue and Judge agents,
    so downstream code does not need to know generation was split in two.
    """

    exploit_type: Optional[str] = None
    exploit_code_harness: Optional[str] = None
    expected_stdout_regex: Optional[str] = None


# ── Prompt construction ──────────────────────────────────────────────────

_DIAGNOSIS_SYSTEM_PROMPT = """\
You are a senior software engineer and QA specialist focusing on code correctness and data integrity.

Analyze the supplied function for a data-flow defect (for example untrusted string interpolation in a query, or an out-of-bounds memory access).

RULES:
1. If the function operates correctly on all inputs, set vulnerability_found=false.
2. If a defect exists, name the exact defect, the affected lines, and the input shape that proves it.
3. Be concise: the explanation is at most 120 words of plain prose. Do not restate the source, do not include code blocks, and do not propose a fix.
4. Do NOT write an exploit or test harness here; a separate step does that.
5. Only report a defect you can justify from the supplied code and context. Set confidence honestly.

Your JSON output MUST conform to this schema (output data, not the schema itself):
{schema}
"""

_DIAGNOSIS_USER_PROMPT = """\
## Target Function
File: {file_path}
Language: {language}

```{language}
{code}
```

## Context Bundle
{context}

Diagnose this function. Return only the diagnosis JSON object.
"""

_COMPACT_DIAGNOSIS_PROMPT = """\
The previous response was cut off because it was too long. Answer with the smallest possible JSON object and nothing else:

{{"vulnerability_found": true|false, "vulnerability_type": "TYPE_OR_NULL", "explanation": "max 40 words", "confidence": 0.0}}

Target ({language}), file {file_path}:
```{language}
{code}
```
"""

_HARNESS_SYSTEM_PROMPT = """\
You are a security test engineer. Write a MINIMAL proof-of-concept harness for the vulnerability described by the user.

RULES:
1. The harness must be valid {language} source and at most 80 lines.
2. It MUST import and invoke the real target from the supplied workspace. Do NOT copy, restate, or redefine the target function.
3. The harness may only create benign prerequisites (temporary database schemas, rows, files, environment values). It must never run a destructive system command and must never attack anything outside the sandbox.
4. It must print the success marker ONLY after the security defect is proven. The marker must not appear inside attacker-controlled input or in data printed by the target.
5. For command injection, use a benign isolated side effect (for example a file under /tmp), verify it, then print the marker.
6. expected_stdout_regex must uniquely match that marker. A harness without it is invalid.
7. The assertion must succeed against the original vulnerable source and fail against a secure patch.
8. Do NOT add third-party dependencies.

Return only this JSON object:
{{"exploit_type": "python_script|c_harness|shell_command", "exploit_code_harness": "...", "expected_stdout_regex": "..."}}
"""

_HARNESS_USER_PROMPT = """\
## Diagnosed Vulnerability
Type: {vuln_type}
CWE: {cwe_id}
Severity: {severity}
Affected lines: {affected_lines}
Explanation: {explanation}

## Target Function ({language})
File: {file_path}
Workspace target: {workspace_target}

```{language}
{code}
```

## Context Bundle
{context}

Write the proof-of-concept harness JSON for this exact target.
"""

_HARNESS_CORRECTION_PROMPT = """\
Your previous harness was rejected: {reason}

Regenerate it in {language}. It must import and invoke the supplied workspace target, must not redefine target code, must not treat arbitrary exceptions as proof of exploitation, and must print the marker only after the defect is actually proven.
"""


def _schema_json(schema: type[BaseModel]) -> str:
    """Compact schema rendering — prompt tokens are cheaper than output tokens."""
    return json.dumps(schema.model_json_schema(), separators=(",", ":"))


def _context_text(state: VulnGuardState) -> str:
    from vulnguard.data.context_gatherer import ContextBundle

    ctx_dict = state.get("context_bundle", {})
    if not ctx_dict:
        return "(No context available)"
    return ContextBundle(**ctx_dict).to_prompt_text()


def _diagnosis_messages(state: VulnGuardState, *, compact: bool = False) -> list[dict[str, str]]:
    if compact:
        return [
            {
                "role": "user",
                "content": _COMPACT_DIAGNOSIS_PROMPT.format(
                    language=state["language"],
                    file_path=state.get("file_path", "unknown"),
                    code=state["original_code"],
                ),
            }
        ]
    return [
        {
            "role": "system",
            "content": _DIAGNOSIS_SYSTEM_PROMPT.format(
                language=state["language"],
                schema=_schema_json(RedAgentDiagnosis),
            ),
        },
        {
            "role": "user",
            "content": _DIAGNOSIS_USER_PROMPT.format(
                file_path=state.get("file_path", "unknown"),
                language=state["language"],
                code=state["original_code"],
                context=_context_text(state),
            ),
        },
    ]


def _harness_messages(state: VulnGuardState, diagnosis: RedAgentDiagnosis) -> list[dict[str, str]]:
    return [
        {"role": "system", "content": _HARNESS_SYSTEM_PROMPT.format(language=state["language"])},
        {
            "role": "user",
            "content": _HARNESS_USER_PROMPT.format(
                vuln_type=diagnosis.vulnerability_type or "unknown",
                cwe_id=diagnosis.cwe_id or "unknown",
                severity=diagnosis.severity or "unknown",
                affected_lines=diagnosis.affected_lines or "unknown",
                explanation=diagnosis.explanation or "",
                language=state["language"],
                file_path=state.get("file_path", "unknown"),
                workspace_target=_workspace_target_instruction(state),
                code=state["original_code"],
                context=_context_text(state),
            ),
        },
    ]


# ── LLM invocation ───────────────────────────────────────────────────────

def _call_llm(
    messages: list[dict],
    risk_score: float = 100.0,
    retries: int | None = None,
    *,
    base_max_tokens: int | None = None,
) -> str:
    """Call the LLM with bounded backoff, severity-based routing and escalation.

    Delegates to `vulnguard.agents.llm_calls.call_llm_json`, which raises
    typed `LLMTruncationError` / `LLMProviderError` once the budget is spent.
    """
    if cfg.llm.mock_mode:
        logger.info("Mock LLM enabled. Returning synthetic Red Agent response.")
        return json.dumps(
            {
                "vulnerability_found": True,
                "vulnerability_type": "MOCK_VULN",
                "cwe_id": "CWE-999",
                "severity": "HIGH",
                "affected_lines": [1, 2],
                "explanation": "Mock vulnerability reported by the mock Red Agent.",
                "confidence": 0.95,
            }
        )

    from vulnguard.agents.llm_calls import call_llm_json

    provider, model_name = cfg.routing.get_model_for_score(risk_score)
    logger.info("Model routing: risk=%.1f → %s/%s", risk_score, provider, model_name)
    return call_llm_json(
        messages,
        model=f"{provider}/{model_name}",
        attempts=retries if retries is not None else cfg.llm.max_retries,
        base_max_tokens=base_max_tokens or cfg.llm.max_tokens,
        temperature=cfg.llm.temperature,
        ceiling=cfg.llm.max_token_ceiling,
        timeout=cfg.llm.request_timeout_seconds,
        retry_base_delay=cfg.llm.retry_base_delay_seconds,
    )


# ── Validation ────────────────────────────────────────────────────────────

def _validate_exploit_language(report: RedAgentReport, target_language: str) -> bool:
    """Check if exploit code matches target language (EC-7.2)."""
    if not report.exploit_code_harness:
        return True

    markers = _LANGUAGE_MARKERS.get(target_language, [])
    if not markers:
        return True  # Unknown language — skip check

    pattern = "|".join(markers)
    return bool(re.search(pattern, report.exploit_code_harness))


def _python_target_import(state: VulnGuardState) -> tuple[str, str]:
    """Return the importable module and symbol that owns the target function."""
    file_path = state.get("file_path", "")
    target_name = state.get("function_id", "").rsplit(":", 1)[-1]
    module_name = Path(file_path).stem if file_path else "target_module"
    repo_root = state.get("repo_root", "")
    if file_path and repo_root:
        try:
            relative = Path(file_path).resolve().relative_to(Path(repo_root).resolve())
            module_name = ".".join(relative.with_suffix("").parts)
            if module_name.endswith(".__init__"):
                module_name = module_name.removesuffix(".__init__")
        except ValueError:
            pass

    owner = target_name
    try:
        source = Path(file_path).read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source)
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and any(
                isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                and child.name == target_name
                for child in node.body
            ):
                owner = node.name
                break
    except (OSError, SyntaxError):
        pass

    return module_name, owner


def _workspace_target_instruction(state: VulnGuardState) -> str:
    if state.get("language") != "python":
        return "Compile/link the harness with the supplied workspace source file."

    module_name, owner = _python_target_import(state)
    target_name = state.get("function_id", "").rsplit(":", 1)[-1]
    if owner == target_name:
        return f"Use `from {module_name} import {target_name}` and invoke `{target_name}`."
    return (
        f"Use `from {module_name} import {owner}`, instantiate `{owner}`, "
        f"and invoke its `{target_name}` method."
    )


def _exploit_validation_error(report: RedAgentReport, state: VulnGuardState) -> str | None:
    """Reject Python PoCs that do not exercise the uploaded target module."""
    harness = report.exploit_code_harness
    if not harness:
        return None
    if not report.expected_stdout_regex:
        return "the harness has no expected_stdout_regex success signal"
    if not _validate_exploit_language(report, state.get("language", "")):
        return f"the harness does not match target language '{state.get('language', '')}'"
    if state.get("language") != "python":
        return None

    try:
        tree = ast.parse(harness)
    except SyntaxError:
        return "the Python exploit harness is not valid syntax"

    target_name = state.get("function_id", "").rsplit(":", 1)[-1]
    if target_name and any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == target_name
        for node in ast.walk(tree)
    ):
        return f"the harness redefines target '{target_name}' instead of importing it"

    module_name, owner = _python_target_import(state)
    imports_target = any(
        isinstance(node, ast.ImportFrom)
        and node.module == module_name
        and any(alias.name in {owner, "*"} for alias in node.names)
        for node in ast.walk(tree)
    ) or any(
        isinstance(node, ast.Import)
        and any(alias.name == module_name for alias in node.names)
        for node in ast.walk(tree)
    )
    if not imports_target:
        return f"the harness must import '{owner}' from workspace module '{module_name}'"

    expected = report.expected_stdout_regex
    if expected:
        if re.fullmatch(r"[A-Za-z0-9_ -]+", expected):
            embedded_marker = any(
                expected in node.value and node.value.strip() != expected
                for node in ast.walk(tree)
                if isinstance(node, ast.Constant) and isinstance(node.value, str)
            )
            if embedded_marker:
                return "the success marker is embedded in exploit input, causing false positives"

        for handler in (node for node in ast.walk(tree) if isinstance(node, ast.ExceptHandler)):
            catches_any = handler.type is None or (
                isinstance(handler.type, ast.Name)
                and handler.type.id in {"Exception", "BaseException"}
            )
            if catches_any:
                strings = (
                    node.value
                    for statement in handler.body
                    for node in ast.walk(statement)
                    if isinstance(node, ast.Constant) and isinstance(node.value, str)
                )
                try:
                    if any(re.search(expected, value) for value in strings):
                        return "the harness reports success for any exception, causing false positives"
                except re.error:
                    return "expected_stdout_regex is not a valid regular expression"

    return None


def _sanitize_exploit(report: RedAgentReport) -> RedAgentReport:
    """Remove dangerous patterns from exploit code (Section 4.3)."""
    if report.exploit_code_harness and _DANGEROUS_PATTERNS.search(report.exploit_code_harness):
        logger.warning("Dangerous payload detected in exploit — sanitizing")
        report.exploit_code_harness = "// DANGEROUS PAYLOAD REMOVED — re-prompt needed"
        report.confidence = 0.0
    return report


# ── Generation helpers ────────────────────────────────────────────────────

def _parse_with_repair(
    messages: list[dict[str, str]],
    schema: type[BaseModel],
    *,
    risk_score: float,
    corrective: str,
    max_tokens: int | None = None,
) -> tuple[Any | None, str, str]:
    """Call the model and parse it, retrying once with a corrective prompt.

    Returns ``(instance | None, failure_reason, raw_text)``. Provider errors
    propagate as typed `LLMCallError` so the caller can decide what to do.
    """
    from vulnguard.agents.llm_parsing import parse_agent_json, raw_response_preview

    raw = ""
    parse_error = ""
    current = list(messages)
    for attempt in range(1, _PARSE_ATTEMPTS + 1):
        # The first attempt owns the full provider retry budget; the corrective
        # attempt is a single call so nested retries stay bounded.
        raw = _call_llm(
            current,
            risk_score=risk_score,
            retries=cfg.llm.max_retries if attempt == 1 else 1,
            base_max_tokens=max_tokens,
        )
        instance, parse_error = parse_agent_json(raw, schema)
        if instance is not None:
            return instance, "", raw

        logger.error(
            "Unparseable %s response (attempt %d/%d): %s",
            schema.__name__,
            attempt,
            _PARSE_ATTEMPTS,
            parse_error,
        )
        logger.error("RAW RESPONSE: %s", raw_response_preview(raw))
        if attempt < _PARSE_ATTEMPTS:
            current = current + [
                {"role": "assistant", "content": raw},
                {"role": "user", "content": corrective.format(parse_error=parse_error)},
            ]
    return None, parse_error, raw


def _diagnose(state: VulnGuardState, risk_score: float) -> tuple[RedAgentDiagnosis | None, str, str]:
    """Produce a diagnosis, falling back to a compact request on truncation."""
    from vulnguard.agents.llm_calls import LLMCallError, LLMTruncationError
    from vulnguard.agents.llm_parsing import raw_response_preview

    corrective = (
        "Your previous response was not valid JSON matching the requested schema "
        "(parsing failed: {parse_error}). Respond again with ONLY a single complete "
        "JSON object matching the schema exactly — no prose and no code."
    )
    try:
        diagnosis, error, raw = _parse_with_repair(
            _diagnosis_messages(state),
            RedAgentDiagnosis,
            risk_score=risk_score,
            corrective=corrective,
        )
        if diagnosis is not None:
            return diagnosis, "", raw
        # A truncated or malformed full diagnosis gets one compact retry: the
        # payload is small enough that it cannot exhaust the output budget.
        logger.warning("Full diagnosis unusable (%s) — retrying in compact mode", error)
    except LLMTruncationError as exc:
        logger.warning("Diagnosis truncated (%s) — retrying in compact mode", exc)
    except LLMCallError as exc:
        return None, str(exc), getattr(exc, "partial_response", "")

    try:
        diagnosis, error, raw = _parse_with_repair(
            _diagnosis_messages(state, compact=True),
            RedAgentDiagnosis,
            risk_score=risk_score,
            corrective=corrective,
        )
    except LLMCallError as exc:
        return None, str(exc), getattr(exc, "partial_response", "")

    if diagnosis is None:
        preview = raw_response_preview(raw)
        return None, error, preview
    return diagnosis, "", raw


def _generate_harness(
    state: VulnGuardState,
    diagnosis: RedAgentDiagnosis,
    risk_score: float,
) -> tuple[RedAgentHarness | None, str]:
    """Produce and validate a proof of concept, or an honest reason it is absent."""
    from vulnguard.agents.llm_calls import LLMCallError
    from vulnguard.agents.llm_parsing import parse_agent_json

    corrective = (
        "Your previous harness was not valid JSON matching the requested schema "
        "(parsing failed: {parse_error}). Respond again with ONLY the JSON object."
    )
    try:
        harness, error, raw = _parse_with_repair(
            _harness_messages(state, diagnosis),
            RedAgentHarness,
            risk_score=risk_score,
            corrective=corrective,
        )
    except LLMCallError as exc:
        return None, str(exc)

    if harness is None:
        return None, f"harness response was not parseable: {error}"
    if not harness.exploit_code_harness:
        return None, "the model did not provide an exploit harness"

    merged = RedAgentReport(**diagnosis.model_dump(), **harness.model_dump())
    validation_error = _exploit_validation_error(merged, state)
    if validation_error is None:
        return harness, ""

    logger.warning("Invalid exploit harness (%s) — re-prompting once", validation_error)
    retry_messages = _harness_messages(state, diagnosis) + [
        {"role": "assistant", "content": raw},
        {
            "role": "user",
            "content": _HARNESS_CORRECTION_PROMPT.format(
                reason=validation_error, language=state["language"]
            ),
        },
    ]
    try:
        retry_raw = _call_llm(retry_messages, risk_score=risk_score, retries=1)
    except LLMCallError as exc:
        return None, f"{validation_error}; corrected harness unavailable: {exc}"

    retry_harness, retry_error = parse_agent_json(retry_raw, RedAgentHarness)
    if retry_harness is None:
        return None, f"{validation_error}; corrected harness unparseable: {retry_error}"

    merged = RedAgentReport(**diagnosis.model_dump(), **retry_harness.model_dump())
    retry_validation_error = _exploit_validation_error(merged, state)
    if retry_validation_error:
        return None, f"{validation_error}; corrected harness still invalid: {retry_validation_error}"
    return retry_harness, ""


# ── LangGraph node function ──────────────────────────────────────────────

def _error_update(
    function_id: str,
    message: str,
    *,
    parse_error: str = "",
    raw: str = "",
    timestamps: dict,
) -> dict[str, Any]:
    """Typed, non-crashing failure result for the graph."""
    logger.error("🔴 Red Agent could not analyze %s: %s", function_id, message)
    red_report: dict[str, Any] = {"parse_error": parse_error or message}
    if raw:
        red_report["raw"] = raw
    return {
        "red_report": red_report,
        "vulnerability_found": False,
        "exploit_harness": None,
        "exploit_type": None,
        "expected_stdout_regex": None,
        "exploit_status": "ERROR",
        "exploit_error": message,
        "judge_verdict": "RED_AGENT_ERROR",
        "pipeline_status": "RED_ERROR",
        "error_logs": message,
        "timestamps": timestamps,
    }


def red_agent_node(state: VulnGuardState) -> dict[str, Any]:
    """LangGraph node: Run Red Agent analysis.

    Returns partial state update dict. Every failure path is converted into an
    explicit state update; this node never raises, so one failed function can
    never crash the scan stream.
    """
    logger.info("🔴 Red Agent analyzing function: %s", state["function_id"])
    start = time.time()
    # `red_end` is stamped on each return so it reflects the actual completion.
    timestamps = dict(state.get("timestamps", {}))
    risk_score = state.get("risk_score", 100.0)

    try:
        diagnosis, error, raw = _diagnose(state, risk_score)
        if diagnosis is None:
            return _error_update(
                state["function_id"],
                error or "the model did not return a usable diagnosis",
                raw=raw,
                timestamps={**timestamps, "red_end": time.time()},
            )

        if not diagnosis.vulnerability_found:
            elapsed = time.time() - start
            logger.info("🔴 Red Agent: no vulnerability found (%.1fs)", elapsed)
            return {
                "red_report": RedAgentReport(**diagnosis.model_dump()).model_dump(),
                "vulnerability_found": False,
                "exploit_harness": None,
                "exploit_type": None,
                "expected_stdout_regex": None,
                "exploit_status": "NONE",
                "exploit_error": None,
                "pipeline_status": "RED_COMPLETE",
                "timestamps": {**timestamps, "red_end": time.time()},
            }

        # ── Exploit generation — never allowed to discard the diagnosis ──
        harness, harness_error = _generate_harness(state, diagnosis, risk_score)
        report = RedAgentReport(
            **diagnosis.model_dump(), **(harness.model_dump() if harness else {})
        )

        if harness is None or not harness.exploit_code_harness:
            logger.warning(
                "🔴 Diagnosis kept, exploit unavailable for %s: %s",
                state["function_id"],
                harness_error or "no harness returned",
            )
            exploit_status = "INVALID" if harness_error else "UNAVAILABLE"
        elif report.exploit_code_harness and _DANGEROUS_PATTERNS.search(
            report.exploit_code_harness
        ):
            report = _sanitize_exploit(report)
            exploit_status = "INVALID"
            harness_error = "the harness contained a destructive command and was removed"
        else:
            exploit_status = "AVAILABLE"

        elapsed = time.time() - start
        logger.info(
            "🔴 Red Agent result: vulnerability_found=%s, type=%s, severity=%s, exploit=%s (%.1fs)",
            report.vulnerability_found,
            report.vulnerability_type,
            report.severity,
            exploit_status,
            elapsed,
        )

        return {
            "red_report": report.model_dump(),
            "vulnerability_found": True,
            "exploit_harness": report.exploit_code_harness,
            "exploit_type": report.exploit_type,
            "expected_stdout_regex": report.expected_stdout_regex,
            "exploit_status": exploit_status,
            "exploit_error": harness_error or None,
            "pipeline_status": "RED_COMPLETE",
            "timestamps": {**timestamps, "red_end": time.time()},
        }
    except Exception as exc:  # defensive: no agent exception escapes to the graph
        logger.exception("🔴 Red Agent failed unexpectedly for %s", state.get("function_id"))
        return _error_update(
            state.get("function_id", "unknown"),
            f"Red Agent internal error: {exc}",
            timestamps={**timestamps, "red_end": time.time()},
        )
