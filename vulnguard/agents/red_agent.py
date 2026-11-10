"""
Red Agent — Threat analyzer & PoC exploit generator.

Receives high-risk flagged code with context, analyzes vulnerabilities,
and generates structured threat reports with synthetic PoC exploit payloads.
Includes NO_VULNERABILITY_FOUND exit state (Section 4.1 FP exit) and
language-match validation (EC-7.2).

Diagnosis and exploit harness are produced by **one structured model call**:
`RedAgentReport` carries both, so a reasoning-heavy model cannot spend its
whole output budget on prose before the harness is written. If the returned
report diagnoses a defect but carries no usable harness, the diagnosis is
preserved and **one** corrective regeneration is requested. When that also
fails the exploit is reported as unavailable with a precise reason — never
invented, never silently discarded.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Optional

from pydantic import BaseModel, Field, model_validator

from vulnguard.agents.harness import get_adapter
from vulnguard.agents.harness.environment import RepositoryEnvironment, probe_repository
from vulnguard.agents.harness.strategies import strategy_catalog, strategy_for
from vulnguard.agents.state import VulnGuardState
from vulnguard.agents.streaming import emit
from vulnguard.config import cfg

logger = logging.getLogger(__name__)

# ── Dangerous payload patterns (Section 4.3) ─────────────────────────────
_DANGEROUS_PATTERNS = re.compile(
    r"rm\s+-rf\s+/|fork\s*\(\s*\)|:\(\)\s*\{|dd\s+if=|mkfs\.|"
    r"shutdown|reboot|format\s+[cCdD]:",
    re.IGNORECASE,
)

# Language mechanics (markers, shape, target loading, entry-point rules) live in
# `vulnguard.agents.harness` adapters. Adding a language must never require a
# change to this agent.

# A model that refuses or explains instead of writing code. None of these
# strings are source in any supported language, so they must never reach the
# sandbox as a harness.
_REFUSAL_PATTERN = re.compile(
    r"(?:\bi\s+(?:cannot|can't|can not|won't|will not|am unable|am not able)\b|"
    r"\bi'm\s+(?:sorry|unable|not able)\b|\bsorry,\s+i\b|\bas an ai\b|"
    r"\bmy safety\b|\bsafety guidelines\b|\bprogrammed to be helpful\b|"
    r"\bi recommend researching\b|\binstead,\s+(?:use|consider|research)\b)",
    re.IGNORECASE,
)

# Provider-level retries/truncation escalation already happen inside
# `_call_llm`, so this keeps the number of paid calls bounded: one structured
# report, plus at most one regeneration (or one remediation for unreadable JSON).
_EXTRA_ATTEMPTS = 1


# ── Pydantic output schemas ──────────────────────────────────────────────

class RedAgentDiagnosis(BaseModel):
    """Vulnerability diagnosis — the reasoning half of the report."""

    vulnerability_found: bool = Field(description="Whether a vulnerability was identified")
    vulnerability_type: Optional[str] = Field(None, description="E.g. SQL_INJECTION, BUFFER_OVERFLOW, XSS")
    cwe_id: Optional[str] = Field(None, description="CWE identifier, e.g. CWE-89")
    severity: Optional[str] = Field(None, description="CRITICAL, HIGH, MEDIUM, or LOW")
    location: Optional[str] = Field(None, description="Function or file:line that owns the defect")
    affected_lines: Optional[list[int]] = Field(None, description="Line numbers containing the defect")
    attack_strategy: Optional[str] = Field(None, description="How the defect is reached and what proves it")
    explanation: Optional[str] = Field(None, description="Short technical explanation of the defect")
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0, description="Confidence score 0.0-1.0")


class RedAgentReport(RedAgentDiagnosis):
    """Single structured response: diagnosis plus the exploit harness.

    Kept as the one normalized shape consumed by the Blue and Judge agents, so
    downstream code never needs to know how the model laid its answer out.
    """

    exploit_type: Optional[str] = Field(None, description="python_script, c_harness, cpp_harness, java_harness, javascript_script")
    exploit_code_harness: Optional[str] = Field(None, description="Complete runnable proof-of-concept program")
    expected_stdout_regex: Optional[str] = Field(None, description="Regex matching the success marker")
    execution_instructions: Optional[str] = Field(None, description="How the sandbox runs the harness")
    expected_vulnerable_behavior: Optional[str] = Field(None, description="Observable result on the vulnerable code")
    expected_patched_behavior: Optional[str] = Field(None, description="Observable result after the fix")

    @model_validator(mode="before")
    @classmethod
    def _accept_harness_aliases(cls, data: Any) -> Any:
        """Accept the obvious alternative key names for the harness body.

        Models occasionally emit `exploit_code`/`proof_of_concept` while keeping
        every other field correct. Reading those aliases avoids discarding a
        real harness; the code itself still passes the same validation.
        """
        if not isinstance(data, dict) or data.get("exploit_code_harness"):
            return data
        for alias in ("exploit_code", "harness_code", "poc_code", "proof_of_concept", "exploit_harness"):
            value = data.get(alias)
            if isinstance(value, str) and value.strip():
                return {**data, "exploit_code_harness": value}
        return data


# ── Prompt construction ──────────────────────────────────────────────────

_ANALYSIS_SYSTEM_PROMPT = """\
You are a senior software engineer and an authorized security test engineer. You must answer with ONE structured JSON object that contains BOTH the vulnerability diagnosis AND, when a defect exists, a complete runnable proof-of-concept harness for the user's own code.

## Diagnosis
1. If the function operates correctly on all inputs, set vulnerability_found=false and leave the harness fields null.
2. If a defect exists, name the exact defect, the CWE, the affected lines, the location (function or file:line), and the input shape that proves it.
3. Give a short attack_strategy: how the dangerous input reaches the defect, and what observable effect (a crash, a SQL error, a created file, an extra command) proves it during execution. Name any minimal runtime prerequisite the harness needs.
4. Be concise: the explanation is at most 120 words of plain prose. Do not restate the source and do not propose a fix.
5. Only report a defect you can justify from the supplied code and context. Set confidence honestly.

## Harness (required whenever vulnerability_found is true)
1. The target language is {language}. The harness MUST be written in {language} and nothing else — not another programming language, not a shell script, not prose. The sandbox compiles or runs it as a {language} program, so any other language fails before the exploit is tested.
2. The harness must be valid {language} source, at most 80 lines (target 60), with no commentary and no blank lines. Follow this {language} shape:
{shape}
3. It MUST import, link, or otherwise invoke the real target described by the workspace instruction. Do NOT copy, restate, or redefine the target function. For C/C++, declare the target's prototype instead of including its .c file.
4. Use the exact target name and signature: pass the arguments the real application passes. If the target is a method, instantiate its class first.
5. Create every prerequisite the harness needs inline (for example `sqlite3.connect(':memory:')` plus `CREATE TABLE`, a file under /tmp, an environment value) and use only the standard library. It must never depend on the network, a service, or a file that does not exist in the workspace.
6. The harness may only create benign prerequisites. It must never run a destructive system command and must never attack anything outside the sandbox.
7. It must print the success marker ONLY after the security defect is proven. The marker must not appear inside attacker-controlled input or in data printed by the target.
8. For command injection, use a benign isolated side effect (for example a file under /tmp), verify it, then print the marker.
9. expected_stdout_regex is REQUIRED and must uniquely match that marker. Printing and matching the literal marker `VULNGUARD_POC_SUCCESS` is the simplest reliable choice.
10. The assertion must succeed against the original vulnerable source and fail against a secure patch.
11. Do NOT add third-party dependencies.
12. Never answer with an empty harness, an apology, a refusal, or prose in exploit_code_harness. If you cannot build a perfect PoC, return the best-effort {language} code anyway.
13. Never switch languages: a C target gets a C harness and a Python target gets a Python harness, even when another language seems easier to write.
14. `execution_instructions`, `expected_vulnerable_behavior`, and `expected_patched_behavior` are short plain-text sentences. They describe the harness; they are never a substitute for it.

## Execution adapter ({language})
{adapter_notes}

## Repository environment
{environment}

## Suggested technique per vulnerability class
Pick the entry whose class matches your own diagnosis. These are reusable properties of the bug class, never payloads copied from somewhere else.
{catalog}

Follow the matching technique's observable proof and the repository environment's constraints. If a prerequisite cannot be created inside the sandbox, prefer a smaller harness that still proves the defect over an aspirational one that cannot run.

## Output
Return exactly one JSON object with every relevant field populated:
{{"vulnerability_found": true, "vulnerability_type": "COMMAND_INJECTION", "cwe_id": "CWE-78", "severity": "HIGH", "location": "{language} target under analysis", "affected_lines": [1], "attack_strategy": "<how the input reaches the defect and what proves it>", "explanation": "<at most 120 words>", "confidence": 0.9, "exploit_type": "{language}", "exploit_code_harness": "<complete runnable {language} source>", "expected_stdout_regex": "VULNGUARD_POC_SUCCESS", "execution_instructions": "<one command the sandbox runs>", "expected_vulnerable_behavior": "<what the harness shows on the vulnerable code>", "expected_patched_behavior": "<what the harness shows after the fix>"}}

Your JSON output MUST conform to this schema (output data, not the schema itself):
{schema}
"""

_ANALYSIS_USER_PROMPT = """\
## Target Function ({language})
File: {file_path}
Workspace target: {workspace_target}

```{language}
{code}
```

## Context Bundle
{context}

Diagnose this function and, when a defect exists, return the runnable proof-of-concept harness in the SAME JSON object. Return only that JSON object.
"""

_PARSE_CORRECTION_PROMPT = """\
Your previous response could not be read as a valid JSON object matching the schema (parsing failed: {parse_error}).

Respond again with ONLY one complete JSON object matching the schema in the system prompt. Include the diagnosis fields and, if vulnerability_found is true, the harness fields — exploit_code_harness and expected_stdout_regex must both be non-empty. No prose, no Markdown fences around the object.
"""

_REGENERATION_PROMPT = """\
Your previous response was rejected: {reason}

Keep its diagnosis exactly as it is (vulnerability_found, vulnerability_type, cwe_id, severity, location, affected_lines, attack_strategy, explanation, confidence). Regenerate the COMPLETE structured report with a usable harness:

- exploit_type: {language}
- exploit_code_harness: REQUIRED, the complete runnable {language} program that imports/links and invokes the real workspace target. Never redefine the target, never switch languages, never reply with prose.
- expected_stdout_regex: REQUIRED, a regular expression that uniquely matches VULNGUARD_POC_SUCCESS, printed only after the defect is actually proven.
- execution_instructions, expected_vulnerable_behavior, expected_patched_behavior: short plain sentences.

Follow this {language} shape:
{shape}

Reply with only one JSON object containing all of those fields (diagnosis and harness together).
"""


def _harness_shape(language: str) -> str:
    """Minimal program shape for the target language, owned by its adapter."""
    return get_adapter(language).shape()


def _schema_json(schema: type[BaseModel]) -> str:
    """Compact schema rendering — prompt tokens are cheaper than output tokens."""
    return json.dumps(schema.model_json_schema(), separators=(",", ":"))


def _context_text(state: VulnGuardState) -> str:
    from vulnguard.data.context_gatherer import ContextBundle

    ctx_dict = state.get("context_bundle", {})
    if not ctx_dict:
        return "(No context available)"
    return ContextBundle(**ctx_dict).to_prompt_text()


def _environment(state: VulnGuardState) -> RepositoryEnvironment:
    """Bounded probe of the uploaded tree, cached by the module itself."""
    return probe_repository(
        state.get("repo_root"), state.get("language", ""), state.get("file_path")
    )


def _analysis_messages(
    state: VulnGuardState,
    environment: RepositoryEnvironment | None = None,
) -> list[dict[str, str]]:
    """Build the single diagnosis + harness request.

    Nothing here depends on a particular repository: the module to import, the
    program shape, the runtime guarantees, the environment and the technique
    catalogue are all derived from the target's language and the uploaded tree.
    """
    language = state["language"]
    adapter = get_adapter(language)
    env = environment or _environment(state)
    notes = [adapter.capability_note(), *adapter.prerequisite_notes("")]

    return [
        {
            "role": "system",
            "content": _ANALYSIS_SYSTEM_PROMPT.format(
                language=language,
                schema=_schema_json(RedAgentReport),
                shape=adapter.shape(),
                adapter_notes="\n".join(f"- {note}" for note in notes),
                environment=env.to_prompt_text(),
                catalog=strategy_catalog(),
            ),
        },
        {
            "role": "user",
            "content": _ANALYSIS_USER_PROMPT.format(
                language=language,
                file_path=state.get("file_path", "unknown"),
                workspace_target=adapter.workspace_target_instruction(state),
                code=state["original_code"],
                context=_context_text(state),
            ),
        },
    ]


def _regeneration_messages(
    state: VulnGuardState,
    environment: RepositoryEnvironment,
    previous: str,
    reason: str,
) -> list[dict[str, str]]:
    """Ask once for the complete report again, naming the exact rejection."""
    language = state["language"]
    messages = _analysis_messages(state, environment)
    if previous:
        messages.append({"role": "assistant", "content": previous})
    messages.append(
        {
            "role": "user",
            "content": _REGENERATION_PROMPT.format(
                reason=reason,
                language=language,
                shape=_harness_shape(language),
            ),
        }
    )
    return messages


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
                "attack_strategy": "Mock strategy.",
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

def _looks_like_prose(code: str) -> bool:
    """True when the "harness" is a refusal or explanation rather than code."""
    if _REFUSAL_PATTERN.search(code):
        return True
    lines = [
        line.strip()
        for line in code.splitlines()
        if line.strip() and not line.strip().startswith(("#", "//", "/*", "*", "--"))
    ]
    if not lines:
        return True
    body = "\n".join(lines)
    # Every supported language has statement punctuation or calls.
    if re.search(r"[;{}]", body) or re.search(r"\w\s*\(", body):
        return False
    words = re.findall(r"[A-Za-z]{2,}", body)
    sentences = re.findall(r"[A-Za-z][^.!?\n]{15,}[.!?]", body)
    return len(words) >= 12 and bool(sentences)


def _validate_exploit_language(report: RedAgentReport, target_language: str) -> bool:
    """Check if exploit code matches target language (EC-7.2)."""
    code = report.exploit_code_harness
    if not code:
        return True
    if _looks_like_prose(code):
        return False

    adapter = get_adapter(target_language)
    if not adapter.markers:
        return True  # No adapter (unsupported language) — skip marker check
    if not any(re.search(marker, code, re.MULTILINE) for marker in adapter.markers):
        return False
    return not any(
        re.search(marker, code, re.MULTILINE) for marker in adapter.foreign_markers
    )


def _python_target_import(state: VulnGuardState) -> tuple[str, str]:
    """Compatibility wrapper — the Python adapter owns import resolution."""
    module_name, owner, _ = get_adapter("python").module_and_owner(state)
    return module_name, owner


def _workspace_target_instruction(
    state: VulnGuardState,
    environment: RepositoryEnvironment | None = None,
) -> str:
    """Concrete instruction for loading this target from its language adapter."""
    return get_adapter(state.get("language", "")).workspace_target_instruction(state)


def _exploit_validation_error(report: RedAgentReport, state: VulnGuardState) -> str | None:
    """Reject a harness that could not legitimately exercise the target.

    Generic checks (refusal/prose, missing success signal, wrong language) run
    here; everything language-specific is delegated to the target's adapter so
    a new language cannot bypass the shared guardrails.
    """
    harness = report.exploit_code_harness
    if not harness:
        return None
    language = state.get("language", "")
    if _looks_like_prose(harness):
        return "the harness is an explanation or refusal, not runnable code"
    if not report.expected_stdout_regex:
        return "the harness has no expected_stdout_regex success signal"
    if not _validate_exploit_language(report, language):
        return (
            f"the harness does not match target language '{language}' "
            f"— write the harness only in {language}"
        )
    return get_adapter(language).validation_error(report, state)


def _sanitize_exploit(report: RedAgentReport) -> RedAgentReport:
    """Remove dangerous patterns from exploit code (Section 4.3)."""
    if report.exploit_code_harness and _DANGEROUS_PATTERNS.search(report.exploit_code_harness):
        logger.warning("Dangerous payload detected in exploit — sanitizing")
        report.exploit_code_harness = "// DANGEROUS PAYLOAD REMOVED — re-prompt needed"
        report.confidence = 0.0
    return report


# ── Generation ────────────────────────────────────────────────────────────

def _harness_problem(report: RedAgentReport, state: VulnGuardState) -> tuple[str | None, str]:
    """Why the report cannot be executed as evidence, or ``(None, "")``.

    The second element is the failure kind recorded on the pipeline state:
    ``EXPLOIT_GENERATION_FAILED`` when no artifact exists (missing, empty or
    prose), ``HARNESS_INVALID`` when code exists but static validation rejects
    it. Neither means the vulnerability is absent.
    """
    harness = (report.exploit_code_harness or "").strip()
    if not harness:
        return "the harness JSON had no exploit_code_harness", "EXPLOIT_GENERATION_FAILED"
    if _looks_like_prose(harness):
        return "the harness is an explanation or refusal, not runnable code", "EXPLOIT_GENERATION_FAILED"
    error = _exploit_validation_error(report, state)
    if error:
        return error, "HARNESS_INVALID"
    return None, ""


def _merged_with_harness(report: RedAgentReport, retry: RedAgentReport) -> RedAgentReport:
    """Keep the original diagnosis and take only the harness from the retry."""
    merged = report.model_dump()
    merged.update(
        {
            "exploit_type": retry.exploit_type,
            "exploit_code_harness": retry.exploit_code_harness,
            "expected_stdout_regex": retry.expected_stdout_regex,
            "execution_instructions": retry.execution_instructions,
            "expected_vulnerable_behavior": retry.expected_vulnerable_behavior,
            "expected_patched_behavior": retry.expected_patched_behavior,
        }
    )
    return RedAgentReport(**merged)


def _analyze(
    state: VulnGuardState,
    risk_score: float,
) -> tuple[RedAgentReport | None, str, str, str]:
    """One structured request; at most one bounded regeneration.

    Returns ``(report | None, failure_reason, failure_kind, raw_response)``.

    * ``report`` is the merged diagnosis + harness when usable, or a
      diagnosis-only report when the harness could not be produced.
    * ``failure_reason`` / ``failure_kind`` describe a missing or rejected
      harness. They are empty when the report is fully usable.
    * ``None`` means the model could not even be read as a report (a response
      failure), so there is no diagnosis to preserve.
    """
    from vulnguard.agents.llm_calls import LLMCallError
    from vulnguard.agents.llm_parsing import parse_agent_json

    language = state["language"]
    environment = _environment(state)
    env_suffix = (
        f" Environment: {environment.limitations_text()}"
        if environment.limitations
        else ""
    )
    ceiling = int(cfg.llm.max_token_ceiling)
    budget = min(
        int(getattr(cfg.llm, "harness_max_tokens", 0) or cfg.llm.max_tokens),
        ceiling,
    )

    # ── The single structured call: diagnosis + harness together ──────────
    try:
        raw = _call_llm(
            _analysis_messages(state, environment),
            risk_score=risk_score,
            retries=cfg.llm.max_retries,
            base_max_tokens=budget,
        )
    except LLMCallError as exc:
        return None, str(exc), "EXPLOIT_GENERATION_FAILED", getattr(exc, "partial_response", "")

    report, parse_error = parse_agent_json(raw, RedAgentReport)

    if report is None:
        # The JSON itself was unreadable, so no diagnosis exists yet. One
        # remediation request is allowed; it asks for the whole object again.
        logger.warning(
            "Red Agent response unparseable (%s) — requesting one corrective report",
            parse_error,
        )
        messages = _analysis_messages(state, environment) + [
            {"role": "assistant", "content": raw},
            {
                "role": "user",
                "content": _PARSE_CORRECTION_PROMPT.format(parse_error=parse_error),
            },
        ]
        try:
            corrected = _call_llm(
                messages,
                risk_score=risk_score,
                retries=_EXTRA_ATTEMPTS,
                base_max_tokens=budget,
            )
        except LLMCallError as exc:
            return (
                None,
                f"the model response was not readable as a report ({parse_error}); "
                f"the corrective request failed: {exc}",
                "EXPLOIT_GENERATION_FAILED",
                raw,
            )
        report, corrected_error = parse_agent_json(corrected, RedAgentReport)
        if report is None:
            return (
                None,
                "the model response was not readable as a report even after one "
                f"correction ({corrected_error})",
                "EXPLOIT_GENERATION_FAILED",
                corrected,
            )
        raw = corrected

    if not report.vulnerability_found:
        return report, "", "", raw

    reason, kind = _harness_problem(report, state)
    if reason is None:
        return report, "", "", raw

    # ── One bounded regeneration, keeping the diagnosis ───────────────────
    logger.warning("Red Agent harness unusable (%s) — one regeneration", reason)
    retry_budget = min(max(budget * 2, budget + 1024), ceiling)
    try:
        retry_raw = _call_llm(
            _regeneration_messages(state, environment, raw, reason),
            risk_score=risk_score,
            retries=_EXTRA_ATTEMPTS,
            base_max_tokens=retry_budget,
        )
    except LLMCallError as exc:
        return (
            report,
            f"{reason}; the regenerated harness is unavailable: {exc}{env_suffix}",
            kind,
            raw,
        )

    retry_report, retry_parse_error = parse_agent_json(retry_raw, RedAgentReport)
    if retry_report is None:
        return (
            report,
            f"{reason}; the regenerated report was unreadable: {retry_parse_error}{env_suffix}",
            kind,
            retry_raw,
        )
    if not retry_report.vulnerability_found:
        return (
            report,
            f"{reason}; the regenerated report denied the diagnosis, so the "
            f"original diagnosis was kept{env_suffix}",
            kind,
            retry_raw,
        )

    retry_reason, retry_kind = _harness_problem(retry_report, state)
    if retry_reason:
        return (
            report,
            f"{reason}; the regenerated harness is still unusable: {retry_reason}{env_suffix}",
            retry_kind or kind,
            retry_raw,
        )

    logger.info("Red Agent: regenerated harness accepted in %s", language)
    return _merged_with_harness(report, retry_report), "", "", retry_raw


# ── LangGraph node function ──────────────────────────────────────────────

def _report_payload(report: RedAgentReport, state: VulnGuardState) -> dict[str, Any]:
    """Persisted report plus the environment assumptions behind the harness."""
    payload = report.model_dump()
    payload["harness_environment"] = _environment(state).to_dict()
    return payload


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
        "exploit_failure_kind": "EXPLOIT_GENERATION_FAILED",
        "judge_verdict": "RED_AGENT_ERROR",
        "pipeline_status": "RED_ERROR",
        "error_logs": message,
        "timestamps": timestamps,
    }


def _diagnosis_summary(report: RedAgentReport) -> dict[str, Any]:
    """The diagnosis fields shown as soon as they are known."""
    return RedAgentDiagnosis(**report.model_dump()).model_dump()


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

    emit(
        state,
        "red_started",
        agent="red_agent",
        attempt_number=state.get("attempt_number", 0),
    )

    try:
        report, failure, failure_kind, raw = _analyze(state, risk_score)

        if report is None:
            emit(
                state,
                "red_completed",
                agent="red_agent",
                vulnerability_found=False,
                exploit_status="ERROR",
                pipeline_status="RED_ERROR",
                exploit_error=failure,
            )
            return _error_update(
                state["function_id"],
                failure or "the model did not return a usable report",
                parse_error=failure,
                raw=raw,
                timestamps={**timestamps, "red_end": time.time()},
            )

        emit(
            state,
            "red_diagnosis",
            agent="red_agent",
            vulnerability_found=bool(report.vulnerability_found),
            diagnosis=_diagnosis_summary(report),
        )

        if not report.vulnerability_found:
            elapsed = time.time() - start
            logger.info("🔴 Red Agent: no vulnerability found (%.1fs)", elapsed)
            emit(
                state,
                "red_completed",
                agent="red_agent",
                vulnerability_found=False,
                exploit_status="NONE",
                pipeline_status="RED_COMPLETE",
            )
            return {
                "red_report": _report_payload(report, state),
                "vulnerability_found": False,
                "exploit_harness": None,
                "exploit_type": None,
                "expected_stdout_regex": None,
                "exploit_status": "NONE",
                "exploit_error": None,
                "exploit_failure_kind": "",
                "pipeline_status": "RED_COMPLETE",
                "timestamps": {**timestamps, "red_end": time.time()},
            }

        # ── Harness evidence — the diagnosis is never discarded ──────────
        if failure:
            # The returned code (if any) was rejected; it must not be exposed
            # as an executable artifact. Only the diagnosis survives.
            cleared = report.model_dump()
            cleared.update({"exploit_code_harness": None, "expected_stdout_regex": None})
            report = RedAgentReport(**cleared)
            exploit_status = (
                "INVALID" if failure_kind == "HARNESS_INVALID" else "UNAVAILABLE"
            )
            exploit_failure_kind = failure_kind or "EXPLOIT_GENERATION_FAILED"
            harness_error = failure
        elif report.exploit_code_harness and _DANGEROUS_PATTERNS.search(
            report.exploit_code_harness
        ):
            report = _sanitize_exploit(report)
            exploit_status = "INVALID"
            exploit_failure_kind = "HARNESS_INVALID"
            harness_error = "the harness contained a destructive command and was removed"
        else:
            exploit_status = "AVAILABLE"
            exploit_failure_kind = ""
            harness_error = None

        emit(
            state,
            "red_harness_generated",
            agent="red_agent",
            exploit_type=report.exploit_type,
            exploit_code_harness=report.exploit_code_harness,
            expected_stdout_regex=report.expected_stdout_regex,
            exploit_status=exploit_status,
            exploit_failure_kind=exploit_failure_kind,
            exploit_error=harness_error,
        )

        elapsed = time.time() - start
        logger.info(
            "🔴 Red Agent result: vulnerability_found=%s, type=%s, severity=%s, exploit=%s (%.1fs)",
            report.vulnerability_found,
            report.vulnerability_type,
            report.severity,
            exploit_status,
            elapsed,
        )

        emit(
            state,
            "red_completed",
            agent="red_agent",
            vulnerability_found=True,
            diagnosis=_diagnosis_summary(report),
            exploit_status=exploit_status,
            exploit_failure_kind=exploit_failure_kind,
            exploit_error=harness_error,
            pipeline_status="RED_COMPLETE",
        )
        return {
            "red_report": _report_payload(report, state),
            "vulnerability_found": True,
            "exploit_harness": report.exploit_code_harness,
            "exploit_type": report.exploit_type,
            "expected_stdout_regex": report.expected_stdout_regex,
            "exploit_status": exploit_status,
            "exploit_error": harness_error,
            "exploit_failure_kind": exploit_failure_kind,
            "pipeline_status": "RED_COMPLETE",
            "timestamps": {**timestamps, "red_end": time.time()},
        }
    except Exception as exc:  # defensive: no agent exception escapes to the graph
        logger.exception("🔴 Red Agent failed unexpectedly for %s", state.get("function_id"))
        emit(
            state,
            "red_completed",
            agent="red_agent",
            vulnerability_found=False,
            exploit_status="ERROR",
            pipeline_status="RED_ERROR",
            exploit_error=f"Red Agent internal error: {exc}",
        )
        return _error_update(
            state.get("function_id", "unknown"),
            f"Red Agent internal error: {exc}",
            timestamps={**timestamps, "red_end": time.time()},
        )
