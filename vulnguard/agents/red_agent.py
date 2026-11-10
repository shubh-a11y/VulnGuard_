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

from vulnguard.agents.harness import get_adapter
from vulnguard.agents.harness.environment import RepositoryEnvironment, probe_repository
from vulnguard.agents.harness.strategies import strategy_for
from vulnguard.agents.state import VulnGuardState
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
    location: Optional[str] = Field(None, description="Function or file:line that owns the defect")
    affected_lines: Optional[list[int]] = Field(None, description="Line numbers containing the defect")
    attack_strategy: Optional[str] = Field(None, description="How the defect is reached and what proves it")
    explanation: Optional[str] = Field(None, description="Short technical explanation of the defect")
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0, description="Confidence score 0.0-1.0")


class RedAgentHarness(BaseModel):
    """Minimal executable proof of concept for a diagnosed defect."""

    exploit_type: Optional[str] = Field(None, description="python_script, c_harness, cpp_harness, java_harness, javascript_script")
    exploit_code_harness: Optional[str] = Field(None, description="Complete runnable proof-of-concept program")
    expected_stdout_regex: Optional[str] = Field(None, description="Regex matching the success marker")
    execution_instructions: Optional[str] = Field(None, description="How the sandbox runs the harness")
    expected_vulnerable_behavior: Optional[str] = Field(None, description="Observable result on the vulnerable code")
    expected_patched_behavior: Optional[str] = Field(None, description="Observable result after the fix")


class RedAgentReport(RedAgentDiagnosis):
    """Merged report persisted on the pipeline state.

    Kept as the single normalized shape consumed by the Blue and Judge agents,
    so downstream code does not need to know generation was split in two.
    """

    exploit_type: Optional[str] = None
    exploit_code_harness: Optional[str] = None
    expected_stdout_regex: Optional[str] = None
    execution_instructions: Optional[str] = None
    expected_vulnerable_behavior: Optional[str] = None
    expected_patched_behavior: Optional[str] = None


# ── Prompt construction ──────────────────────────────────────────────────

_DIAGNOSIS_SYSTEM_PROMPT = """\
You are a senior software engineer and QA specialist focusing on code correctness and data integrity.

Analyze the supplied function for a data-flow defect (for example untrusted string interpolation in a query, or an out-of-bounds memory access).

RULES:
1. If the function operates correctly on all inputs, set vulnerability_found=false.
2. If a defect exists, name the exact defect, the CWE, the affected lines, the location (function or file:line), and the input shape that proves it.
3. Give a short attack_strategy: how the dangerous input reaches the defect, and what observable effect (a crash, a SQL error, a created file, an extra command) proves it during execution.
4. Name any minimal runtime prerequisite a proof of concept would need (a database table, a temporary file, a writable directory) in the attack_strategy.
5. Be concise: the explanation is at most 120 words of plain prose. Do not restate the source, do not include code blocks, and do not propose a fix.
6. Do NOT write an exploit or test harness here; a separate step does that.
7. Only report a defect you can justify from the supplied code and context. Set confidence honestly.

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
You are a security test engineer writing authorized, offline sandbox tests for the user's own code. Write a MINIMAL proof-of-concept harness for the vulnerability described by the user.

The target language is {language}. The harness MUST be written in {language} and nothing else — not another programming language, not a shell script, not prose. The sandbox compiles or runs it as a {language} program, so any other language fails before the exploit is tested.

RULES:
1. The harness must be valid {language} source, at most 80 lines (target 60), with no commentary and no blank lines. Follow this {language} shape:
{shape}
2. It MUST import, link, or otherwise invoke the real target from the supplied workspace. Do NOT copy, restate, or redefine the target function. For C/C++, declare the target's prototype instead of including its .c file.
3. Use the exact target name and signature: pass the arguments the real application passes. If the target is a method, instantiate its class first.
4. Create every prerequisite the harness needs inline (for example `sqlite3.connect(':memory:')` plus `CREATE TABLE`, a file under /tmp, an environment value) and use only the standard library. It must never depend on the network, a service, or a file that does not exist in the workspace.
5. The harness may only create benign prerequisites. It must never run a destructive system command and must never attack anything outside the sandbox.
6. It must print the success marker ONLY after the security defect is proven. The marker must not appear inside attacker-controlled input or in data printed by the target.
7. For command injection, use a benign isolated side effect (for example a file under /tmp), verify it, then print the marker.
8. expected_stdout_regex is REQUIRED and must uniquely match that marker. Printing and matching the literal marker `VULNGUARD_POC_SUCCESS` is the simplest reliable choice.
9. The assertion must succeed against the original vulnerable source and fail against a secure patch.
10. Do NOT add third-party dependencies.
11. Never answer with null fields, an apology, a refusal, or an explanation: exploit_code_harness and expected_stdout_regex must both be non-empty. If you cannot build a perfect PoC, return the best-effort {language} code anyway.
12. Never switch languages: a C target gets a C harness and a Python target gets a Python harness, even when another language seems easier to write.
13. `execution_instructions`, `expected_vulnerable_behavior`, and `expected_patched_behavior` are short plain-text sentences. They describe the harness; they are never a substitute for it.

## Execution adapter ({language})
{adapter_notes}

## Repository environment
{environment}

## Exploit strategy for this finding
{strategy}

Follow the strategy's observable proof and the repository environment's constraints. If a prerequisite cannot be created inside the sandbox, prefer a smaller harness that still proves the defect over an aspirational one that cannot run.

Return only this JSON object, with every field populated:
{{"exploit_type": "{language}", "exploit_code_harness": "<complete runnable {language} source>", "expected_stdout_regex": "VULNGUARD_POC_SUCCESS", "execution_instructions": "<one command the sandbox runs>", "expected_vulnerable_behavior": "<what the harness shows on the vulnerable code>", "expected_patched_behavior": "<what the harness shows after the fix>"}}

Your JSON output MUST conform to this schema (output data, not the schema itself):
{schema}
"""

_HARNESS_USER_PROMPT = """\
## Diagnosed Vulnerability
Type: {vuln_type}
CWE: {cwe_id}
Severity: {severity}
Location: {location}
Affected lines: {affected_lines}
Attack strategy: {attack_strategy}
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

Regenerate it in {language} — the same language as the target. Do not switch languages, and do not reply with an apology, refusal, explanation, or prose: return best-effort runnable {language} code even if the PoC is imperfect. It must import or link and invoke the supplied workspace target, must not redefine target code, must not treat arbitrary exceptions as proof of exploitation, and must print the marker only after the defect is actually proven.

Both fields are REQUIRED and must be non-empty: `exploit_code_harness` (the complete runnable {language} harness) and `expected_stdout_regex` (a regex that uniquely matches the marker the harness prints, for example `VULNGUARD_POC_SUCCESS`).

Follow this {language} shape:
{shape}

Reply with only this JSON object:
{{"exploit_type": "{language}", "exploit_code_harness": "...", "expected_stdout_regex": "...", "execution_instructions": "...", "expected_vulnerable_behavior": "...", "expected_patched_behavior": "..."}}
"""

# Used after a truncated or unparseable harness response. The point is a much
# smaller program, so the JSON closes inside a normal output budget.
_HARNESS_MINIMAL_PROMPT = """\
The previous harness response was unusable: {reason}

Regenerate the SMALLEST possible runnable {language} proof of concept for the same target. Hard limits:
- At most 30 lines, no comments, no blank lines, no prose, no explanation.
- Import or link the workspace target and call it with its real signature; never redefine the target.
- Set up prerequisites inline with the standard library only (for example an in-memory SQLite table); no network and no missing files.
- Print VULNGUARD_POC_SUCCESS only after the defect is actually observed. Do not treat an arbitrary exception as proof.

Follow this {language} shape:
{shape}

Reply with only this JSON object and no other text:
{{"exploit_type": "{language}", "exploit_code_harness": "<complete {language} source>", "expected_stdout_regex": "VULNGUARD_POC_SUCCESS", "execution_instructions": "<one command>", "expected_vulnerable_behavior": "<vulnerable result>", "expected_patched_behavior": "<result after the fix>"}}
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


def _harness_messages(
    state: VulnGuardState,
    diagnosis: RedAgentDiagnosis,
    environment: RepositoryEnvironment | None = None,
) -> list[dict[str, str]]:
    """Build the harness request from the adapter, environment and strategy.

    Nothing here depends on a particular repository: the module to import, the
    program shape, the runtime guarantees and the exploit strategy are all
    derived from the target's language and the uploaded tree.
    """
    language = state["language"]
    adapter = get_adapter(language)
    env = environment or probe_repository(
        state.get("repo_root"), language, state.get("file_path")
    )
    strategy = strategy_for(diagnosis.vulnerability_type, diagnosis.cwe_id)
    notes = [adapter.capability_note(), *adapter.prerequisite_notes(diagnosis.vulnerability_type or "")]

    return [
        {
            "role": "system",
            "content": _HARNESS_SYSTEM_PROMPT.format(
                language=language,
                schema=_schema_json(RedAgentHarness),
                shape=adapter.shape(),
                adapter_notes="\n".join(f"- {note}" for note in notes),
                environment=env.to_prompt_text(),
                strategy=strategy.prompt_block(),
            ),
        },
        {
            "role": "user",
            "content": _HARNESS_USER_PROMPT.format(
                vuln_type=diagnosis.vulnerability_type or "unknown",
                cwe_id=diagnosis.cwe_id or "unknown",
                severity=diagnosis.severity or "unknown",
                location=diagnosis.location or state.get("function_id", "unknown"),
                affected_lines=diagnosis.affected_lines or "unknown",
                attack_strategy=diagnosis.attack_strategy or "(not supplied)",
                explanation=diagnosis.explanation or "",
                language=language,
                file_path=state.get("file_path", "unknown"),
                workspace_target=adapter.workspace_target_instruction(state),
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
) -> tuple[RedAgentHarness | None, str, str]:
    """Produce and validate a proof of concept, or an honest failure.

    Returns ``(harness | None, failure_message, failure_kind)`` where
    ``failure_kind`` is one of ``""``, ``EXPLOIT_GENERATION_FAILED`` (the model
    refused, truncated, or returned something unparseable) or
    ``HARNESS_INVALID`` (code was produced but rejected by static validation).

    Two bounded calls at most: the structured request, then one smaller
    regeneration with a larger output budget. A truncated response is never
    re-asked with the same budget, because that is guaranteed to fail again.
    """
    from vulnguard.agents.llm_calls import LLMCallError, LLMTruncationError
    from vulnguard.agents.llm_parsing import parse_agent_json

    language = state["language"]
    environment = probe_repository(
        state.get("repo_root"), language, state.get("file_path")
    )
    env_suffix = (
        f" Environment: {environment.limitations_text()}"
        if environment.limitations
        else ""
    )
    base_budget = int(
        getattr(cfg.llm, "harness_max_tokens", 0) or cfg.llm.max_tokens
    )
    ceiling = int(cfg.llm.max_token_ceiling)
    first_budget = min(base_budget, ceiling)

    raw = ""
    reason = ""
    kind = "EXPLOIT_GENERATION_FAILED"

    try:
        raw = _call_llm(
            _harness_messages(state, diagnosis, environment),
            risk_score=risk_score,
            retries=cfg.llm.max_retries,
            base_max_tokens=first_budget,
        )
    except LLMTruncationError as exc:
        raw = getattr(exc, "partial_response", "") or ""
        reason = (
            "harness generation was truncated "
            f"(finish_reason={exc.finish_reason or 'length'})"
        )
    except LLMCallError as exc:
        return (
            None,
            f"harness generation failed: {exc}{env_suffix}",
            "EXPLOIT_GENERATION_FAILED",
        )
    else:
        harness, parse_error = parse_agent_json(raw, RedAgentHarness)
        if harness is None:
            reason = f"harness response was not parseable: {parse_error}"
        elif not harness.exploit_code_harness:
            reason = "the harness JSON had no exploit_code_harness"
        else:
            merged = RedAgentReport(**diagnosis.model_dump(), **harness.model_dump())
            validation_error = _exploit_validation_error(merged, state)
            if validation_error is None:
                return harness, "", ""
            reason = validation_error
            # A refusal or prose is a generation failure, not a malformed
            # harness: no executable artifact exists to judge.
            kind = (
                "EXPLOIT_GENERATION_FAILED"
                if _looks_like_prose(harness.exploit_code_harness or "")
                else "HARNESS_INVALID"
            )

    logger.warning(
        "Harness unusable (%s) — regenerating a minimal %s harness", reason, language
    )
    retry_messages = _harness_messages(state, diagnosis, environment)
    if raw:
        retry_messages = retry_messages + [{"role": "assistant", "content": raw}]
    retry_messages = retry_messages + [
        {
            "role": "user",
            "content": _HARNESS_MINIMAL_PROMPT.format(
                reason=reason,
                language=language,
                shape=_harness_shape(language),
            ),
        }
    ]
    retry_budget = min(max(first_budget * 2, first_budget + 1024), ceiling)
    try:
        retry_raw = _call_llm(
            retry_messages,
            risk_score=risk_score,
            retries=1,
            base_max_tokens=retry_budget,
        )
    except LLMTruncationError as exc:
        return (
            None,
            f"{reason}; corrected harness unavailable: {exc}{env_suffix}",
            "EXPLOIT_GENERATION_FAILED",
        )
    except LLMCallError as exc:
        return (
            None,
            f"{reason}; corrected harness unavailable: {exc}{env_suffix}",
            "EXPLOIT_GENERATION_FAILED",
        )

    retry_harness, retry_error = parse_agent_json(retry_raw, RedAgentHarness)
    if retry_harness is None:
        return (
            None,
            f"{reason}; corrected harness unparseable: {retry_error}{env_suffix}",
            "EXPLOIT_GENERATION_FAILED",
        )
    if not retry_harness.exploit_code_harness:
        return (
            None,
            f"{reason}; the model did not provide an exploit harness{env_suffix}",
            "EXPLOIT_GENERATION_FAILED",
        )

    merged = RedAgentReport(**diagnosis.model_dump(), **retry_harness.model_dump())
    retry_validation_error = _exploit_validation_error(merged, state)
    if retry_validation_error:
        retry_kind = (
            "EXPLOIT_GENERATION_FAILED"
            if _looks_like_prose(retry_harness.exploit_code_harness)
            else "HARNESS_INVALID"
        )
        return (
            None,
            f"{reason}; corrected harness still invalid: {retry_validation_error}{env_suffix}",
            retry_kind,
        )
    return retry_harness, "", ""


# ── LangGraph node function ──────────────────────────────────────────────

def _report_payload(report: RedAgentReport, state: VulnGuardState) -> dict[str, Any]:
    """Persisted report plus the environment assumptions behind the harness."""
    payload = report.model_dump()
    payload["harness_environment"] = probe_repository(
        state.get("repo_root"), state.get("language", ""), state.get("file_path")
    ).to_dict()
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
                "exploit_failure_kind": "",
                "pipeline_status": "RED_COMPLETE",
                "timestamps": {**timestamps, "red_end": time.time()},
            }

        # ── Exploit generation — never allowed to discard the diagnosis ──
        harness, harness_error, harness_failure_kind = _generate_harness(
            state, diagnosis, risk_score
        )
        report = RedAgentReport(
            **diagnosis.model_dump(), **(harness.model_dump() if harness else {})
        )

        if harness is None or not harness.exploit_code_harness:
            logger.warning(
                "🔴 Diagnosis kept, exploit unavailable for %s: %s",
                state["function_id"],
                harness_error or "no harness returned",
            )
            # A generated-but-rejected harness is INVALID; a refusal, truncation,
            # empty response, or provider failure left us with no harness at all,
            # which is UNAVAILABLE. Neither is evidence that the defect is absent.
            exploit_status = (
                "INVALID" if harness_failure_kind == "HARNESS_INVALID" else "UNAVAILABLE"
            )
            exploit_failure_kind = harness_failure_kind or "EXPLOIT_GENERATION_FAILED"
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
            "red_report": _report_payload(report, state),
            "vulnerability_found": True,
            "exploit_harness": report.exploit_code_harness,
            "exploit_type": report.exploit_type,
            "expected_stdout_regex": report.expected_stdout_regex,
            "exploit_status": exploit_status,
            "exploit_error": harness_error or None,
            "exploit_failure_kind": exploit_failure_kind,
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
