"""
Blue Agent — Secure patch generator.

Receives the Red Agent's threat report and crafts a secure code patch
that remediates the vulnerability while preserving function signatures,
business logic, and performance. Includes anti-triviality checks (Section 4.4),
interface contract enforcement, and retry-aware prompting (EC-7.1).

Enhanced with research paper techniques:
  - Token Context Diffs (Agentless / VRepair) for concise, low-token patches
  - <START_BUG> / <END_BUG> markers (InferFix) for precise bug localization
  - eWASH cross-file context (InferFix) for multi-file vulnerability awareness
  - Historical fix hints (InferFix + CVEfixes) for few-shot demonstration
"""

from __future__ import annotations

import difflib
import json
import logging
import re
import time
from typing import Any, Optional

from pydantic import BaseModel, Field

from vulnguard.agents.state import VulnGuardState
from vulnguard.agents.streaming import emit
from vulnguard.config import cfg

logger = logging.getLogger(__name__)


# ── Pydantic output schema ───────────────────────────────────────────────

class BlueAgentPatch(BaseModel):
    """Structured patch output from the Blue Agent."""

    patched_code: str = Field(description="Complete patched function code")
    changes_summary: str = Field(description="Brief summary of changes made")
    preserved_interface: bool = Field(description="Whether function signature was preserved (must be True)")
    new_dependencies_added: bool = Field(description="Whether new imports/libs were added (must be False)")
    justification: str = Field(description="Why this patch fixes the vulnerability without breaking functionality")


class TokenContextDiff(BaseModel):
    """Token Context Diff format from VRepair paper.

    Instead of rewriting entire functions, the LLM outputs minimal edits
    using <ModStart> / <ModEnd> markers with surrounding context.
    """

    edits: list[dict] = Field(
        description="List of edits. Each edit has 'before' (lines to find) and 'after' (replacement lines)."
    )
    changes_summary: str = Field(description="Brief summary of changes made")
    preserved_interface: bool = Field(description="Whether function signature was preserved (must be True)")
    new_dependencies_added: bool = Field(description="Whether new imports/libs were added (must be False)")
    justification: str = Field(description="Why this patch fixes the vulnerability without breaking functionality")


# ── Prompt construction ──────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are an expert secure code remediation engineer specializing in {language}.

Your task is to fix the identified security vulnerability in the provided function.

STRICT RULES:
1. You MUST preserve the function name, parameter types/names, and return type exactly.
2. You MUST preserve all original business logic and functionality.
3. You MUST NOT add any new third-party dependencies or imports not already present.
4. You MUST NOT delete substantial logic. If your fix removes more than 60% of the code,
   provide explicit justification explaining why the removed code was entirely part of the vulnerability.
5. Apply the MINIMUM change necessary to fix the vulnerability.
6. Your patch must compile/run without errors in the existing project context.
7. For command injection, do not use os.system, shell=True, or join arguments back into a command string. Use an existing shell-free API with an argument list.

Available imports/packages (do NOT use anything not listed here):
{available_imports}

RESPONSE FORMAT:
You MUST respond with a JSON object. The JSON MUST contain these fields:
  - "patched_code": The complete patched function code as a string.
  - "changes_summary": Brief summary of changes made.
  - "preserved_interface": true (must be true).
  - "new_dependencies_added": false (must be false).
  - "justification": Why this patch fixes the vulnerability.

{schema}
"""

_USER_PROMPT = """\
## Vulnerability Report (from Red Team)
Type: {vuln_type}
CWE: {cwe_id}
Severity: {severity}
Affected Lines: {affected_lines}
Explanation: {explanation}

## Original Vulnerable Code
Lines between `// <START_BUG>` and `// <END_BUG>` are the exact lines flagged as vulnerable.
```{language}
{code}
```

## Cross-File Context (eWASH)
{cross_file_context}

## Same-File Context
{context}

{hint_section}

Fix the vulnerability described above. Return the COMPLETE patched function.
"""

_RETRY_PROMPT = """\
## RETRY ATTEMPT {attempt_number} of {max_attempts}

Your previous patch FAILED validation. Do NOT repeat any previous approach.

### Previous Failed Attempts:
{attempt_history}

### Latest Error:
```
{error_logs}
```

### Original Vulnerability (REMINDER — do not lose sight of this):
Type: {vuln_type}
Explanation: {explanation}

### Original Code:
```{language}
{code}
```

Generate a NEW patch that fixes BOTH the original vulnerability AND the validation errors.
"""


def _build_prompt(state: VulnGuardState) -> list[dict[str, str]]:
    """Build Blue Agent prompt messages.

    Enhanced with:
      - <START_BUG> / <END_BUG> markers on affected lines (InferFix)
      - eWASH cross-file context from context_extractor (InferFix)
      - Historical fix hints from retriever (InferFix + CVEfixes)
    """
    red_report = state.get("red_report") or {}
    ctx = state.get("context_bundle") or {}

    imports_text = "\n".join(ctx.get("imports", [])) or "(none detected)"
    schema_json = json.dumps(BlueAgentPatch.model_json_schema(), indent=2)

    # Same-file context (existing)
    context_sections = []
    for key in ["type_definitions", "callee_signatures", "macro_definitions"]:
        items = ctx.get(key, [])
        if items:
            context_sections.append(f"### {key}\n" + "\n".join(items))
    context_text = "\n\n".join(context_sections) or "(minimal context)"

    # ── InferFix: Inject bug markers on affected lines ────────────
    affected_lines = red_report.get("affected_lines", [])
    marked_code = _inject_bug_markers(state["original_code"], affected_lines)

    # ── InferFix: Cross-file eWASH context ────────────────────────
    cross_file_text = _get_cross_file_context(state)

    # ── InferFix + CVEfixes: Historical fix hints ─────────────────
    hint_section = _get_historical_hint(state)

    messages = [
        {
            "role": "system",
            "content": _SYSTEM_PROMPT.format(
                language=state["language"],
                available_imports=imports_text,
                schema=schema_json,
            ),
        },
    ]

    attempt = state.get("attempt_number", 0)

    if attempt > 0 and state.get("attempt_history"):
        # Retry prompt — includes history and errors (EC-7.1)
        history_text = ""
        for record in state["attempt_history"]:
            history_text += (
                f"\n--- Attempt {record.get('attempt_number', '?')} ---\n"
                f"Failure: {record.get('failure_reason', 'unknown')}\n"
                f"Error: {record.get('error_logs', 'none')[:500]}\n"
            )

        messages.append({
            "role": "user",
            "content": _RETRY_PROMPT.format(
                attempt_number=attempt + 1,
                max_attempts=state["max_attempts"],
                attempt_history=history_text,
                error_logs=state.get("error_logs", "none")[:1000],
                vuln_type=red_report.get("vulnerability_type", "unknown"),
                explanation=red_report.get("explanation", ""),
                language=state["language"],
                code=state["original_code"],
            ),
        })
    else:
        # First attempt — enhanced with markers, eWASH, and hints
        messages.append({
            "role": "user",
            "content": _USER_PROMPT.format(
                vuln_type=red_report.get("vulnerability_type", "unknown"),
                cwe_id=red_report.get("cwe_id", "unknown"),
                severity=red_report.get("severity", "unknown"),
                affected_lines=affected_lines,
                explanation=red_report.get("explanation", ""),
                language=state["language"],
                code=marked_code,
                context=context_text,
                cross_file_context=cross_file_text,
                hint_section=hint_section,
            ),
        })

    return messages


# ── InferFix: Bug marker injection ───────────────────────────────────────

def _inject_bug_markers(code: str, affected_lines: list[int] | None) -> str:
    """Wrap affected lines with <START_BUG> / <END_BUG> markers.

    Based on InferFix's approach of providing precise bug localization
    to the LLM so it knows exactly which lines to fix.
    """
    from vulnguard.data.context_extractor import inject_bug_markers
    return inject_bug_markers(code, affected_lines)


# ── InferFix: Cross-file eWASH context ───────────────────────────────────

def _get_cross_file_context(state: VulnGuardState) -> str:
    """Extract cross-file eWASH context if file_path and repo_root are available.

    Returns a formatted text block with class fields, peer method signatures,
    and dependency file skeletons.
    """
    file_path = state.get("file_path", "")
    repo_root = state.get("repo_root", "")
    red_report = state.get("red_report") or {}

    if not file_path or not repo_root:
        return "(no cross-file context available)"

    from pathlib import Path

    fp = Path(file_path)
    rr = Path(repo_root)

    if not fp.exists() or not rr.exists():
        return "(source file or repo root not found)"

    try:
        from vulnguard.data.context_extractor import extract_cross_file_context

        # Extract the function name from the function_id (format: "file.py:func_name")
        func_name = state.get("function_id", "").split(":")[-1] if ":" in state.get("function_id", "") else ""

        xctx = extract_cross_file_context(
            func_code=state["original_code"],
            func_name=func_name,
            file_path=fp,
            repo_root=rr,
            language=state["language"],
            affected_lines=red_report.get("affected_lines"),
        )
        text = xctx.to_prompt_text()
        return text if text.strip() else "(no cross-file dependencies detected)"
    except Exception as exc:
        logger.warning("eWASH context extraction failed: %s", exc)
        return f"(eWASH extraction failed: {exc})"


# ── InferFix + CVEfixes: Historical fix hints ────────────────────────────

def _get_historical_hint(state: VulnGuardState) -> str:
    """Query the retriever for a similar historical bug fix and format it as a hint.

    Returns a formatted prompt section, or an empty string if no retriever is available.
    """
    try:
        from vulnguard.models.retriever import get_retriever

        retriever = get_retriever()
        if retriever is None:
            return ""

        red_report = state.get("red_report") or {}
        vuln_type = red_report.get("vulnerability_type", "")
        code = state["original_code"]

        hint = retriever.find_similar_fix(code, vuln_type)
        if hint:
            return (
                "## Historical Fix Hint (similar vulnerability)\n"
                "The following is a real-world fix for a structurally similar vulnerability. "
                "Use it as inspiration, but adapt it to the current code.\n\n"
                f"```\n{hint}\n```"
            )
    except ImportError:
        pass  # Retriever not yet implemented
    except Exception as exc:
        logger.debug("Retriever hint lookup failed: %s", exc)

    return ""


# ── Anti-triviality check (Section 4.4) ──────────────────────────────────

def _check_ast_loc_delta(original: str, patched: str, min_ratio: float = 0.4) -> tuple[bool, str]:
    """Reject destructive patches that delete too much code.

    Returns (is_acceptable, reason).
    """
    orig_lines = len([l for l in original.splitlines() if l.strip()])
    patch_lines = len([l for l in patched.splitlines() if l.strip()])

    if orig_lines == 0:
        return True, "original is empty"

    ratio = patch_lines / orig_lines
    if ratio < min_ratio:
        return False, (
            f"DESTRUCTIVE_PATCH: patched code retains only {ratio:.0%} of original "
            f"({patch_lines}/{orig_lines} non-empty lines). Minimum is {min_ratio:.0%}."
        )
    return True, "ok"


def _compute_diff(original: str, patched: str) -> str:
    """Generate unified diff between original and patched code."""
    return "\n".join(
        difflib.unified_diff(
            original.splitlines(),
            patched.splitlines(),
            fromfile="original",
            tofile="patched",
            lineterm="",
        )
    )


# ── LLM invocation ───────────────────────────────────────────────────────

def _call_llm(messages: list[dict], risk_score: float = 100.0, retries: int | None = None) -> str:
    """Call LLM with bounded backoff, escalation and severity-based routing.

    Delegates to `vulnguard.agents.llm_calls.call_llm_json`, which raises
    typed `LLMTruncationError` / `LLMProviderError` once the budget is spent.
    """
    if cfg.llm.mock_mode:
        logger.info("Mock LLM enabled. Returning synthetic Blue Agent response.")
        return """
        {
          "patched_code": "def exploit():\\n    pass\\n",
          "changes_summary": "Mock patch applied.",
          "preserved_interface": true,
          "new_dependencies_added": false,
          "justification": "Mock justification."
        }
        """

    from vulnguard.agents.llm_calls import call_llm_json

    provider, model_name = cfg.routing.get_model_for_score(risk_score)
    logger.info("Model routing: risk=%.1f → %s/%s", risk_score, provider, model_name)
    return call_llm_json(
        messages,
        model=f"{provider}/{model_name}",
        attempts=retries if retries is not None else cfg.llm.max_retries,
        base_max_tokens=cfg.llm.max_tokens,
        temperature=cfg.llm.temperature,
        ceiling=cfg.llm.max_token_ceiling,
        timeout=cfg.llm.request_timeout_seconds,
        retry_base_delay=cfg.llm.retry_base_delay_seconds,
    )


# ── LangGraph node function ──────────────────────────────────────────────

def _insecure_patch_reason(state: VulnGuardState, patched_code: str) -> str | None:
    vuln_type = (state.get("red_report") or {}).get("vulnerability_type", "")
    if vuln_type == "COMMAND_INJECTION" and (
        re.search(r"\bos\.system\s*\(", patched_code)
        or re.search(r"\bshell\s*=\s*True\b", patched_code)
    ):
        return "Command injection patch still invokes a shell; use a shell-free argument-list API"
    return None


# A malformed response is retried once with a corrective prompt. Provider
# retries and truncation escalation already happen inside `_call_llm`.
_PARSE_ATTEMPTS = 2


def _generation_error(message: str, timestamps: dict) -> dict[str, Any]:
    """Explicit patch-generation failure — never a build failure or a PASS."""
    logger.error("🔵 Blue Agent could not generate a patch: %s", message)
    return {
        "patched_code": None,
        "patch_justification": None,
        "patch_diff": None,
        "judge_verdict": "PATCH_GENERATION_FAILED",
        "pipeline_status": "BLUE_ERROR",
        "error_logs": f"Blue Agent patch generation failed: {message}",
        "timestamps": timestamps,
    }


def blue_agent_node(state: VulnGuardState) -> dict[str, Any]:
    """LangGraph node: Generate a secure patch.

    Returns partial state update dict. Provider and parse failures become an
    explicit `BLUE_ERROR` state; this node never raises.
    """
    attempt = state.get("attempt_number", 0)
    logger.info("🔵 Blue Agent generating patch (attempt %d)", attempt + 1)
    start = time.time()
    emit(
        state,
        "blue_started",
        agent="blue_agent",
        attempt_number=attempt,
        max_attempts=state.get("max_attempts", 3),
    )

    timestamps = {**state.get("timestamps", {}), "blue_end": time.time()}
    risk_score = state.get("risk_score", 100.0)

    from vulnguard.agents.llm_calls import LLMCallError
    from vulnguard.agents.llm_parsing import parse_agent_json, raw_response_preview, strip_code_fences

    patch: BlueAgentPatch | None = None
    parse_error = ""
    raw_response = ""
    try:
        messages = _build_prompt(state)
        for parse_attempt in range(1, _PARSE_ATTEMPTS + 1):
            raw_response = _call_llm(
                messages,
                risk_score=risk_score,
                retries=cfg.llm.max_retries if parse_attempt == 1 else 1,
            )
            patch, parse_error = parse_agent_json(raw_response, BlueAgentPatch)
            if patch is not None:
                break
            logger.error(
                "Failed to parse Blue Agent response (attempt %d/%d): %s",
                parse_attempt,
                _PARSE_ATTEMPTS,
                parse_error,
            )
            logger.error("RAW RESPONSE: %s", raw_response_preview(raw_response))
            if parse_attempt < _PARSE_ATTEMPTS:
                messages = messages + [
                    {"role": "assistant", "content": strip_code_fences(raw_response) or raw_response},
                    {
                        "role": "user",
                        "content": (
                            "Your previous patch response was not valid JSON matching the requested "
                            f"schema (parsing failed: {parse_error}). Respond again with ONLY a "
                            "single complete JSON object containing patched_code, changes_summary, "
                            "preserved_interface, new_dependencies_added, and justification."
                        ),
                    },
                ]
    except LLMCallError as exc:
        result = _generation_error(str(exc), timestamps)
        emit(state, "blue_completed", agent="blue_agent", **{
            "pipeline_status": "BLUE_ERROR",
            "error_logs": result["error_logs"],
            "patched_code": None,
        })
        return result
    except Exception as exc:  # defensive: keep the graph alive, log the cause
        logger.exception("🔵 Blue Agent crashed while building the prompt")
        result = _generation_error(f"internal error: {exc}", timestamps)
        emit(state, "blue_completed", agent="blue_agent", **{
            "pipeline_status": "BLUE_ERROR",
            "error_logs": result["error_logs"],
            "patched_code": None,
        })
        return result

    if patch is None:
        result = _generation_error(
            f"output was not parseable after {_PARSE_ATTEMPTS} attempts: {parse_error}",
            timestamps,
        )
        emit(state, "blue_completed", agent="blue_agent", **{
            "pipeline_status": "BLUE_ERROR",
            "error_logs": result["error_logs"],
            "patched_code": None,
        })
        return result

    # ── Validate interface preservation ───────────────────
    if not patch.preserved_interface:
        logger.warning("Blue Agent declared interface NOT preserved — rejecting")
        emit(state, "blue_completed", agent="blue_agent", **{
            "pipeline_status": "BLUE_INTERFACE_VIOLATION",
            "error_logs": "Blue Agent broke function interface contract",
            "patched_code": patch.patched_code,
        })
        return {
            "patched_code": patch.patched_code,
            "pipeline_status": "BLUE_INTERFACE_VIOLATION",
            "judge_verdict": "INTERFACE_VIOLATION",
            "error_logs": "Blue Agent broke function interface contract",
            "timestamps": {**state.get("timestamps", {}), "blue_end": time.time()},
        }

    # ── Reject new dependencies (Section 4.4) ────────────
    if patch.new_dependencies_added:
        logger.warning("Blue Agent added new dependencies — rejecting")
        emit(state, "blue_completed", agent="blue_agent", **{
            "pipeline_status": "BLUE_NEW_DEPS",
            "error_logs": "Blue Agent attempted to add unapproved dependencies",
            "patched_code": patch.patched_code,
        })
        return {
            "patched_code": patch.patched_code,
            "pipeline_status": "BLUE_NEW_DEPS",
            "judge_verdict": "NEW_DEPENDENCIES_REJECTED",
            "error_logs": "Blue Agent attempted to add unapproved dependencies",
            "timestamps": {**state.get("timestamps", {}), "blue_end": time.time()},
        }

    insecure_reason = _insecure_patch_reason(state, patch.patched_code)
    if insecure_reason:
        logger.warning("Insecure patch rejected: %s", insecure_reason)
        emit(state, "blue_completed", agent="blue_agent", **{
            "pipeline_status": "BLUE_INSECURE_PATCH",
            "error_logs": insecure_reason,
            "patched_code": patch.patched_code,
        })
        return {
            "patched_code": patch.patched_code,
            "pipeline_status": "BLUE_INSECURE_PATCH",
            "judge_verdict": "NEW_VULNERABILITY_INTRODUCED",
            "error_logs": insecure_reason,
            "timestamps": {**state.get("timestamps", {}), "blue_end": time.time()},
        }

    # ── Anti-triviality check (Section 4.4) ───────────────
    ok, reason = _check_ast_loc_delta(
        state["original_code"],
        patch.patched_code,
        min_ratio=cfg.agent.min_ast_ratio,
    )
    if not ok:
        logger.warning("Anti-triviality check failed: %s", reason)
        emit(state, "blue_completed", agent="blue_agent", **{
            "pipeline_status": "BLUE_DESTRUCTIVE",
            "error_logs": reason,
            "patched_code": patch.patched_code,
        })
        return {
            "patched_code": patch.patched_code,
            "pipeline_status": "BLUE_DESTRUCTIVE",
            "judge_verdict": "DESTRUCTIVE_PATCH_REJECTED",
            "error_logs": reason,
            "timestamps": {**state.get("timestamps", {}), "blue_end": time.time()},
        }

    # ── Success ───────────────────────────────────────────
    diff = _compute_diff(state["original_code"], patch.patched_code)

    elapsed = time.time() - start
    logger.info("🔵 Blue Agent patch generated (%.1fs): %s", elapsed, patch.changes_summary[:100])

    emit(
        state,
        "blue_patch_generated",
        agent="blue_agent",
        patched_code=patch.patched_code,
        patch_diff=diff,
        patch_justification=patch.justification,
        changes_summary=patch.changes_summary,
        attempt_number=attempt,
    )
    emit(
        state,
        "blue_completed",
        agent="blue_agent",
        pipeline_status="BLUE_COMPLETE",
        patched_code=patch.patched_code,
        patch_diff=diff,
        patch_justification=patch.justification,
        error_logs="",
    )

    return {
        "patched_code": patch.patched_code,
        "patch_justification": patch.justification,
        "patch_diff": diff,
        "judge_verdict": "",
        "error_logs": "",
        "pipeline_status": "BLUE_COMPLETE",
        "timestamps": timestamps,
    }
