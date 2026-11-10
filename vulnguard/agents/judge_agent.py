"""
Judge Agent — Sandbox evaluator & retry loop manager.

Orchestrates validation: AST/LOC delta → Build → Tests → Exploit dual pass.
Manages the attempt history ledger and enforces retry limits.
"""

from __future__ import annotations

import logging
import re
import time
from enum import Enum
from typing import Any

from vulnguard.agents.state import VulnGuardState
from vulnguard.config import cfg

logger = logging.getLogger(__name__)


class JudgeVerdict(str, Enum):
    """Possible validation outcomes."""

    PASS = "PASS"
    BUILD_FAILED = "BUILD_FAILED"
    TESTS_FAILED = "TESTS_FAILED"
    # The exploit never triggered against the *original* code — the reported
    # vulnerability (or the harness) is unproven; the patch is not at fault.
    EXPLOIT_NOT_REPRODUCED = "EXPLOIT_NOT_REPRODUCED"
    # The harness itself is malformed, unsafe, or does not exercise the target.
    EXPLOIT_INVALID = "EXPLOIT_INVALID"
    # No usable harness was produced, so the patch could not be proven secure.
    EXPLOIT_UNAVAILABLE = "EXPLOIT_UNAVAILABLE"
    # The model refused, truncated, or returned nothing usable — a generation
    # failure, never evidence that the vulnerability is absent.
    EXPLOIT_GENERATION_FAILED = "EXPLOIT_GENERATION_FAILED"
    # A harness was produced but rejected by static validation (wrong language,
    # redefined target, missing success signal) before it could be executed.
    HARNESS_INVALID = "HARNESS_INVALID"
    # The harness/target failed to build or run — not a security result.
    EXPLOIT_EXECUTION_ERROR = "EXPLOIT_EXECUTION_ERROR"
    EXPLOIT_NOT_BLOCKED = "EXPLOIT_NOT_BLOCKED"
    DESTRUCTIVE_PATCH_REJECTED = "DESTRUCTIVE_PATCH_REJECTED"
    NEW_VULNERABILITY_INTRODUCED = "NEW_VULNERABILITY_INTRODUCED"
    NEW_DEPENDENCIES_REJECTED = "NEW_DEPENDENCIES_REJECTED"
    PATCH_GENERATION_FAILED = "PATCH_GENERATION_FAILED"
    INTERFACE_VIOLATION = "INTERFACE_VIOLATION"
    MAX_RETRIES_EXHAUSTED = "MAX_RETRIES_EXHAUSTED"
    SANDBOX_UNAVAILABLE = "SANDBOX_UNAVAILABLE"


# ── Error log truncation (Section 4.6) ────────────────────────────────────

_ERROR_PATTERN = re.compile(
    r".*(?:error|fail|fault|warning|undefined|segfault|traceback|exception|"
    r"cannot|unable|not found|denied|killed|abort|panic).*",
    re.IGNORECASE,
)

_MEMORY_CRASH_PATTERN = re.compile(
    r"stack smashing detected|segmentation fault|addresssanitizer|"
    r"heap-buffer-overflow|stack-buffer-overflow|aborted \(core dumped\)",
    re.IGNORECASE,
)


# Verdicts where the patch (or its generation) is at fault and another attempt
# with the real evidence can help.
RETRYABLE_VERDICTS = frozenset(
    {
        JudgeVerdict.BUILD_FAILED,
        JudgeVerdict.TESTS_FAILED,
        JudgeVerdict.EXPLOIT_NOT_BLOCKED,
        JudgeVerdict.DESTRUCTIVE_PATCH_REJECTED,
        JudgeVerdict.INTERFACE_VIOLATION,
        JudgeVerdict.NEW_VULNERABILITY_INTRODUCED,
        JudgeVerdict.NEW_DEPENDENCIES_REJECTED,
        JudgeVerdict.PATCH_GENERATION_FAILED,
    }
)

# Verdicts where the evidence itself is unusable. Retrying Blue would only
# produce patches for an unproven vulnerability, so these terminate the run.
TERMINAL_FAILURE_VERDICTS = frozenset(
    {
        JudgeVerdict.EXPLOIT_NOT_REPRODUCED,
        JudgeVerdict.EXPLOIT_INVALID,
        JudgeVerdict.EXPLOIT_UNAVAILABLE,
        JudgeVerdict.EXPLOIT_GENERATION_FAILED,
        JudgeVerdict.HARNESS_INVALID,
        JudgeVerdict.EXPLOIT_EXECUTION_ERROR,
    }
)


def _execution_started(logs: str) -> bool:
    """Whether the harness actually ran (the sandbox echoes a marker first)."""
    return "VULNGUARD_EXECUTION_STARTED" in logs


def _exploit_succeeded(
    success_code: bool,
    logs: str,
    expected_regex: str | None,
    vulnerability_type: str,
) -> bool:
    """Return whether a started harness demonstrated the reported defect."""
    if "VULNGUARD_EXECUTION_STARTED" not in logs:
        return False

    memory_defect = any(
        marker in vulnerability_type.upper()
        for marker in ("BUFFER", "MEMORY", "USE_AFTER_FREE", "OUT_OF_BOUNDS")
    )
    if memory_defect:
        return bool(_MEMORY_CRASH_PATTERN.search(logs))

    if expected_regex:
        try:
            return bool(re.search(expected_regex, logs))
        except re.error:
            return False
    return success_code


def _truncate_error_logs(logs: str, max_chars: int = 2000) -> str:
    """Filter error logs to relevant lines, capped at max_chars."""
    if len(logs) <= max_chars:
        return logs

    relevant = [line for line in logs.splitlines() if _ERROR_PATTERN.match(line)]
    truncated = "\n".join(relevant)

    if len(truncated) > max_chars:
        truncated = truncated[:max_chars] + "\n[... truncated]"

    return truncated or logs[:max_chars] + "\n[... truncated]"


# ── Sandbox execution helpers ─────────────────────────────────────────────

def _get_full_file_code(state: VulnGuardState, use_patched: bool) -> str:
    """Reconstruct the full file content by splicing the target function."""
    from pathlib import Path
    
    file_path = state.get("file_path")
    
    # Pre-clean patched code to remove markdown blocks
    patched_code = state.get("patched_code", "")
    if patched_code:
        cleaned_code = patched_code.strip()
        if cleaned_code.startswith("```"):
            lines = cleaned_code.splitlines()
            if len(lines) > 2 and lines[-1].strip() == "```":
                cleaned_code = "\n".join(lines[1:-1])
        patched_code = cleaned_code

    if not file_path or not Path(file_path).exists():
        return patched_code if use_patched else state.get("original_code", "")
        
    start_byte = state.get("start_byte")
    end_byte = state.get("end_byte")
    
    if start_byte is None or end_byte is None:
        logger.warning("No start_byte/end_byte in state — falling back to snippet")
        return patched_code if use_patched else state.get("original_code", "")
        
    original_bytes = Path(file_path).read_bytes()
    
    if not use_patched:
        return original_bytes.decode("utf-8", errors="replace")
            
    new_bytes = patched_code.encode("utf-8")
    before = original_bytes[:start_byte]
    after = original_bytes[end_byte:]
    
    return (before + new_bytes + after).decode("utf-8", errors="replace")


def _run_build(state: VulnGuardState, use_patched: bool = False) -> tuple[bool, str]:
    """Run build in Docker sandbox. Returns (success, logs)."""
    try:
        from vulnguard.sandbox.docker_runner import DockerRunner

        runner = DockerRunner()
        code = _get_full_file_code(state, use_patched)
        result = runner.run_build(
            repo_root=state.get("repo_root", ""),
            file_path=state.get("file_path", ""),
            code=code,
        )
        return result.success, result.combined_output
    except ImportError:
        logger.warning("Docker SDK not available — skipping build check")
        return True, "Docker not available — build check skipped"
    except Exception as exc:
        logger.error("Build execution failed: %s", exc)
        return False, str(exc)


def _run_tests(state: VulnGuardState) -> tuple[bool, str]:
    """Run existing test suite in Docker sandbox."""
    try:
        from vulnguard.sandbox.docker_runner import DockerRunner

        runner = DockerRunner()
        result = runner.run_tests(
            repo_root=state.get("repo_root", ""),
            file_path=state.get("file_path", ""),
            code=_get_full_file_code(state, use_patched=True),
        )
        if result.exit_code == 5 and "no tests ran" in result.combined_output.lower():
            return True, "No tests discovered; regression test step skipped"
        return result.success, result.combined_output
    except ImportError:
        logger.info("Docker not available — skipping test suite")
        return True, "Skipped (Docker unavailable)"
    except Exception as exc:
        return False, str(exc)


def _run_exploit(state: VulnGuardState, use_patched: bool = False) -> tuple[bool, str]:
    """Run Red Agent's PoC exploit. Returns (crashed/failed, logs).

    For unpatched code: exploit should succeed (crash = vulnerability exists).
    For patched code: exploit should fail (no crash = vulnerability fixed).
    """
    exploit_code = state.get("exploit_harness")
    if not exploit_code:
        logger.info("No exploit harness — skipping exploit validation")
        return True, "No exploit to run"

    try:
        from vulnguard.sandbox.docker_runner import DockerRunner

        runner = DockerRunner()
        code = _get_full_file_code(state, use_patched)
        result = runner.run_exploit(
            repo_root=state.get("repo_root", ""),
            exploit_code=exploit_code,
            target_code=code,
            file_path=state.get("file_path", ""),
            language=state.get("language", "c"),
        )
        return result.success, result.combined_output
    except ImportError:
        return True, "Docker not available — exploit check skipped"
    except Exception as exc:
        return False, str(exc)


# ── Core validation pipeline ─────────────────────────────────────────────

def _validate(state: VulnGuardState) -> tuple[JudgeVerdict, str]:
    """Run the full validation sequence.

    Steps:
    1. Build compilation check (patched code) — skipped for single-file uploads
    2. Existing test suite (regression check) — skipped for single-file uploads
    3. Exploit dual pass:
       a. Exploit on unpatched → should crash/fail (proves vuln exists)
       b. Exploit on patched → should pass/not crash (proves vuln is fixed)
    4. Deterministic double-run (Section 4.6)

    Returns (verdict, error_logs).
    """
    patched = state.get("patched_code")
    if not patched:
        return JudgeVerdict.BUILD_FAILED, "No patched code provided"

    from vulnguard.data.parser import validate_syntax

    full_code = _get_full_file_code(state, use_patched=True)
    syntax_ok, syntax_error = validate_syntax(full_code, state.get("language", "python"))
    if not syntax_ok:
        return JudgeVerdict.BUILD_FAILED, syntax_error

    # ── Exploit evidence gate ─────────────────────────────────────────
    # A patch is only ever marked PASS after a valid exploit demonstrated the
    # defect on the original code and failed on the patched code.
    exploit_status = state.get("exploit_status") or (
        "AVAILABLE" if state.get("exploit_harness") else "NONE"
    )
    failure_kind = state.get("exploit_failure_kind") or ""
    if failure_kind == "EXPLOIT_GENERATION_FAILED":
        return (
            JudgeVerdict.EXPLOIT_GENERATION_FAILED,
            "No executable proof of concept could be generated for this finding, "
            "so the patch was NOT security-validated. This is an exploit-generation "
            f"failure, not evidence that the vulnerability is absent. {state.get('exploit_error') or ''}".strip(),
        )
    if failure_kind == "HARNESS_INVALID":
        return (
            JudgeVerdict.HARNESS_INVALID,
            "The generated harness was rejected before execution, so the patch was "
            f"NOT security-validated. {state.get('exploit_error') or ''}".strip(),
        )
    if exploit_status in {"INVALID", "ERROR"}:
        return (
            JudgeVerdict.EXPLOIT_INVALID,
            "The proof of concept for this finding was invalid, so the patch "
            f"could not be validated. {state.get('exploit_error') or ''}".strip(),
        )

    if state.get("exploit_harness"):
        from vulnguard.agents.red_agent import RedAgentReport, _exploit_validation_error

        try:
            report = RedAgentReport.model_validate(state.get("red_report") or {})
        except Exception as exc:
            return JudgeVerdict.EXPLOIT_INVALID, f"Invalid exploit report: {exc}"
        harness_error = _exploit_validation_error(report, state)
        if harness_error:
            return JudgeVerdict.EXPLOIT_INVALID, f"Invalid exploit harness: {harness_error}"

    from vulnguard.sandbox.docker_runner import check_docker_available, get_docker_error

    if not check_docker_available():
        detail = get_docker_error()
        return (
            JudgeVerdict.SANDBOX_UNAVAILABLE,
            "Static syntax and patch guardrail checks passed, but runtime validation did not run. "
            f"{detail or 'Run `python -m vulnguard.main doctor --build-sandbox`.'}",
        )

    if not state.get("exploit_harness"):
        return (
            JudgeVerdict.EXPLOIT_UNAVAILABLE,
            "No executable proof of concept was available for this finding, so "
            "the patch was NOT proven secure. "
            f"{state.get('exploit_error') or ''}".strip(),
        )

    repo_root = state.get("repo_root", "")

    if repo_root:
        # ── Step 1: Build (full project only) ─────────────
        build_ok, build_logs = _run_build(state, use_patched=True)
        if not build_ok:
            return JudgeVerdict.BUILD_FAILED, _truncate_error_logs(build_logs)

        # ── Step 2: Tests (full project only) ─────────────
        tests_ok, test_logs = _run_tests(state)
        if not tests_ok:
            return JudgeVerdict.TESTS_FAILED, _truncate_error_logs(test_logs)
    else:
        logger.info("Static syntax check passed (single-file mode)")

    # ── Step 3a: Exploit on unpatched (should demonstrate vulnerability) ──
    if state.get("exploit_harness"):
        expected_regex = state.get("expected_stdout_regex")

        vulnerability_type = (state.get("red_report") or {}).get("vulnerability_type", "")

        unpatched_ok, unpatched_logs = _run_exploit(state, use_patched=False)
        if not _execution_started(unpatched_logs):
            # The harness or the original target never ran (compile/import
            # failure). That is inconclusive evidence, not a patch failure and
            # certainly not a security success.
            return (
                JudgeVerdict.EXPLOIT_EXECUTION_ERROR,
                "The exploit harness did not run against the original code, so "
                "the vulnerability was not proved.\n"
                + _truncate_error_logs(unpatched_logs),
            )
        if not _exploit_succeeded(
            unpatched_ok, unpatched_logs, expected_regex, vulnerability_type
        ):
            return (
                JudgeVerdict.EXPLOIT_NOT_REPRODUCED,
                "The exploit ran but did not demonstrate the reported defect on "
                "the original code; the finding or the harness is unproven.\n"
                + _truncate_error_logs(unpatched_logs),
            )

        # ── Step 3b: Exploit on patched (should NOT trigger) ────
        patched_ok, patched_logs = _run_exploit(state, use_patched=True)
        if not _execution_started(patched_logs):
            return (
                JudgeVerdict.BUILD_FAILED,
                "The patched source could not be executed.\n"
                + _truncate_error_logs(patched_logs),
            )
        if _exploit_succeeded(patched_ok, patched_logs, expected_regex, vulnerability_type):
            return JudgeVerdict.EXPLOIT_NOT_BLOCKED, _truncate_error_logs(patched_logs)

        # ── Step 4: Deterministic double-run (Section 4.6) ──
        if cfg.agent.double_run_validation:
            patched_ok2, patched_logs2 = _run_exploit(state, use_patched=True)
            if not _execution_started(patched_logs2):
                return (
                    JudgeVerdict.BUILD_FAILED,
                    "The patched source executed once but failed on the repeat run.\n"
                    + _truncate_error_logs(patched_logs2),
                )
            if _exploit_succeeded(
                patched_ok2, patched_logs2, expected_regex, vulnerability_type
            ):
                return JudgeVerdict.EXPLOIT_NOT_BLOCKED, "Flaky result — blocked first run, succeeded second"

    return JudgeVerdict.PASS, ""


# ── LangGraph node function ──────────────────────────────────────────────

def judge_agent_node(state: VulnGuardState) -> dict[str, Any]:
    """LangGraph node: Validate the Blue Agent's patch.

    Returns partial state update. If validation fails, increments
    attempt_number and appends to attempt_history for retry.
    """
    attempt = state.get("attempt_number", 0)
    logger.info("⚖️  Judge Agent validating patch (attempt %d)", attempt + 1)
    start = time.time()

    # Check if Blue Agent already rejected (interface violation, destructive, etc.)
    pre_verdict = state.get("judge_verdict", "")
    pre_status = state.get("pipeline_status", "")
    if pre_status == "BLUE_ERROR":
        # Blue could not produce a parseable patch — an honest generation
        # failure, not a build failure. Schedule a retry with feedback.
        verdict = JudgeVerdict.PATCH_GENERATION_FAILED
        error_logs = state.get("error_logs", "")
    elif pre_verdict in {
        JudgeVerdict.DESTRUCTIVE_PATCH_REJECTED.value,
        JudgeVerdict.INTERFACE_VIOLATION.value,
        JudgeVerdict.NEW_VULNERABILITY_INTRODUCED.value,
        JudgeVerdict.NEW_DEPENDENCIES_REJECTED.value,
    }:
        logger.info("⚖️  Pre-rejected by Blue Agent guardrails: %s", pre_verdict)
        verdict = JudgeVerdict(pre_verdict)
        error_logs = state.get("error_logs", "")
    else:
        # Run full sandbox validation
        verdict, error_logs = _validate(state)

    elapsed = time.time() - start
    logger.info("⚖️  Judge verdict: %s (%.1fs)", verdict.value, elapsed)

    sandbox_unavailable = verdict == JudgeVerdict.SANDBOX_UNAVAILABLE
    result: dict[str, Any] = {
        "judge_verdict": verdict.value,
        "error_logs": error_logs,
        "build_success": not sandbox_unavailable and verdict != JudgeVerdict.BUILD_FAILED,
        "test_success": not sandbox_unavailable and verdict != JudgeVerdict.TESTS_FAILED,
        "exploit_blocked": verdict == JudgeVerdict.PASS,
        # Distinguish the three claims the UI must not merge: the defect was
        # reproduced, the patch stopped it, and the patch was security-validated.
        "exploit_confirmed": verdict
        in (JudgeVerdict.PASS, JudgeVerdict.EXPLOIT_NOT_BLOCKED),
        "security_validated": verdict == JudgeVerdict.PASS,
        "timestamps": {**state.get("timestamps", {}), "judge_end": time.time()},
    }

    max_attempts = state.get("max_attempts", 3)
    if verdict in (JudgeVerdict.PASS, JudgeVerdict.SANDBOX_UNAVAILABLE):
        result["pipeline_status"] = "COMPLETE"
    elif verdict in TERMINAL_FAILURE_VERDICTS:
        # The evidence, not the patch, is the problem. Asking Blue for another
        # patch would be repairing code for an unproven vulnerability.
        result["pipeline_status"] = "FAILED"
        logger.warning(
            "⚖️  %s — ending without a Blue retry (patch is not validated)",
            verdict.value,
        )
    elif verdict in RETRYABLE_VERDICTS and attempt + 1 < max_attempts:
        result["pipeline_status"] = "RETRY"
        result["attempt_number"] = attempt + 1
        result["attempt_history"] = [
            {
                "attempt_number": attempt + 1,
                "patched_code": state.get("patched_code", ""),
                "error_logs": error_logs[:500],
                "failure_reason": verdict.value,
            }
        ]
        logger.info("⚖️  Scheduling retry %d/%d", attempt + 2, max_attempts)
    else:
        result["pipeline_status"] = "FAILED"
        result["judge_verdict"] = JudgeVerdict.MAX_RETRIES_EXHAUSTED.value
        logger.warning("⚖️  Max retries exhausted — pipeline FAILED")

    return result
