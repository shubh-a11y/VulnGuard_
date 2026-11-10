"""
Shared agent state schema for the LangGraph pipeline.

Defines the TypedDict that flows through Red → Blue → Judge nodes.
Immutable context fields are set once and never modified (EC-7.1).
"""

from __future__ import annotations

import operator
from typing import Annotated, Optional, TypedDict


class AttemptRecord(TypedDict):
    """Single retry attempt record for the attempt history ledger."""

    attempt_number: int
    patched_code: str
    error_logs: str
    failure_reason: str


class VulnGuardState(TypedDict):
    """Root state schema for the VulnGuard LangGraph pipeline.

    Fields in the 'Immutable Context' block are set once at pipeline start
    and MUST NOT be modified by any agent node (EC-7.1 frozen_context).
    """

    # ── Immutable Context (frozen — set once, never mutated) ──────────
    function_id: str
    original_code: str
    language: str
    risk_score: float
    context_bundle: dict  # Serialized ContextBundle
    file_path: str
    repo_root: str
    start_byte: Optional[int]
    end_byte: Optional[int]

    # ── Red Agent outputs ─────────────────────────────────────────────
    red_report: Optional[dict]
    vulnerability_found: bool
    exploit_harness: Optional[str]
    exploit_type: Optional[str]
    expected_stdout_regex: Optional[str]
    # NONE | AVAILABLE | UNAVAILABLE | INVALID | ERROR — distinguishes "no
    # defect found" from "defect found but no usable proof of concept".
    exploit_status: str
    exploit_error: Optional[str]
    # "" | EXPLOIT_GENERATION_FAILED | HARNESS_INVALID — why no usable harness
    # exists. Generation failure (refusal/truncation/empty) is never evidence
    # that the vulnerability is absent.
    exploit_failure_kind: str

    # ── Blue Agent outputs ────────────────────────────────────────────
    patched_code: Optional[str]
    patch_justification: Optional[str]
    patch_diff: Optional[str]

    # ── Judge Agent outputs ───────────────────────────────────────────
    build_success: bool
    test_success: bool
    exploit_blocked: bool
    judge_verdict: str  # PASS | BUILD_FAILED | TESTS_FAILED | etc.
    error_logs: Optional[str]
    # True only when a valid harness demonstrated the defect on the original code.
    exploit_confirmed: bool
    # True only for a Judge PASS: exploit reproduced, patch blocked it, and the
    # build/test steps that ran did not fail.
    security_validated: bool

    # ── Retry management ──────────────────────────────────────────────
    attempt_number: int
    attempt_history: Annotated[list[dict], operator.add]  # Append-only ledger
    max_attempts: int

    # ── Pipeline metadata ─────────────────────────────────────────────
    pipeline_status: str  # TRIAGE | RED | BLUE | JUDGE | COMPLETE | FAILED
    timestamps: dict


def initial_state(
    function_id: str,
    code: str,
    language: str,
    risk_score: float,
    context_bundle: dict,
    file_path: str = "",
    repo_root: str = "",
    start_byte: Optional[int] = None,
    end_byte: Optional[int] = None,
    max_attempts: int = 3,
) -> VulnGuardState:
    """Create a fresh pipeline state with defaults."""
    return VulnGuardState(
        # Immutable context
        function_id=function_id,
        original_code=code,
        language=language,
        risk_score=risk_score,
        context_bundle=context_bundle,
        file_path=file_path,
        repo_root=repo_root,
        start_byte=start_byte,
        end_byte=end_byte,
        # Red outputs
        red_report=None,
        vulnerability_found=False,
        exploit_harness=None,
        exploit_type=None,
        expected_stdout_regex=None,
        exploit_status="NONE",
        exploit_error=None,
        exploit_failure_kind="",
        # Blue outputs
        patched_code=None,
        patch_justification=None,
        patch_diff=None,
        # Judge outputs
        build_success=False,
        test_success=False,
        exploit_blocked=False,
        judge_verdict="",
        error_logs=None,
        exploit_confirmed=False,
        security_validated=False,
        # Retry
        attempt_number=0,
        attempt_history=[],
        max_attempts=max_attempts,
        # Meta
        pipeline_status="TRIAGE",
        timestamps={},
    )
