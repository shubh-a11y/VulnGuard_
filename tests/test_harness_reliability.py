"""Red Agent harness reliability: budgets, recovery, and honest failure states."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from vulnguard.agents.judge_agent import (
    TERMINAL_FAILURE_VERDICTS,
    JudgeVerdict,
    judge_agent_node,
)
from vulnguard.agents.llm_calls import LLMTruncationError
from vulnguard.agents.red_agent import red_agent_node
from vulnguard.agents.state import initial_state
from vulnguard.config import cfg

DIAGNOSIS = json.dumps(
    {
        "vulnerability_found": True,
        "vulnerability_type": "COMMAND_INJECTION",
        "cwe_id": "CWE-78",
        "severity": "HIGH",
        "location": "vuln_cmdi.py:2",
        "affected_lines": [5],
        "attack_strategy": "Semicolon splits the shell command and runs a second command.",
        "explanation": "Hostname is interpolated into a shell command.",
        "confidence": 0.9,
    }
)

VALID_HARNESS = json.dumps(
    {
        "exploit_type": "python_script",
        "exploit_code_harness": (
            "import os\n"
            "from vuln_cmdi import ping_host\n"
            "ping_host('localhost; touch /tmp/vg_probe')\n"
            "if os.path.exists('/tmp/vg_probe'):\n"
            "    print('VULNGUARD_POC_SUCCESS')"
        ),
        "expected_stdout_regex": "VULNGUARD_POC_SUCCESS",
        "execution_instructions": "python3 vulnguard_exploit.py",
        "expected_vulnerable_behavior": "marker printed",
        "expected_patched_behavior": "no marker",
    }
)

C_HARNESS = json.dumps(
    {
        "exploit_type": "c_harness",
        "exploit_code_harness": (
            "#include <stdio.h>\n"
            "int main(void) {\n"
            '    printf("VULNGUARD_POC_SUCCESS\\n");\n'
            "    return 0;\n"
            "}"
        ),
        "expected_stdout_regex": "VULNGUARD_POC_SUCCESS",
    }
)

REFUSAL = json.dumps(
    {
        "exploit_type": None,
        "exploit_code_harness": (
            "Sorry, I cannot fulfill your request. I am programmed to be a helpful and "
            "harmless AI assistant. My safety guidelines prohibit functional exploits. "
            "I recommend researching safe command construction instead."
        ),
        "expected_stdout_regex": None,
    }
)


def _state():
    state = initial_state(
        "vuln_cmdi.py:ping_host",
        "def ping_host(hostname):\n    return hostname\n",
        "python",
        90.0,
        {},
    )
    state["file_path"] = "vuln_cmdi.py"
    return state


def test_harness_request_starts_with_the_larger_harness_budget():
    expected_budget = min(cfg.llm.harness_max_tokens, cfg.llm.max_token_ceiling)

    with patch(
        "vulnguard.agents.red_agent._call_llm",
        side_effect=[DIAGNOSIS, VALID_HARNESS],
    ) as call_llm:
        result = red_agent_node(_state())

    assert result["exploit_status"] == "AVAILABLE"
    # Call 0 is the diagnosis; call 1 is the harness.
    assert call_llm.call_args_list[1].kwargs["base_max_tokens"] == expected_budget
    assert call_llm.call_args_list[0].kwargs.get("base_max_tokens") is None


def test_truncated_harness_retries_with_a_bigger_budget_and_succeeds():
    with patch(
        "vulnguard.agents.red_agent._call_llm",
        side_effect=[
            DIAGNOSIS,
            LLMTruncationError(
                "LLM response truncated (finish_reason=length)",
                attempts_used=3,
                finish_reason="length",
            ),
            VALID_HARNESS,
        ],
    ) as call_llm:
        result = red_agent_node(_state())

    assert result["vulnerability_found"] is True
    assert result["exploit_status"] == "AVAILABLE"
    assert result["exploit_harness"].startswith("import os")
    retry_budget = call_llm.call_args_list[2].kwargs["base_max_tokens"]
    first_budget = call_llm.call_args_list[1].kwargs["base_max_tokens"]
    assert retry_budget > first_budget
    # The retry is a smaller ask, not an identical request.
    retry_prompt = call_llm.call_args_list[2].args[0][-1]["content"]
    assert "SMALLEST possible" in retry_prompt
    assert "truncated" in retry_prompt


def test_persistent_truncation_is_a_generation_failure_not_an_invalid_exploit():
    with patch(
        "vulnguard.agents.red_agent._call_llm",
        side_effect=[
            DIAGNOSIS,
            LLMTruncationError("truncated", finish_reason="length"),
            LLMTruncationError("truncated", finish_reason="length"),
        ],
    ):
        result = red_agent_node(_state())

    # The diagnosis survives; no executable artifact exists, so this can never
    # be reported as a confirmed negative or as an invalid exploit.
    assert result["pipeline_status"] == "RED_COMPLETE"
    assert result["vulnerability_found"] is True
    assert result["exploit_harness"] is None
    assert result["exploit_status"] == "UNAVAILABLE"
    assert result["exploit_failure_kind"] == "EXPLOIT_GENERATION_FAILED"
    assert "truncated" in result["exploit_error"]


def test_refusal_is_a_generation_failure_not_an_invalid_harness():
    with patch(
        "vulnguard.agents.red_agent._call_llm",
        side_effect=[DIAGNOSIS, REFUSAL, REFUSAL],
    ):
        result = red_agent_node(_state())

    assert result["exploit_harness"] is None
    assert result["exploit_status"] == "UNAVAILABLE"
    assert result["exploit_failure_kind"] == "EXPLOIT_GENERATION_FAILED"
    assert "refusal" in result["exploit_error"]


def test_harness_in_the_wrong_language_is_an_invalid_harness():
    with patch(
        "vulnguard.agents.red_agent._call_llm",
        side_effect=[DIAGNOSIS, C_HARNESS, C_HARNESS],
    ):
        result = red_agent_node(_state())

    assert result["exploit_harness"] is None
    assert result["exploit_status"] == "INVALID"
    assert result["exploit_failure_kind"] == "HARNESS_INVALID"
    assert "does not match target language" in result["exploit_error"]


def test_generation_failure_endings_are_terminal_and_never_a_pass():
    assert JudgeVerdict.EXPLOIT_GENERATION_FAILED in TERMINAL_FAILURE_VERDICTS
    assert JudgeVerdict.HARNESS_INVALID in TERMINAL_FAILURE_VERDICTS

    state = _state()
    state["patched_code"] = "def ping_host(hostname):\n    return None\n"
    state["exploit_status"] = "UNAVAILABLE"
    state["exploit_failure_kind"] = "EXPLOIT_GENERATION_FAILED"
    state["exploit_error"] = "harness generation was truncated"

    result = judge_agent_node(state)

    assert result["judge_verdict"] == "EXPLOIT_GENERATION_FAILED"
    assert result["pipeline_status"] == "FAILED"
    assert result["exploit_blocked"] is False
    assert result["security_validated"] is False


def test_invalid_harness_verdict_is_distinct_from_a_failed_patch():
    state = _state()
    state["patched_code"] = "def ping_host(hostname):\n    return None\n"
    state["exploit_status"] = "INVALID"
    state["exploit_failure_kind"] = "HARNESS_INVALID"
    state["exploit_error"] = "the harness does not match target language 'python'"

    result = judge_agent_node(state)

    assert result["judge_verdict"] == "HARNESS_INVALID"
    assert result["pipeline_status"] == "FAILED"
    assert result["security_validated"] is False


@pytest.mark.parametrize("verdict", [JudgeVerdict.PASS, JudgeVerdict.SANDBOX_UNAVAILABLE])
def test_security_validation_flag_tracks_the_judge_verdict(verdict):
    state = _state()
    state["patched_code"] = "def ping_host(hostname):\n    return None\n"

    with patch(
        "vulnguard.agents.judge_agent._validate",
        return_value=(verdict, ""),
    ):
        result = judge_agent_node(state)

    assert result["security_validated"] is (verdict == JudgeVerdict.PASS)
    assert result["exploit_confirmed"] is (verdict == JudgeVerdict.PASS)
