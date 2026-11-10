"""Red Agent harness reliability: one structured request, bounded recovery.

The regression these tests lock down (``the harness JSON had no
exploit_code_harness``) came from asking for the diagnosis in one request and
the harness in a second one: in JSON mode the second response could legally be
``{"exploit_code_harness": null}``. The report is now produced by a single
request, and a missing harness triggers exactly one regeneration.
"""

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

PYTHON_HARNESS = (
    "import os\n"
    "from vuln_cmdi import ping_host\n"
    "ping_host('localhost; touch /tmp/vg_probe')\n"
    "if os.path.exists('/tmp/vg_probe'):\n"
    "    print('VULNGUARD_POC_SUCCESS')"
)

DIAGNOSIS_FIELDS = {
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


def _report(**overrides) -> str:
    """One structured response carrying both halves of the report."""
    payload = {
        **DIAGNOSIS_FIELDS,
        "exploit_type": "python_script",
        "exploit_code_harness": PYTHON_HARNESS,
        "expected_stdout_regex": "VULNGUARD_POC_SUCCESS",
        "execution_instructions": "python3 vulnguard_exploit.py",
        "expected_vulnerable_behavior": "marker printed",
        "expected_patched_behavior": "no marker",
    }
    payload.update(overrides)
    return json.dumps(payload)


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


# ── Objective 1: diagnosis and harness in one structured response ─────────


def test_one_structured_response_contains_the_diagnosis_and_the_harness():
    with patch("vulnguard.agents.red_agent._call_llm", return_value=_report()) as call_llm:
        result = red_agent_node(_state())

    # Exactly one paid request: no separate harness call exists any more.
    assert call_llm.call_count == 1
    system_prompt = call_llm.call_args_list[0].args[0][0]["content"]
    assert "ONE structured JSON object" in system_prompt
    assert "exploit_code_harness" in system_prompt
    assert "vulnerability_found" in system_prompt

    assert result["vulnerability_found"] is True
    assert result["exploit_status"] == "AVAILABLE"
    assert result["exploit_harness"].startswith("import os")
    assert result["expected_stdout_regex"] == "VULNGUARD_POC_SUCCESS"
    assert result["red_report"]["vulnerability_type"] == "COMMAND_INJECTION"
    assert result["red_report"]["cwe_id"] == "CWE-78"
    assert result["pipeline_status"] == "RED_COMPLETE"


def test_missing_exploit_code_harness_triggers_exactly_one_regeneration():
    missing = _report(exploit_code_harness=None, expected_stdout_regex=None)

    with patch(
        "vulnguard.agents.red_agent._call_llm",
        side_effect=[missing, _report()],
    ) as call_llm:
        result = red_agent_node(_state())

    assert call_llm.call_count == 2
    retry_messages = call_llm.call_args_list[1].args[0]
    retry_prompt = retry_messages[-1]["content"]
    # The precise rejection is stated, and the complete report is requested.
    assert "no exploit_code_harness" in retry_prompt
    assert "Keep its diagnosis exactly as it is" in retry_prompt
    assert {"role": "assistant", "content": missing} in retry_messages

    assert result["exploit_status"] == "AVAILABLE"
    assert result["exploit_harness"].startswith("import os")
    # The preserved diagnosis, not the second response's wording.
    assert result["red_report"]["vulnerability_type"] == "COMMAND_INJECTION"
    assert result["red_report"]["explanation"].startswith("Hostname is interpolated")


def test_invalid_second_response_keeps_the_diagnosis_and_records_the_reason():
    missing = _report(exploit_code_harness=None, expected_stdout_regex=None)

    with patch(
        "vulnguard.agents.red_agent._call_llm",
        side_effect=[missing, missing],
    ) as call_llm:
        result = red_agent_node(_state())

    assert call_llm.call_count == 2
    assert result["vulnerability_found"] is True
    assert result["exploit_harness"] is None
    assert result["exploit_status"] == "UNAVAILABLE"
    assert result["exploit_failure_kind"] == "EXPLOIT_GENERATION_FAILED"
    assert "no exploit_code_harness" in result["exploit_error"]
    # The diagnosis is preserved and still reaches the Blue Agent.
    assert result["red_report"]["vulnerability_type"] == "COMMAND_INJECTION"
    assert result["red_report"]["cwe_id"] == "CWE-78"
    assert result["pipeline_status"] == "RED_COMPLETE"


def test_unreadable_response_gets_one_corrective_request_with_the_whole_schema():
    with patch(
        "vulnguard.agents.red_agent._call_llm",
        side_effect=["Sure! Here is my analysis:", _report()],
    ) as call_llm:
        result = red_agent_node(_state())

    assert call_llm.call_count == 2
    correction = call_llm.call_args_list[1].args[0][-1]["content"]
    assert "could not be read as a valid JSON object" in correction
    assert "exploit_code_harness" in correction
    assert result["exploit_status"] == "AVAILABLE"


def test_persistent_truncation_is_an_explicit_error_not_a_false_negative():
    with patch(
        "vulnguard.agents.red_agent._call_llm",
        side_effect=LLMTruncationError("truncated", finish_reason="length"),
    ):
        result = red_agent_node(_state())

    # A single response that never arrived yields no diagnosis to preserve, so
    # the pipeline reports an agent error rather than "no vulnerability".
    assert result["pipeline_status"] == "RED_ERROR"
    assert result["judge_verdict"] == "RED_AGENT_ERROR"
    assert result["vulnerability_found"] is False
    assert "truncated" in result["error_logs"]


def test_refusal_is_a_generation_failure_not_an_invalid_harness():
    refusal = (
        "Sorry, I cannot fulfill your request. I am programmed to be a helpful and "
        "harmless AI assistant. My safety guidelines prohibit functional exploits. "
        "I recommend researching safe command construction instead."
    )
    bad = _report(exploit_code_harness=refusal)

    with patch("vulnguard.agents.red_agent._call_llm", side_effect=[bad, bad]):
        result = red_agent_node(_state())

    assert result["exploit_harness"] is None
    assert result["exploit_status"] == "UNAVAILABLE"
    assert result["exploit_failure_kind"] == "EXPLOIT_GENERATION_FAILED"
    assert "refusal" in result["exploit_error"]


def test_harness_in_the_wrong_language_is_an_invalid_harness():
    c_harness = (
        "#include <stdio.h>\n"
        "int main(void) {\n"
        '    printf("VULNGUARD_POC_SUCCESS\\n");\n'
        "    return 0;\n"
        "}"
    )
    wrong = _report(exploit_type="c_harness", exploit_code_harness=c_harness)

    with patch("vulnguard.agents.red_agent._call_llm", side_effect=[wrong, wrong]):
        result = red_agent_node(_state())

    assert result["exploit_harness"] is None
    assert result["exploit_status"] == "INVALID"
    assert result["exploit_failure_kind"] == "HARNESS_INVALID"
    assert "does not match target language" in result["exploit_error"]


def test_harness_aliases_are_accepted_without_losing_the_body():
    payload = json.loads(_report())
    payload.pop("exploit_code_harness")
    payload["exploit_code"] = PYTHON_HARNESS

    with patch("vulnguard.agents.red_agent._call_llm", return_value=json.dumps(payload)):
        result = red_agent_node(_state())

    assert result["exploit_status"] == "AVAILABLE"
    assert result["exploit_harness"].startswith("import os")


def test_default_report_budget_uses_the_harness_budget():
    expected_budget = min(cfg.llm.harness_max_tokens, cfg.llm.max_token_ceiling)

    with patch("vulnguard.agents.red_agent._call_llm", return_value=_report()) as call_llm:
        red_agent_node(_state())

    assert call_llm.call_args_list[0].kwargs["base_max_tokens"] == expected_budget


# ── Judge evidence gates remain intact ───────────────────────────────────


def test_generation_failure_endings_are_terminal_and_never_a_pass():
    assert JudgeVerdict.EXPLOIT_GENERATION_FAILED in TERMINAL_FAILURE_VERDICTS
    assert JudgeVerdict.HARNESS_INVALID in TERMINAL_FAILURE_VERDICTS

    state = _state()
    state["patched_code"] = "def ping_host(hostname):\n    return None\n"
    state["exploit_status"] = "UNAVAILABLE"
    state["exploit_failure_kind"] = "EXPLOIT_GENERATION_FAILED"
    state["exploit_error"] = "the harness JSON had no exploit_code_harness"

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
