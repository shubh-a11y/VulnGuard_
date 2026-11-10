"""Progressive per-agent streaming: real results, in Red → Blue → Judge order.

The live stream receives intermediate events emitted by the nodes at the moment
they produce a result, not only a summary once a LangGraph node returns.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from vulnguard.agents import judge_agent, red_agent
from vulnguard.agents.blue_agent import blue_agent_node
from vulnguard.agents.judge_agent import judge_agent_node
from vulnguard.agents.red_agent import red_agent_node
from vulnguard.agents.state import initial_state
from vulnguard.agents.streaming import bind_events, unbind_events

SCAN_ID = "scan-123"
# `file_path` has no repository root here, so the adapter resolves the bare
# module name — exactly what a single-file upload produces.
HARNESS = (
    "from app import run\n"
    "print(run)\n"
    "print('VULNGUARD_POC_SUCCESS')"
)
MARKER = "VULNGUARD_POC_SUCCESS"


def _state(**overrides) -> dict:
    state = initial_state(
        "pkg/app.py:run",
        "def run(value):\n    return eval(value)\n",
        "python",
        92.0,
        {},
        scan_id=SCAN_ID,
    )
    state["file_path"] = "pkg/app.py"
    state.update(overrides)
    return state


def _report(**overrides) -> str:
    payload = {
        "vulnerability_found": True,
        "vulnerability_type": "CODE_INJECTION",
        "cwe_id": "CWE-95",
        "severity": "HIGH",
        "location": "pkg/app.py:run",
        "affected_lines": [2],
        "attack_strategy": "The argument is evaluated as code.",
        "explanation": "eval() executes attacker-controlled input.",
        "confidence": 0.9,
        "exploit_type": "python_script",
        "exploit_code_harness": HARNESS,
        "expected_stdout_regex": MARKER,
        "execution_instructions": "python3 exploit.py",
        "expected_vulnerable_behavior": "marker printed",
        "expected_patched_behavior": "no marker",
    }
    payload.update(overrides)
    return json.dumps(payload)


@pytest.fixture()
def sink():
    events: list[dict] = []
    bind_events(SCAN_ID, events.append)
    try:
        yield events
    finally:
        unbind_events(SCAN_ID)


def test_red_agent_streams_diagnosis_then_harness_then_completion(sink):
    with patch.object(red_agent, "_call_llm", return_value=_report()):
        red_agent_node(_state())

    assert [event["type"] for event in sink] == [
        "red_started",
        "red_diagnosis",
        "red_harness_generated",
        "red_completed",
    ]

    # Each event carries the real result produced at that point.
    assert sink[1]["diagnosis"]["vulnerability_type"] == "CODE_INJECTION"
    assert sink[1]["diagnosis"]["cwe_id"] == "CWE-95"
    assert sink[2]["exploit_code_harness"] == HARNESS
    assert sink[2]["exploit_status"] == "AVAILABLE"
    assert sink[3]["exploit_status"] == "AVAILABLE"
    assert sink[3]["pipeline_status"] == "RED_COMPLETE"

    for event in sink:
        assert event["scan_id"] == SCAN_ID
        assert event["function_id"] == "pkg/app.py:run"


def test_red_agent_streams_the_preserved_diagnosis_when_no_harness_exists(sink):
    missing = _report(exploit_code_harness=None, expected_stdout_regex=None)

    with patch.object(red_agent, "_call_llm", side_effect=[missing, missing]):
        result = red_agent_node(_state())

    assert result["exploit_status"] == "UNAVAILABLE"
    assert sink[2]["type"] == "red_harness_generated"
    assert sink[2]["exploit_code_harness"] is None
    assert "no exploit_code_harness" in sink[2]["exploit_error"]
    assert sink[3]["diagnosis"]["vulnerability_type"] == "CODE_INJECTION"


def test_blue_agent_streams_the_patch_before_completion(sink):
    state = _state(
        red_report={
            "vulnerability_type": "CODE_INJECTION",
            "cwe_id": "CWE-95",
            "explanation": "eval() executes attacker-controlled input.",
        },
        exploit_harness=HARNESS,
    )
    patch_response = json.dumps(
        {
            "patched_code": "def run(value):\n    return int(value)\n",
            "changes_summary": "Parse the value instead of executing it.",
            "preserved_interface": True,
            "new_dependencies_added": False,
            "justification": "int() cannot execute input.",
        }
    )

    with patch("vulnguard.agents.blue_agent._call_llm", return_value=patch_response):
        blue_agent_node(state)

    assert [event["type"] for event in sink] == [
        "blue_started",
        "blue_patch_generated",
        "blue_completed",
    ]
    generated = sink[1]
    assert generated["patched_code"].startswith("def run(value):")
    assert generated["patch_diff"].startswith("--- original")
    assert sink[2]["pipeline_status"] == "BLUE_COMPLETE"


def test_judge_streams_original_and_patched_execution_results(sink):
    state = _state(
        patched_code="def run(value):\n    return int(value)\n",
        exploit_harness=HARNESS,
        expected_stdout_regex=MARKER,
        exploit_status="AVAILABLE",
        red_report={
            "vulnerability_found": True,
            "vulnerability_type": "CODE_INJECTION",
            "exploit_code_harness": HARNESS,
            "expected_stdout_regex": MARKER,
        },
    )

    with patch(
        "vulnguard.sandbox.docker_runner.check_docker_available", return_value=True
    ), patch.object(
        judge_agent,
        "_run_exploit",
        side_effect=[
            (True, f"VULNGUARD_EXECUTION_STARTED\n{MARKER}"),
            (False, "VULNGUARD_EXECUTION_STARTED\nno marker"),
            (False, "VULNGUARD_EXECUTION_STARTED\nno marker"),
        ],
    ):
        result = judge_agent_node(state)

    types = [event["type"] for event in sink]
    assert types[:3] == ["judge_started", "judge_original_result", "judge_patched_result"]
    assert types[-1] == "judge_completed"
    assert types.index("judge_original_result") < types.index("judge_patched_result")

    original = sink[1]
    assert original["ran"] is True
    assert original["reproduced"] is True
    assert MARKER in original["logs"]

    patched = sink[2]
    assert patched["ran"] is True
    assert patched["reproduced"] is False
    assert "no marker" in patched["logs"]

    completed = sink[-1]
    assert completed["judge_verdict"] == "PASS"
    assert completed["exploit_confirmed"] is True
    assert completed["exploit_blocked"] is True
    assert completed["security_validated"] is True
    assert result["judge_verdict"] == "PASS"


def test_events_are_a_no_op_without_an_attached_stream():
    # No bind_events() for this scan: evaluation and CLI runs must be unaffected.
    state = _state(scan_id="unattached-scan")
    with patch.object(red_agent, "_call_llm", return_value=_report()):
        result = red_agent_node(state)

    assert result["exploit_status"] == "AVAILABLE"
