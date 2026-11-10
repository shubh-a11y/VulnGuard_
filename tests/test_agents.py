"""
Tests for the agent system (state, Red Agent parsing, Blue Agent checks).

Uses mocks for LLM calls — no actual API calls needed.
"""

import json
import pytest
from unittest.mock import patch, MagicMock

from langgraph.graph import END as GRAPH_END

from vulnguard.agents.graph import _after_red, _after_judge
from vulnguard.agents.llm_calls import LLMProviderError, LLMTruncationError, call_llm_json
from vulnguard.agents.llm_parsing import (
    is_truncated_response,
    parse_agent_json,
    strip_code_fences,
    unwrap_schema_payload,
)

from vulnguard.agents.state import VulnGuardState, initial_state
from vulnguard.agents.red_agent import (
    RedAgentDiagnosis,
    RedAgentReport,
    _call_llm,
    _exploit_validation_error,
    _harness_messages,
    red_agent_node,
    _validate_exploit_language,
    _sanitize_exploit,
)
from vulnguard.agents.blue_agent import (
    _check_ast_loc_delta,
    _insecure_patch_reason,
    blue_agent_node,
)
from vulnguard.agents.judge_agent import (
    JudgeVerdict,
    _exploit_succeeded,
    _run_tests,
    _truncate_error_logs,
    _validate,
    judge_agent_node,
)
from vulnguard.sandbox.docker_runner import CommandResult


class TestInitialState:
    def test_creates_valid_state(self):
        state = initial_state(
            function_id="test_fn",
            code="int f() { return 1; }",
            language="c",
            risk_score=75.0,
            context_bundle={"imports": []},
        )
        assert state["function_id"] == "test_fn"
        assert state["attempt_number"] == 0
        assert state["max_attempts"] == 3
        assert state["pipeline_status"] == "TRIAGE"
        assert state["vulnerability_found"] is False

    def test_attempt_history_starts_empty(self):
        state = initial_state("fn", "code", "c", 50.0, {})
        assert state["attempt_history"] == []


class TestRedAgentReport:
    def test_no_vulnerability_report(self):
        report = RedAgentReport(vulnerability_found=False)
        assert not report.vulnerability_found
        assert report.vulnerability_type is None
        assert report.exploit_code_harness is None

    def test_full_report(self):
        report = RedAgentReport(
            vulnerability_found=True,
            vulnerability_type="SQL_INJECTION",
            cwe_id="CWE-89",
            severity="CRITICAL",
            affected_lines=[42, 43],
            explanation="User input concatenated into SQL query",
            exploit_type="python_script",
            exploit_code_harness='import requests\nr = requests.get("...',
            expected_stdout_regex="SQL Error",
            confidence=0.95,
        )
        assert report.vulnerability_found
        assert report.severity == "CRITICAL"

    def test_json_roundtrip(self):
        report = RedAgentReport(vulnerability_found=True, vulnerability_type="XSS")
        json_str = report.model_dump_json()
        parsed = RedAgentReport.model_validate_json(json_str)
        assert parsed.vulnerability_type == "XSS"

    def test_mock_response_matches_diagnosis_schema(self):
        with patch("vulnguard.agents.red_agent.cfg") as mock_cfg:
            mock_cfg.llm.mock_mode = True
            response = _call_llm([], risk_score=100.0)

        report = RedAgentReport.model_validate_json(response)
        assert report.vulnerability_found is True
        # The mock returns the diagnosis phase only; the harness is a separate call.
        assert report.exploit_code_harness is None

    def test_schema_wrapped_response_is_unwrapped(self):
        state = initial_state("fn", "def fn():\n    pass", "python", 90.0, {})
        response = json.dumps(
            {
                "description": "Structured threat report",
                "properties": {"vulnerability_found": False},
            }
        )

        with patch("vulnguard.agents.red_agent._call_llm", return_value=response):
            result = red_agent_node(state)

        assert result["pipeline_status"] == "RED_COMPLETE"
        assert result["vulnerability_found"] is False


class TestExploitLanguageValidation:
    """Test EC-7.2: Language match validation."""

    def test_c_exploit_matches_c(self):
        report = RedAgentReport(
            vulnerability_found=True,
            exploit_code_harness='#include <stdio.h>\nint main() { printf("pwned"); }',
        )
        assert _validate_exploit_language(report, "c") is True

    def test_python_exploit_mismatches_c(self):
        report = RedAgentReport(
            vulnerability_found=True,
            exploit_code_harness='import os\nos.system("echo pwned")',
        )
        assert _validate_exploit_language(report, "c") is False

    def test_no_exploit_always_valid(self):
        report = RedAgentReport(vulnerability_found=True, exploit_code_harness=None)
        assert _validate_exploit_language(report, "c") is True

    def test_rejects_harness_that_redefines_python_target(self):
        report = RedAgentReport(
            vulnerability_found=True,
            exploit_code_harness="def update_user_status(value):\n    print(value)",
            expected_stdout_regex="DEFECT_TRIGGERED",
        )
        state = initial_state("database.py:update_user_status", "pass", "python", 90.0, {})
        state["file_path"] = "database.py"

        assert "redefines target" in _exploit_validation_error(report, state)

    def test_accepts_harness_that_imports_python_target(self, tmp_path):
        package = tmp_path / "vuln_taint_flow"
        package.mkdir()
        target = package / "database.py"
        target.write_text(
            "class Database:\n"
            "    def update_user_status(self, value):\n"
            "        pass\n"
        )
        report = RedAgentReport(
            vulnerability_found=True,
            exploit_code_harness=(
                "from vuln_taint_flow.database import Database\n"
                "print(Database)"
            ),
            expected_stdout_regex="DEFECT_TRIGGERED",
        )
        state = initial_state("vuln_taint_flow/database.py:update_user_status", "pass", "python", 90.0, {})
        state["file_path"] = str(target)
        state["repo_root"] = str(tmp_path)

        assert _exploit_validation_error(report, state) is None

    def test_rejects_marker_embedded_in_exploit_input(self):
        report = RedAgentReport(
            vulnerability_found=True,
            exploit_code_harness=(
                "from vuln_cmdi import ping_host\n"
                "ping_host('localhost; echo DEFECT_TRIGGERED')"
            ),
            expected_stdout_regex="DEFECT_TRIGGERED",
        )
        state = initial_state("vuln_cmdi.py:ping_host", "pass", "python", 90.0, {})
        state["file_path"] = "vuln_cmdi.py"

        assert "embedded in exploit input" in _exploit_validation_error(report, state)

    def test_rejects_harness_without_success_regex(self):
        report = RedAgentReport(
            vulnerability_found=True,
            exploit_code_harness="from vuln_sqli import get_user",
        )
        state = initial_state("vuln_sqli.py:get_user", "pass", "python", 90.0, {})
        state["file_path"] = "vuln_sqli.py"

        assert "no expected_stdout_regex" in _exploit_validation_error(report, state)

    def test_rejects_refusal_text_as_harness(self):
        report = RedAgentReport(
            vulnerability_found=True,
            exploit_code_harness=(
                "Sorry, I cannot fulfill your request. I am programmed to be a helpful "
                "and harmless AI assistant. My safety guidelines strictly prohibit me "
                "from creating functional exploit payloads. I recommend researching "
                "safe string handling functions like strncpy or snprintf."
            ),
            expected_stdout_regex="VULNGUARD_POC_SUCCESS",
        )
        state = initial_state("vuln_buffer.c:process_data", "pass", "c", 90.0, {})

        assert "refusal" in _exploit_validation_error(report, state)

    def test_rejects_c_harness_without_main(self):
        report = RedAgentReport(
            vulnerability_found=True,
            exploit_code_harness=(
                '#include <stdio.h>\nvoid process_data(char *input) { printf("%s", input); }'
            ),
            expected_stdout_regex="VULNGUARD_POC_SUCCESS",
        )
        state = initial_state("vuln_buffer.c:process_data", "pass", "c", 90.0, {})

        assert "no int main" in _exploit_validation_error(report, state)

    def test_accepts_c_harness_with_main(self):
        report = RedAgentReport(
            vulnerability_found=True,
            exploit_code_harness=(
                "#include <stdio.h>\n"
                "void process_data(char *input);\n"
                "int main(void) {\n"
                '    process_data("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");\n'
                '    printf("VULNGUARD_POC_SUCCESS\\n");\n'
                "    return 0;\n"
                "}"
            ),
            expected_stdout_regex="VULNGUARD_POC_SUCCESS",
        )
        state = initial_state("vuln_buffer.c:process_data", "pass", "c", 90.0, {})

        assert _exploit_validation_error(report, state) is None

    def test_c_harness_rejected_for_python_target(self):
        report = RedAgentReport(
            vulnerability_found=True,
            exploit_code_harness='#include <stdio.h>\nint main(void) { printf("x"); }',
            expected_stdout_regex="VULNGUARD_POC_SUCCESS",
        )
        state = initial_state("vuln_cmdi.py:ping_host", "pass", "python", 90.0, {})
        state["file_path"] = "vuln_cmdi.py"

        assert "does not match target language 'python'" in _exploit_validation_error(
            report, state
        )

    def test_harness_prompt_pins_target_language(self):
        state = initial_state("vuln_buffer.c:process_data", "pass", "c", 90.0, {})
        diagnosis = RedAgentDiagnosis(vulnerability_found=True)

        system_prompt = _harness_messages(state, diagnosis)[0]["content"]

        assert "The target language is c" in system_prompt
        assert "#include <stdio.h>" in system_prompt
        assert "int main(void)" in system_prompt
        assert "Never switch languages" in system_prompt

    def test_rejects_python_harness_for_c_target(self):
        report = RedAgentReport(
            vulnerability_found=True,
            exploit_code_harness="import subprocess\nprint('DEFECT_TRIGGERED')",
            expected_stdout_regex="DEFECT_TRIGGERED",
        )
        state = initial_state("vuln_buffer.c:process_data", "pass", "c", 90.0, {})

        assert "does not match target language" in _exploit_validation_error(report, state)

    def test_invalid_harness_is_included_in_corrective_prompt(self):
        invalid = json.dumps(
            {
                "vulnerability_found": True,
                "vulnerability_type": "COMMAND_INJECTION",
                "exploit_code_harness": (
                    "from vuln_cmdi import ping_host\n"
                    "ping_host('localhost; echo DEFECT_TRIGGERED')"
                ),
                "expected_stdout_regex": "DEFECT_TRIGGERED",
            }
        )
        corrected = json.dumps(
            {
                "vulnerability_found": True,
                "vulnerability_type": "COMMAND_INJECTION",
                "exploit_code_harness": (
                    "import os\nfrom vuln_cmdi import ping_host\n"
                    "ping_host('localhost; touch /tmp/vg_probe')\n"
                    "if os.path.exists('/tmp/vg_probe'):\n    print('DEFECT_TRIGGERED')"
                ),
                "expected_stdout_regex": "DEFECT_TRIGGERED",
            }
        )
        state = initial_state("vuln_cmdi.py:ping_host", "pass", "python", 90.0, {})
        state["file_path"] = "vuln_cmdi.py"

        diagnosis = json.dumps(
            {
                "vulnerability_found": True,
                "vulnerability_type": "COMMAND_INJECTION",
                "explanation": "Shell metacharacters reach the command string",
            }
        )

        with patch(
            "vulnguard.agents.red_agent._call_llm",
            side_effect=[diagnosis, invalid, corrected],
        ) as call_llm:
            result = red_agent_node(state)

        # Call 1 = diagnosis, call 2 = harness, call 3 = corrective harness prompt.
        retry_messages = call_llm.call_args_list[2].args[0]
        assert {"role": "assistant", "content": invalid} in retry_messages
        assert "embedded in exploit input" in retry_messages[-1]["content"]
        assert "touch /tmp/vg_probe" in result["exploit_harness"]
        assert result["exploit_status"] == "AVAILABLE"

    def test_empty_harness_gets_one_corrective_retry(self):
        empty = json.dumps(
            {
                "exploit_type": None,
                "exploit_code_harness": None,
                "expected_stdout_regex": None,
            }
        )
        corrected = json.dumps(
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
            }
        )
        diagnosis = json.dumps(
            {
                "vulnerability_found": True,
                "vulnerability_type": "COMMAND_INJECTION",
                "explanation": "Shell metacharacters reach the command string",
            }
        )
        state = initial_state("vuln_cmdi.py:ping_host", "pass", "python", 90.0, {})
        state["file_path"] = "vuln_cmdi.py"

        with patch(
            "vulnguard.agents.red_agent._call_llm",
            side_effect=[diagnosis, empty, corrected],
        ) as call_llm:
            result = red_agent_node(state)

        retry_messages = call_llm.call_args_list[2].args[0]
        assert "no exploit_code_harness" in retry_messages[-1]["content"]
        assert retry_messages[2]["content"] == empty
        assert result["exploit_status"] == "AVAILABLE"
        assert "VULNGUARD_POC_SUCCESS" in result["exploit_harness"]

    def test_rejects_generic_exception_as_exploit_success(self):
        report = RedAgentReport(
            vulnerability_found=True,
            exploit_code_harness=(
                "from vuln_sqli import get_user\n"
                "try:\n    get_user('x')\n"
                "except Exception:\n    print('DEFECT_TRIGGERED')"
            ),
            expected_stdout_regex="DEFECT_TRIGGERED",
        )
        state = initial_state("vuln_sqli.py:get_user", "pass", "python", 90.0, {})
        state["file_path"] = "vuln_sqli.py"

        assert "false positives" in _exploit_validation_error(report, state)


class TestExploitSanitization:
    """Test Section 4.3: Dangerous payload detection."""

    def test_removes_rm_rf(self):
        report = RedAgentReport(
            vulnerability_found=True,
            exploit_code_harness='system("rm -rf /");',
            confidence=0.9,
        )
        sanitized = _sanitize_exploit(report)
        assert "DANGEROUS PAYLOAD REMOVED" in sanitized.exploit_code_harness
        assert sanitized.confidence == 0.0

    def test_preserves_safe_exploit(self):
        report = RedAgentReport(
            vulnerability_found=True,
            exploit_code_harness='printf("test output");',
            confidence=0.9,
        )
        sanitized = _sanitize_exploit(report)
        assert "printf" in sanitized.exploit_code_harness
        assert sanitized.confidence == 0.9


class TestAntiTrivialityCheck:
    """Test Section 4.4: Destructive patch rejection."""

    def test_rejects_destructive_patch(self):
        original = "\n".join(["line"] * 100)
        patched = "\n".join(["line"] * 20)  # 80% reduction
        ok, reason = _check_ast_loc_delta(original, patched, min_ratio=0.4)
        assert ok is False
        assert "DESTRUCTIVE_PATCH" in reason

    def test_accepts_reasonable_patch(self):
        original = "\n".join(["line"] * 100)
        patched = "\n".join(["line"] * 80)  # 20% reduction
        ok, reason = _check_ast_loc_delta(original, patched, min_ratio=0.4)
        assert ok is True

    def test_accepts_equal_length(self):
        code = "int f() { return 1; }"
        ok, _ = _check_ast_loc_delta(code, code, min_ratio=0.4)
        assert ok is True

    def test_handles_empty_original(self):
        ok, _ = _check_ast_loc_delta("", "int f() { return 1; }", min_ratio=0.4)
        assert ok is True

    def test_rejects_command_injection_patch_that_keeps_os_system(self):
        state = initial_state("vuln_cmdi.py:ping_host", "pass", "python", 90.0, {})
        state["red_report"] = {"vulnerability_type": "COMMAND_INJECTION"}

        reason = _insecure_patch_reason(state, "os.system(' '.join(command))")

        assert "still invokes a shell" in reason

    def test_successful_retry_clears_previous_judge_error(self):
        state = initial_state("vuln_cmdi.py:ping_host", "def ping_host(host):\n    return 0", "python", 90.0, {})
        state["red_report"] = {"vulnerability_type": "COMMAND_INJECTION"}
        state["judge_verdict"] = "NEW_VULNERABILITY_INTRODUCED"
        state["error_logs"] = "old failure"
        response = json.dumps(
            {
                "patched_code": "def ping_host(host):\n    return os.spawnvp(os.P_WAIT, 'ping', ['ping', host])",
                "changes_summary": "Use shell-free execution",
                "preserved_interface": True,
                "new_dependencies_added": False,
                "justification": "Arguments are not interpreted by a shell",
            }
        )

        with patch("vulnguard.agents.blue_agent._call_llm", return_value=response):
            result = blue_agent_node(state)

        assert result["judge_verdict"] == ""
        assert result["error_logs"] == ""


class TestErrorLogTruncation:
    """Test Section 4.6: Error log filtering."""

    def test_short_logs_unchanged(self):
        logs = "error: undefined reference to 'foo'"
        result = _truncate_error_logs(logs, max_chars=2000)
        assert result == logs

    def test_long_logs_filtered(self):
        lines = ["noise line"] * 500 + ["error: something failed"] + ["more noise"] * 500
        logs = "\n".join(lines)
        result = _truncate_error_logs(logs, max_chars=500)
        assert "error: something failed" in result
        assert len(result) <= 600  # Some tolerance for truncation marker


class TestJudgeVerdict:
    def test_all_verdicts_are_strings(self):
        for v in JudgeVerdict:
            assert isinstance(v.value, str)

    def test_pass_is_pass(self):
        assert JudgeVerdict.PASS.value == "PASS"

    def test_memory_crash_reproduces_exploit_after_execution_started(self):
        logs = "VULNGUARD_EXECUTION_STARTED\n*** stack smashing detected ***: terminated"
        assert _exploit_succeeded(False, logs, "DEFECT_TRIGGERED", "BUFFER_OVERFLOW")

    def test_safe_memory_output_does_not_match_broad_exploit_regex(self):
        logs = "VULNGUARD_EXECUTION_STARTED\nProcessed: AAAAAAAAAAAAAAA"
        assert not _exploit_succeeded(True, logs, r"Processed: A+", "BUFFER_OVERFLOW")

    def test_compiler_error_does_not_reproduce_exploit(self):
        logs = "undefined reference; source contains DEFECT_TRIGGERED"
        assert not _exploit_succeeded(False, logs, "DEFECT_TRIGGERED", "BUFFER_OVERFLOW")

    def test_no_collected_tests_are_skipped(self):
        state = initial_state("fn", "def fn():\n    return 1", "python", 90.0, {})
        runner = MagicMock()
        runner.run_tests.return_value = CommandResult(
            success=False,
            exit_code=5,
            stdout="no tests ran in 0.00s",
            stderr="",
        )

        with patch("vulnguard.sandbox.docker_runner.DockerRunner", return_value=runner):
            success, message = _run_tests(state)

        assert success is True
        assert "skipped" in message

    def test_missing_docker_returns_static_only_verdict(self):
        state = initial_state("fn", "def fn():\n    return 1", "python", 90.0, {})
        state["patched_code"] = "def fn():\n    return 2"

        with patch(
            "vulnguard.sandbox.docker_runner.check_docker_available",
            return_value=False,
        ):
            verdict, message = _validate(state)

        assert verdict == JudgeVerdict.SANDBOX_UNAVAILABLE
        assert "Static syntax" in message

    def test_static_only_verdict_completes_without_retry(self):
        state = initial_state("fn", "def fn():\n    return 1", "python", 90.0, {})
        state["patched_code"] = "def fn():\n    return 2"

        with patch(
            "vulnguard.agents.judge_agent._validate",
            return_value=(JudgeVerdict.SANDBOX_UNAVAILABLE, "static only"),
        ):
            result = judge_agent_node(state)

        assert result["pipeline_status"] == "COMPLETE"
        assert result["judge_verdict"] == "SANDBOX_UNAVAILABLE"
        assert "attempt_number" not in result
        assert result["build_success"] is False
        assert result["test_success"] is False
        assert result["exploit_blocked"] is False


class TestLLMParsingHelpers:
    """Shared parsing helpers used by Red and Blue agent nodes."""

    def test_strips_whole_payload_fence(self):
        payload = '```json\n{"a": 1}\n```'
        assert strip_code_fences(payload) == '{"a": 1}'

    def test_leaves_unfenced_json_unchanged(self):
        payload = '{"a": 1}'
        assert strip_code_fences(payload) == '{"a": 1}'

    def test_unwraps_schema_echoed_response(self):
        schema = RedAgentReport
        data = {
            "type": "object",
            "properties": {"vulnerability_found": False},
        }
        unwrapped = unwrap_schema_payload(data, schema)
        assert unwrapped == {"vulnerability_found": False}

    def test_parse_agent_json_accepts_fences_and_plain(self):
        good = json.dumps({"vulnerability_found": False})
        report, error = parse_agent_json("```json\n" + good + "\n```", RedAgentReport)
        assert error == ""
        assert report is not None
        report2, error2 = parse_agent_json(good, RedAgentReport)
        assert error2 == ""
        assert report2 is not None

    def test_parse_agent_json_rejects_truncated_json(self):
        truncated = (
            '{\n  "vulnerability_found": true,\n'
            '  "vulnerability_type": "COMMAND_INJECTION",\n  "cwe'
        )
        report, error = parse_agent_json(truncated, RedAgentReport)
        assert report is None
        assert error

    def test_is_truncated_response_detects_finish_reason(self):
        resp = MagicMock()
        choice = MagicMock()
        choice.finish_reason = "length"
        resp.choices = [choice]
        assert is_truncated_response(resp) is True

        choice.finish_reason = "stop"
        assert is_truncated_response(resp) is False


class TestRedAgentParseFailures:
    """Truncated/malformed model output must never become a false negative."""

    TRUNCATED = (
        '{\n'
        '  "vulnerability_found": true,\n'
        '  "vulnerability_type": "COMMAND_INJECTION",\n'
        '  "cwe'
    )
    NEGATIVE = json.dumps({"vulnerability_found": False})
    DIAGNOSIS = json.dumps(
        {
            "vulnerability_found": True,
            "vulnerability_type": "COMMAND_INJECTION",
            "cwe_id": "CWE-78",
            "severity": "HIGH",
            "explanation": "Shell metacharacters reach the command string",
            "confidence": 0.9,
        }
    )

    def test_truncated_json_becomes_red_error_not_negative_detection(self):
        state = initial_state("vuln_cmdi.py:ping_host", "def ping_host():\n    pass", "python", 90.0, {})

        with patch(
            "vulnguard.agents.red_agent._call_llm",
            side_effect=[self.TRUNCATED, self.TRUNCATED, self.TRUNCATED, self.TRUNCATED],
        ) as call_llm:
            result = red_agent_node(state)

        # Two full-diagnosis attempts, then two compact-mode attempts.
        assert len(call_llm.call_args_list) == 4
        assert result["pipeline_status"] == "RED_ERROR"
        assert result["judge_verdict"] == "RED_AGENT_ERROR"
        assert result["red_report"]["parse_error"]
        assert result["red_report"]["raw"].startswith('{')
        # The failure must not leak into a RED_COMPLETE-style result:
        assert "exploit_harness" in result and result["exploit_harness"] is None

    def test_parse_failure_retries_with_corrective_prompt(self):
        state = initial_state("vuln_cmdi.py:ping_host", "def ping_host():\n    pass", "python", 90.0, {})

        with patch(
            "vulnguard.agents.red_agent._call_llm",
            side_effect=[self.TRUNCATED, self.NEGATIVE],
        ) as call_llm:
            result = red_agent_node(state)

        assert result["pipeline_status"] == "RED_COMPLETE"
        assert result["vulnerability_found"] is False
        retry_messages = call_llm.call_args_list[1].args[0]
        corrective_prompts = [
            message["content"]
            for message in retry_messages
            if message["role"] == "user" and "not valid JSON" in message["content"]
        ]
        assert corrective_prompts

    def test_fenced_json_is_parsed(self):
        state = initial_state("vuln_cmdi.py:ping_host", "def ping_host():\n    pass", "python", 90.0, {})
        fenced = "```json\n" + self.NEGATIVE + "\n```"

        with patch("vulnguard.agents.red_agent._call_llm", return_value=fenced):
            result = red_agent_node(state)

        assert result["pipeline_status"] == "RED_COMPLETE"
        assert result["vulnerability_found"] is False

    def test_provider_error_is_not_swallowed_as_negative(self):
        state = initial_state("vuln_cmdi.py:ping_host", "def ping_host():\n    pass", "python", 90.0, {})

        with patch(
            "vulnguard.agents.red_agent._call_llm",
            side_effect=LLMProviderError("provider unavailable"),
        ):
            result = red_agent_node(state)

        # A provider failure terminates the *agent*, never the scan, and is
        # never reported as "no vulnerability found".
        assert result["pipeline_status"] == "RED_ERROR"
        assert result["judge_verdict"] == "RED_AGENT_ERROR"
        assert "provider unavailable" in result["error_logs"]
        assert result["vulnerability_found"] is False

    def test_harness_only_requested_when_a_defect_is_diagnosed(self):
        state = initial_state("vuln_cmdi.py:ping_host", "def ping_host():\n    pass", "python", 90.0, {})

        with patch(
            "vulnguard.agents.red_agent._call_llm", return_value=self.NEGATIVE
        ) as call_llm:
            result = red_agent_node(state)

        assert len(call_llm.call_args_list) == 1
        assert result["exploit_status"] == "NONE"

    def test_diagnosis_survives_harness_truncation(self):
        state = initial_state("vuln_cmdi.py:ping_host", "def ping_host():\n    pass", "python", 90.0, {})

        with patch(
            "vulnguard.agents.red_agent._call_llm",
            side_effect=[
                self.DIAGNOSIS,
                LLMTruncationError("LLM response truncated (finish_reason=length)"),
                LLMTruncationError("LLM response truncated (finish_reason=length)"),
            ],
        ):
            result = red_agent_node(state)

        # The finding is preserved; only the proof of concept is missing. No
        # harness exists at all, so this is a generation failure (UNAVAILABLE),
        # never an invalid exploit and never a confirmed negative.
        assert result["pipeline_status"] == "RED_COMPLETE"
        assert result["vulnerability_found"] is True
        assert result["red_report"]["vulnerability_type"] == "COMMAND_INJECTION"
        assert result["red_report"]["explanation"]
        assert result["exploit_harness"] is None
        assert result["exploit_status"] == "UNAVAILABLE"
        assert result["exploit_failure_kind"] == "EXPLOIT_GENERATION_FAILED"
        assert "truncated" in result["exploit_error"]

    def test_invalid_harness_never_becomes_an_exploit(self):
        state = initial_state("vuln_cmdi.py:ping_host", "def ping_host():\n    pass", "python", 90.0, {})
        bad_harness = json.dumps(
            {
                "exploit_type": "python_script",
                "exploit_code_harness": "print('DEFECT_TRIGGERED')",
                "expected_stdout_regex": "DEFECT_TRIGGERED",
            }
        )

        with patch(
            "vulnguard.agents.red_agent._call_llm",
            side_effect=[self.DIAGNOSIS, bad_harness, bad_harness],
        ):
            result = red_agent_node(state)

        assert result["vulnerability_found"] is True
        assert result["exploit_harness"] is None
        assert result["exploit_status"] == "INVALID"
        assert "must import" in result["exploit_error"]

    def test_generated_exploit_is_not_treated_as_validated(self):
        state = initial_state("vuln_cmdi.py:ping_host", "def ping_host():\n    pass", "python", 90.0, {})
        harness = json.dumps(
            {
                "exploit_type": "python_script",
                "exploit_code_harness": (
                    "import os\nfrom vuln_cmdi import ping_host\n"
                    "ping_host('localhost; touch /tmp/vg_probe')\n"
                    "if os.path.exists('/tmp/vg_probe'):\n    print('DEFECT_TRIGGERED')"
                ),
                "expected_stdout_regex": "DEFECT_TRIGGERED",
            }
        )
        state["file_path"] = "vuln_cmdi.py"

        with patch(
            "vulnguard.agents.red_agent._call_llm",
            side_effect=[self.DIAGNOSIS, harness],
        ):
            result = red_agent_node(state)

        # Exploit generated but NOT executed: judge sandbox state stays untouched.
        assert result["pipeline_status"] == "RED_COMPLETE"
        assert result["vulnerability_found"] is True
        assert result["exploit_status"] == "AVAILABLE"
        assert result["exploit_harness"]
        assert "build_success" not in result
        assert "exploit_blocked" not in result


class TestBlueAgentParseFailures:
    def test_parse_failure_is_reported_as_generation_failure(self):
        state = initial_state("vuln_diff.py:func", "def func():\n    pass", "python", 90.0, {})
        state["red_report"] = {"vulnerability_type": "COMMAND_INJECTION"}

        with patch(
            "vulnguard.agents.blue_agent._call_llm",
            side_effect=["{" * 3, "{" * 3],
        ) as call_llm:
            result = blue_agent_node(state)

        assert len(call_llm.call_args_list) == 2
        assert result["pipeline_status"] == "BLUE_ERROR"
        assert result["judge_verdict"] == "PATCH_GENERATION_FAILED"
        assert result["patched_code"] is None
        assert "not parseable" in result["error_logs"]

    def test_parse_failure_recovers_on_retry(self):
        state = initial_state("vuln_diff.py:func", "def func():\n    pass", "python", 90.0, {})
        state["red_report"] = {"vulnerability_type": "COMMAND_INJECTION"}
        good = json.dumps(
            {
                "patched_code": "def func():\n    pass",
                "changes_summary": "no change needed",
                "preserved_interface": True,
                "new_dependencies_added": False,
                "justification": "ok",
            }
        )

        with patch(
            "vulnguard.agents.blue_agent._call_llm",
            side_effect=["```json\n" + good[:-1], good],
        ):
            result = blue_agent_node(state)

        assert result["pipeline_status"] == "BLUE_COMPLETE"
        assert result["patched_code"] == "def func():\n    pass"


class TestJudgeGenerationFailure:
    """Blue Agent generation failures route into the bounded retry loop."""

    def _state(self, attempt: int = 0, max_attempts: int = 3):
        state = initial_state("vuln_diff.py:func", "def func():\n    pass", "python", 90.0, {})
        state["patched_code"] = None
        state["pipeline_status"] = "BLUE_ERROR"
        state["judge_verdict"] = JudgeVerdict.PATCH_GENERATION_FAILED.value
        state["error_logs"] = "Blue Agent output parse error after 3 attempts"
        state["attempt_number"] = attempt
        state["max_attempts"] = max_attempts
        return state

    def test_generation_failure_schedules_retry_with_feedback(self):
        result = judge_agent_node(self._state(attempt=0))

        assert result["pipeline_status"] == "RETRY"
        assert result["attempt_number"] == 1
        assert result["attempt_history"][0]["failure_reason"] == "PATCH_GENERATION_FAILED"
        assert "parse error" in result["attempt_history"][0]["error_logs"]

    def test_generation_failure_exhausted_retries_is_honest_failure(self):
        result = judge_agent_node(self._state(attempt=2, max_attempts=3))

        assert result["pipeline_status"] == "FAILED"
        assert result["judge_verdict"] == "MAX_RETRIES_EXHAUSTED"


class TestGraphRouting:
    def test_red_error_routes_to_end_without_blue(self):
        state = initial_state("fn", "code", "python", 90.0, {})
        state["vulnerability_found"] = False
        state["pipeline_status"] = "RED_ERROR"

        assert _after_red(state) is GRAPH_END

    def test_confirmed_negative_routes_to_end(self):
        state = initial_state("fn", "code", "python", 90.0, {})
        state["vulnerability_found"] = False
        state["pipeline_status"] = "RED_COMPLETE"

        assert _after_red(state) is GRAPH_END

    def test_detected_vulnerability_routes_to_blue(self):
        state = initial_state("fn", "code", "python", 90.0, {})
        state["vulnerability_found"] = True
        state["pipeline_status"] = "RED_COMPLETE"

        assert _after_red(state) == "blue_agent"


class TestLLMTruncationEscalation:
    """A truncated completion must be retried with a larger output budget."""

    @staticmethod
    def _llm_response(content: str, finish_reason: str = "stop"):
        resp = MagicMock()
        choice = MagicMock()
        choice.message.content = content
        choice.finish_reason = finish_reason
        resp.choices = [choice]
        return resp

    def test_truncated_completion_retries_with_larger_max_tokens(self):
        truncated = self._llm_response('{"vulnerability_found": tru', finish_reason="length")
        valid = self._llm_response(
            json.dumps({"vulnerability_found": False}),
            finish_reason="stop",
        )
        mock_cfg = MagicMock()
        mock_cfg.llm.mock_mode = False
        mock_cfg.llm.max_tokens = 100
        mock_cfg.llm.max_token_ceiling = 1000
        mock_cfg.llm.request_timeout_seconds = 5.0
        mock_cfg.llm.temperature = 0.0
        mock_cfg.llm.max_retries = 3
        mock_cfg.llm.retry_base_delay_seconds = 0.0
        mock_cfg.routing.get_model_for_score.return_value = ("gemini", "test-model")

        with patch("vulnguard.agents.red_agent.cfg", mock_cfg), patch(
            "vulnguard.llm_runtime.completion",
            side_effect=[truncated, truncated, valid],
        ) as completion_mock:
            result = _call_llm([], risk_score=50.0)

        assert result == json.dumps({"vulnerability_found": False})
        requested_tokens = [call.kwargs["max_tokens"] for call in completion_mock.call_args_list]
        assert requested_tokens == [100, 200, 400]
        assert completion_mock.call_args_list[0].kwargs["timeout"] == 5.0

    def test_truncation_at_the_ceiling_stops_without_repeating_the_call(self):
        truncated = self._llm_response('{"vulnerability_found": tru', finish_reason="length")

        with patch("vulnguard.llm_runtime.completion", return_value=truncated) as completion_mock:
            with pytest.raises(LLMTruncationError) as exc_info:
                call_llm_json(
                    [],
                    model="gemini/test-model",
                    attempts=5,
                    base_max_tokens=4096,
                    ceiling=4096,
                    retry_base_delay=0.0,
                )

        assert completion_mock.call_count == 1
        assert exc_info.value.attempts_used == 1
        assert "ceiling" in str(exc_info.value)

    def test_non_retryable_provider_error_fails_fast(self):
        class _BadRequest(Exception):
            pass

        with patch(
            "vulnguard.llm_runtime.completion", side_effect=_BadRequest("invalid model")
        ) as completion_mock:
            with pytest.raises(LLMProviderError):
                call_llm_json([], model="gemini/nope", attempts=3, retry_base_delay=0.0)

        assert completion_mock.call_count == 1


class TestJudgeVerdictSemantics:
    """Inconclusive or unproven evidence must never look like a secure patch."""

    HARNESS = (
        "import os\nfrom vuln_cmdi import ping_host\n"
        "ping_host('localhost; touch /tmp/vg_probe')\n"
        "if os.path.exists('/tmp/vg_probe'):\n    print('DEFECT_TRIGGERED')\n"
    )

    def _state(self, **overrides):
        state = initial_state(
            "vuln_cmdi.py:ping_host", "def ping_host():\n    return 0", "python", 90.0, {}
        )
        state["file_path"] = "vuln_cmdi.py"
        state["patched_code"] = "def ping_host():\n    return 1"
        state["red_report"] = {
            "vulnerability_found": True,
            "vulnerability_type": "COMMAND_INJECTION",
            "exploit_code_harness": self.HARNESS,
            "expected_stdout_regex": "DEFECT_TRIGGERED",
        }
        state["exploit_harness"] = self.HARNESS
        state["expected_stdout_regex"] = "DEFECT_TRIGGERED"
        state["exploit_status"] = "AVAILABLE"
        state.update(overrides)
        return state

    def test_no_exploit_is_never_a_pass(self):
        state = self._state(
            exploit_harness=None, red_report={}, exploit_status="NONE"
        )

        with patch(
            "vulnguard.sandbox.docker_runner.check_docker_available", return_value=True
        ):
            verdict, message = _validate(state)

        assert verdict == JudgeVerdict.EXPLOIT_UNAVAILABLE
        assert "NOT proven secure" in message

    def test_invalid_exploit_is_distinguished_from_a_failed_patch(self):
        state = self._state(
            exploit_harness=None,
            exploit_status="INVALID",
            exploit_error="harness redefines the target function",
        )

        with patch(
            "vulnguard.sandbox.docker_runner.check_docker_available", return_value=True
        ):
            verdict, message = _validate(state)

        assert verdict == JudgeVerdict.EXPLOIT_INVALID
        assert "redefines the target" in message

    def test_harness_that_never_runs_is_an_execution_error(self):
        with patch(
            "vulnguard.sandbox.docker_runner.check_docker_available", return_value=True
        ), patch(
            "vulnguard.agents.judge_agent._run_exploit",
            return_value=(False, "ModuleNotFoundError: No module named 'vuln_cmdi'"),
        ):
            verdict, message = _validate(self._state())

        assert verdict == JudgeVerdict.EXPLOIT_EXECUTION_ERROR
        assert "did not run" in message
        assert "ModuleNotFoundError" in message

    def test_execution_without_the_marker_is_not_reproduced(self):
        with patch(
            "vulnguard.sandbox.docker_runner.check_docker_available", return_value=True
        ), patch(
            "vulnguard.agents.judge_agent._run_exploit",
            return_value=(True, "VULNGUARD_EXECUTION_STARTED\nnormal output"),
        ):
            verdict, message = _validate(self._state())

        assert verdict == JudgeVerdict.EXPLOIT_NOT_REPRODUCED
        assert "did not demonstrate" in message

    def test_patched_source_that_stops_running_is_a_build_failure(self):
        with patch(
            "vulnguard.sandbox.docker_runner.check_docker_available", return_value=True
        ), patch(
            "vulnguard.agents.judge_agent._run_exploit",
            side_effect=[
                (False, "VULNGUARD_EXECUTION_STARTED\nDEFECT_TRIGGERED"),
                (False, "SyntaxError: invalid syntax"),
            ],
        ):
            verdict, message = _validate(self._state())

        assert verdict == JudgeVerdict.BUILD_FAILED
        assert "could not be executed" in message

    def test_dual_pass_with_a_blocking_patch_is_a_pass(self):
        clean = (True, "VULNGUARD_EXECUTION_STARTED\nclean run")
        triggering = (False, "VULNGUARD_EXECUTION_STARTED\nDEFECT_TRIGGERED")

        with patch(
            "vulnguard.sandbox.docker_runner.check_docker_available", return_value=True
        ), patch(
            "vulnguard.agents.judge_agent._run_exploit",
            side_effect=[triggering, clean, clean],
        ):
            verdict, message = _validate(self._state())

        assert verdict == JudgeVerdict.PASS
        assert message == ""


class TestJudgeRetryRouting:
    """Retry only what the patch can fix; never re-patch unproven evidence."""

    def _state(self, attempt: int = 0, max_attempts: int = 3):
        state = initial_state(
            "vuln_cmdi.py:ping_host", "def ping_host():\n    return 0", "python", 90.0, {}
        )
        state["patched_code"] = "def ping_host():\n    return 1"
        state["attempt_number"] = attempt
        state["max_attempts"] = max_attempts
        return state

    def test_exploit_not_reproduced_ends_without_asking_blue_for_a_patch(self):
        with patch(
            "vulnguard.agents.judge_agent._validate",
            return_value=(JudgeVerdict.EXPLOIT_NOT_REPRODUCED, "not reproduced"),
        ):
            result = judge_agent_node(self._state())

        assert result["pipeline_status"] == "FAILED"
        assert result["judge_verdict"] == "EXPLOIT_NOT_REPRODUCED"
        assert "attempt_history" not in result
        assert result["exploit_blocked"] is False

    def test_exploit_not_blocked_retries_blue_with_the_evidence(self):
        with patch(
            "vulnguard.agents.judge_agent._validate",
            return_value=(JudgeVerdict.EXPLOIT_NOT_BLOCKED, "marker still printed"),
        ):
            result = judge_agent_node(self._state())

        assert result["pipeline_status"] == "RETRY"
        assert result["attempt_number"] == 1
        assert result["attempt_history"][0]["failure_reason"] == "EXPLOIT_NOT_BLOCKED"
        assert "marker still printed" in result["attempt_history"][0]["error_logs"]

    def test_build_failure_exhaustion_is_reported_as_max_retries(self):
        with patch(
            "vulnguard.agents.judge_agent._validate",
            return_value=(JudgeVerdict.BUILD_FAILED, "syntax error"),
        ):
            result = judge_agent_node(self._state(attempt=2, max_attempts=3))

        assert result["pipeline_status"] == "FAILED"
        assert result["judge_verdict"] == "MAX_RETRIES_EXHAUSTED"

    def test_sandbox_unavailable_is_not_a_pass(self):
        with patch(
            "vulnguard.agents.judge_agent._validate",
            return_value=(JudgeVerdict.SANDBOX_UNAVAILABLE, "no docker"),
        ):
            result = judge_agent_node(self._state())

        assert result["pipeline_status"] == "COMPLETE"
        assert result["judge_verdict"] == "SANDBOX_UNAVAILABLE"
        assert result["exploit_blocked"] is False
