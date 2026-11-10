"""Language harness adapters: registry, target loading, validation, strategies."""

from __future__ import annotations

import pytest

from vulnguard.agents.harness import (
    adapter_capabilities,
    executable_languages,
    get_adapter,
    supported_languages,
)
from vulnguard.agents.harness.strategies import strategy_for, strategy_keys
from vulnguard.agents.red_agent import RedAgentReport, _exploit_validation_error
from vulnguard.agents.state import initial_state


def _state(function_id: str, language: str, *, repo_root: str = "", file_path: str = ""):
    state = initial_state(function_id, "pass", language, 90.0, {})
    state["file_path"] = file_path
    state["repo_root"] = repo_root
    return state


@pytest.mark.parametrize(
    ("alias", "expected"),
    [
        ("python", "python"),
        ("py", "python"),
        ("python3", "python"),
        ("c", "c"),
        ("c++", "cpp"),
        ("cpp", "cpp"),
        ("node", "javascript"),
        ("ts", "javascript"),
        ("java", "java"),
    ],
)
def test_language_aliases_resolve_to_the_right_adapter(alias, expected):
    assert get_adapter(alias).language == expected


def test_unknown_language_falls_back_to_an_unsupported_adapter():
    adapter = get_adapter("brainfuck")
    assert adapter.language == "generic"
    assert adapter.runtime_status == "unsupported"
    assert adapter.validation_error(RedAgentReport(vulnerability_found=True), {}) is None


def test_support_matrix_separates_verified_from_experimental_runtimes():
    assert set(executable_languages()) == {"python", "c", "cpp"}
    statuses = {entry["language"]: entry["runtime_status"] for entry in adapter_capabilities()}
    assert statuses["javascript"] == "experimental"
    assert statuses["java"] == "experimental"
    assert set(supported_languages()) == {"python", "c", "cpp", "javascript", "java"}


def test_python_adapter_resolves_import_and_class_from_the_repository(tmp_path):
    package = tmp_path / "src" / "billing"
    package.mkdir(parents=True)
    target = package / "invoices.py"
    target.write_text(
        "class InvoiceRepository:\n"
        "    def find_invoice(self, invoice_id):\n"
        "        return invoice_id\n",
        encoding="utf-8",
    )
    state = _state(
        "src/billing/invoices.py:find_invoice",
        "python",
        repo_root=str(tmp_path),
        file_path=str(target),
    )

    adapter = get_adapter("python")
    module, owner, target_name = adapter.module_and_owner(state)

    assert module == "src.billing.invoices"
    assert owner == "InvoiceRepository"
    assert target_name == "find_invoice"
    instruction = adapter.workspace_target_instruction(state)
    assert "from src.billing.invoices import InvoiceRepository" in instruction
    assert "find_invoice" in instruction


def test_python_adapter_accepts_a_harness_that_imports_the_real_target(tmp_path):
    target = tmp_path / "accounts.py"
    target.write_text("def lookup(name):\n    return name\n", encoding="utf-8")
    state = _state(
        "accounts.py:lookup",
        "python",
        repo_root=str(tmp_path),
        file_path=str(target),
    )
    report = RedAgentReport(
        vulnerability_found=True,
        exploit_code_harness=(
            "from accounts import lookup\n"
            "result = lookup(\"x' OR '1'='1\")\n"
            "print('VULNGUARD_POC_SUCCESS')"
        ),
        expected_stdout_regex="VULNGUARD_POC_SUCCESS",
    )

    assert get_adapter("python").validation_error(report, state) is None


def test_python_adapter_rejects_a_redefinition_of_the_target(tmp_path):
    target = tmp_path / "accounts.py"
    target.write_text("def lookup(name):\n    return name\n", encoding="utf-8")
    state = _state(
        "accounts.py:lookup",
        "python",
        repo_root=str(tmp_path),
        file_path=str(target),
    )
    report = RedAgentReport(
        vulnerability_found=True,
        exploit_code_harness=(
            "def lookup(name):\n    return name\nprint('VULNGUARD_POC_SUCCESS')"
        ),
        expected_stdout_regex="VULNGUARD_POC_SUCCESS",
    )

    assert "redefines target" in get_adapter("python").validation_error(report, state)


def test_c_adapter_requires_an_entry_point_and_a_call_to_the_target():
    state = _state("src/telemetry.c:ingest_sample", "c")

    no_main = RedAgentReport(
        vulnerability_found=True,
        exploit_code_harness='#include <stdio.h>\nvoid ingest_sample(char *input);',
        expected_stdout_regex="VULNGUARD_POC_SUCCESS",
    )
    assert "no int main()" in get_adapter("c").validation_error(no_main, state)

    no_target = RedAgentReport(
        vulnerability_found=True,
        exploit_code_harness=(
            '#include <stdio.h>\nint main(void) { printf("VULNGUARD_POC_SUCCESS\\n"); return 0; }'
        ),
        expected_stdout_regex="VULNGUARD_POC_SUCCESS",
    )
    assert "does not invoke target" in get_adapter("c").validation_error(no_target, state)


def test_c_adapter_accepts_a_prototype_plus_main_that_calls_the_target():
    state = _state("src/telemetry.c:ingest_sample", "c")
    report = RedAgentReport(
        vulnerability_found=True,
        exploit_code_harness=(
            "#include <stdio.h>\n"
            "void ingest_sample(char *input);\n"
            "int main(void) {\n"
            '    ingest_sample("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");\n'
            '    printf("VULNGUARD_POC_SUCCESS\\n");\n'
            "    return 0;\n"
            "}"
        ),
        expected_stdout_regex="VULNGUARD_POC_SUCCESS",
    )

    assert get_adapter("c").validation_error(report, state) is None


def test_javascript_adapter_requires_a_module_load_and_output():
    state = _state("lib/report.js:renderReport", "javascript")
    valid = RedAgentReport(
        vulnerability_found=True,
        exploit_code_harness=(
            "const report = require('./lib/report');\n"
            "const out = report.renderReport('<b>x</b>');\n"
            "if (out.includes('<b>')) {\n"
            "  console.log('VULNGUARD_POC_SUCCESS');\n"
            "}"
        ),
        expected_stdout_regex="VULNGUARD_POC_SUCCESS",
    )
    no_output = RedAgentReport(
        vulnerability_found=True,
        exploit_code_harness="const report = require('./lib/report');\nreport.renderReport('x');",
        expected_stdout_regex="VULNGUARD_POC_SUCCESS",
    )

    assert get_adapter("js").validation_error(valid, state) is None
    assert "observable output" in get_adapter("js").validation_error(no_output, state)


def test_java_adapter_requires_a_main_and_a_target_call():
    state = _state("src/main/java/Report.java:render", "java")
    valid = RedAgentReport(
        vulnerability_found=True,
        exploit_code_harness=(
            "public class Exploit {\n"
            "    public static void main(String[] args) throws Exception {\n"
            "        Report r = new Report();\n"
            "        r.render(args[0]);\n"
            '        System.out.println("VULNGUARD_POC_SUCCESS");\n'
            "    }\n"
            "}"
        ),
        expected_stdout_regex="VULNGUARD_POC_SUCCESS",
    )
    assert get_adapter("java").validation_error(valid, state) is None

    missing_main = RedAgentReport(
        vulnerability_found=True,
        exploit_code_harness="public class Exploit { void render() {} }",
        expected_stdout_regex="VULNGUARD_POC_SUCCESS",
    )
    assert "main" in get_adapter("java").validation_error(missing_main, state)


@pytest.mark.parametrize(
    ("vulnerability_type", "cwe", "expected"),
    [
        ("SQL_INJECTION", "CWE-89", "SQL_INJECTION"),
        ("COMMAND_INJECTION", None, "COMMAND_INJECTION"),
        (None, "CWE-121", "BUFFER_OVERFLOW"),
        ("FORMAT_STRING", "CWE-134", "FORMAT_STRING"),
        ("PATH_TRAVERSAL", None, "PATH_TRAVERSAL"),
        ("TOCTOU", None, "TOCTOU"),
        ("XSS", None, "XSS"),
        ("NOT_A_KNOWN_CLASS", None, "GENERIC_DEFECT"),
    ],
)
def test_strategy_selection_is_vulnerability_class_driven(vulnerability_type, cwe, expected):
    assert strategy_for(vulnerability_type, cwe).key == expected


def test_strategy_guidance_is_repository_independent():
    sql = strategy_for("SQL_INJECTION", "CWE-89").prompt_block()
    assert "in-memory SQLite" in sql
    assert "function" not in sql.lower().split("class:")[0]

    generic = strategy_for(None, None).prompt_block()
    assert "Class: GENERIC_DEFECT" in generic
    assert len(set(strategy_keys())) == len(strategy_keys())


def test_every_adapter_exposes_a_non_empty_shape():
    for adapter in (get_adapter(name) for name in supported_languages()):
        assert adapter.shape().strip()
        assert adapter.to_dict()["runtime_status"] in {"verified", "experimental"}
