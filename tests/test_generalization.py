"""Generalization: the Red Agent must work on repositories it has never seen.

Two kinds of coverage are kept deliberately separate:

* ``test_regression_dataset_*`` — the labeled ``data/test_vulns`` cohort, used
  only to prove the generic pipeline still handles the known scenarios.
* ``test_independent_*`` — repositories constructed here with different names,
  layouts and dependencies, which the production code has never seen.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from vulnguard.agents.harness import get_adapter
from vulnguard.agents.harness.environment import probe_repository
from vulnguard.agents.red_agent import red_agent_node
from vulnguard.agents.state import initial_state

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MARKER = "VULNGUARD_POC_SUCCESS"


def _diagnosis(vuln_type: str = "SQL_INJECTION", cwe: str = "CWE-89") -> str:
    return json.dumps(
        {
            "vulnerability_found": True,
            "vulnerability_type": vuln_type,
            "cwe_id": cwe,
            "severity": "HIGH",
            "location": "derived from the analyzed source",
            "affected_lines": [4],
            "attack_strategy": "Untrusted input reaches the sink without validation.",
            "explanation": "The sink interprets attacker-controlled input as syntax.",
            "confidence": 0.9,
        }
    )


def _harness(**fields) -> str:
    payload = {
        "exploit_type": "script",
        "exploit_code_harness": "",
        "expected_stdout_regex": MARKER,
        "execution_instructions": "run the harness",
        "expected_vulnerable_behavior": "the defect is observed",
        "expected_patched_behavior": "the defect no longer occurs",
    }
    payload.update(fields)
    return json.dumps(payload)


def _state(payload: dict) -> dict:
    state = initial_state(
        f"{payload['relative_path']}:{payload['name']}",
        payload["code"],
        payload["language"],
        90.0,
        {},
        file_path=payload["file_path"],
        repo_root=payload["repo_root"],
        start_byte=payload.get("start_byte"),
        end_byte=payload.get("end_byte"),
    )
    return state


def _run(state: dict, diagnosis: str, harness: str) -> dict:
    with patch("vulnguard.agents.red_agent._call_llm", side_effect=[diagnosis, harness]) as call:
        result = red_agent_node(state)
    return result, call


# ── Independent repositories (never used to develop the fixes) ────────────


@pytest.fixture()
def invoices_repo(tmp_path: Path) -> dict:
    package = tmp_path / "svc" / "billing"
    package.mkdir(parents=True)
    (tmp_path / "svc" / "__init__.py").write_text("", encoding="utf-8")
    (package / "__init__.py").write_text("", encoding="utf-8")
    source = package / "invoices.py"
    source.write_text(
        "class InvoiceRepository:\n"
        "    def __init__(self, dsn):\n"
        "        self.dsn = dsn\n"
        "\n"
        "    def find_invoice(self, invoice_id):\n"
        "        query = f\"SELECT * FROM invoices WHERE id = '{invoice_id}'\"\n"
        "        return self.dsn.execute(query).fetchall()\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        "[project]\n"
        'name = "acme-billing"\n'
        'dependencies = ["vg-absent-dependency-xyz>=1.0"]\n',
        encoding="utf-8",
    )
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_invoices.py").write_text(
        "def test_placeholder():\n    assert True\n", encoding="utf-8"
    )
    return {
        "id": "svc/billing/invoices.py:find_invoice",
        "name": "find_invoice",
        "code": source.read_text(encoding="utf-8"),
        "language": "python",
        "file_path": str(source),
        "repo_root": str(tmp_path),
        "relative_path": "svc/billing/invoices.py",
    }


def test_independent_python_repository_is_probed_from_its_actual_layout(invoices_repo):
    env = probe_repository(
        invoices_repo["repo_root"],
        invoices_repo["language"],
        invoices_repo["file_path"],
    )

    assert env.target_module == "svc.billing.invoices"
    assert "pyproject.toml" in env.manifests
    assert any("tests/" in marker for marker in env.test_infrastructure)
    assert any("vg-absent-dependency-xyz" in dep for dep in env.missing_dependencies)
    assert any("not importable" in limitation for limitation in env.limitations)


def test_independent_python_repository_generates_a_repository_specific_harness(invoices_repo):
    harness = (
        "from svc.billing.invoices import InvoiceRepository\n"
        "repo = InvoiceRepository(None)\n"
        "try:\n"
        "    repo.find_invoice(\"1' OR '1'='1\")\n"
        "except Exception:\n"
        "    pass\n"
        f"print('{MARKER}')"
    )

    result, call = _run(_state(invoices_repo), _diagnosis(), _harness(exploit_code_harness=harness))

    assert result["exploit_status"] == "AVAILABLE", result.get("exploit_error")
    prompt = call.call_args_list[1].args[0]
    prompt_text = "\n".join(message["content"] for message in prompt)

    # Everything the model needs is derived from this repository.
    assert "svc.billing.invoices" in prompt_text
    assert "InvoiceRepository" in prompt_text
    assert "in-memory SQLite" in prompt_text
    assert "vg-absent-dependency-xyz" in prompt_text
    # ... and not from the regression dataset.
    assert "test_vulns" not in prompt_text
    assert "vuln_" not in prompt_text
    assert "ping_host" not in prompt_text

    stored = result["red_report"]["harness_environment"]
    assert stored["target_module"] == "svc.billing.invoices"
    assert stored["runtime_status"] == "verified"


def test_independent_c_repository_uses_the_c_adapter(tmp_path: Path):
    source = tmp_path / "src" / "telemetry.c"
    source.parent.mkdir()
    source.write_text(
        "void ingest_sample(char *input) {\n"
        "    char buffer[16];\n"
        "    strcpy(buffer, input);\n"
        "}\n",
        encoding="utf-8",
    )
    payload = {
        "name": "ingest_sample",
        "code": source.read_text(encoding="utf-8"),
        "language": "c",
        "file_path": str(source),
        "repo_root": str(tmp_path),
        "relative_path": "src/telemetry.c",
    }
    harness = (
        "#include <stdio.h>\n"
        "void ingest_sample(char *input);\n"
        "int main(void) {\n"
        '    ingest_sample("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");\n'
        f'    printf("{MARKER}\\n");\n'
        "    return 0;\n"
        "}"
    )

    result, call = _run(
        _state(payload),
        _diagnosis("BUFFER_OVERFLOW", "CWE-121"),
        _harness(exploit_type="c_harness", exploit_code_harness=harness),
    )

    assert result["exploit_status"] == "AVAILABLE", result.get("exploit_error")
    prompt_text = "\n".join(
        message["content"] for message in call.call_args_list[1].args[0]
    )
    assert "int main(void)" in prompt_text
    assert "AddressSanitizer" in prompt_text
    assert "telemetry.c" in prompt_text
    assert get_adapter("c").validation_error(
        type("Report", (), {"exploit_code_harness": harness, "expected_stdout_regex": MARKER})(),
        _state(payload),
    ) is None


def test_independent_javascript_repository_uses_the_javascript_adapter(tmp_path: Path):
    source = tmp_path / "lib" / "report.js"
    source.parent.mkdir()
    source.write_text(
        "function renderReport(input) { return `<div>${input}</div>`; }\n"
        "module.exports = { renderReport };\n",
        encoding="utf-8",
    )
    payload = {
        "name": "renderReport",
        "code": source.read_text(encoding="utf-8"),
        "language": "javascript",
        "file_path": str(source),
        "repo_root": str(tmp_path),
        "relative_path": "lib/report.js",
    }
    harness = (
        "const report = require('./lib/report');\n"
        "const out = report.renderReport('<img src=x onerror=alert(1)>');\n"
        "if (out.includes('<img')) {\n"
        f"  console.log('{MARKER}');\n"
        "}"
    )

    result, _ = _run(
        _state(payload),
        _diagnosis("XSS", "CWE-79"),
        _harness(exploit_type="javascript_script", exploit_code_harness=harness),
    )

    assert result["exploit_status"] == "AVAILABLE", result.get("exploit_error")
    assert "experimental" in result["red_report"]["harness_environment"]["runtime_status"]


def test_production_agent_code_contains_no_dataset_fixtures():
    """The Red Agent and adapters must not encode the regression corpus."""
    production = [PROJECT_ROOT / "vulnguard" / "agents" / "red_agent.py"]
    production.extend((PROJECT_ROOT / "vulnguard" / "agents" / "harness").glob("*.py"))

    forbidden = (
        "test_vulns",
        "vuln_sqli",
        "vuln_cmdi",
        "vuln_buffer",
        "vuln_format",
        "vuln_race",
        "vuln_taint_flow",
        "ping_host",
        "process_data",
        "get_user",
    )
    for path in production:
        text = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in text, f"{path.name} hardcodes fixture token {token!r}"


# ── Regression dataset: data/test_vulns (six labeled scenarios) ───────────


def _fixture_harness(payload: dict) -> str:
    language = payload["language"]
    target = payload["name"]

    if language == "python":
        module, owner, _ = get_adapter("python").module_and_owner(payload)
        return (
            f"from {module} import {owner}\n"
            f"print({owner})\n"
            f"print('{MARKER}')"
        )

    return (
        "#include <stdio.h>\n"
        f"void {target}(char *input);\n"
        "int main(void) {\n"
        f'    {target}("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");\n'
        f'    printf("{MARKER}\\n");\n'
        "    return 0;\n"
        "}"
    )


def test_regression_dataset_all_six_scenarios_still_produce_a_valid_harness():
    from vulnguard.evaluation import KNOWN_VULN_FUNCTIONS, _load_function_payload

    assert len(KNOWN_VULN_FUNCTIONS) == 6

    for spec in KNOWN_VULN_FUNCTIONS:
        payload = _load_function_payload(spec)
        harness = _fixture_harness(payload)

        result, _ = _run(
            _state(payload),
            _diagnosis("GENERIC_DEFECT", ""),
            _harness(exploit_code_harness=harness),
        )

        assert result["exploit_status"] == "AVAILABLE", (
            payload["id"],
            result.get("exploit_error"),
        )
        assert result["pipeline_status"] == "RED_COMPLETE"
        assert result["vulnerability_found"] is True
        assert result["red_report"]["harness_environment"]["repo_root"]
