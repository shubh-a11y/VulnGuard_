"""End-to-end checks for the dashboard upload and scan transport."""

import io
import json
import sqlite3
import zipfile

from fastapi.testclient import TestClient

from vulnguard.models.risk_scorer import RiskResult
from vulnguard.ui.server import create_app
from vulnguard.ui.store import ScanStore

SOURCE = b"import os\r\n\r\ndef unsafe(value):\r\n    return eval(value)\r\n"


def _patch_high_risk_scorer(monkeypatch):
    monkeypatch.setattr("vulnguard.models.risk_scorer.RiskScorer.__init__", lambda self: None)
    monkeypatch.setattr(
        "vulnguard.models.risk_scorer.RiskScorer.optimal_threshold",
        property(lambda self: 65),
    )
    monkeypatch.setattr(
        "vulnguard.models.risk_scorer.RiskScorer.score",
        lambda self, code, language: RiskResult(risk_score=100.0),
    )


def _upload_function(client) -> dict:
    response = client.post(
        "/upload",
        files={"file": ("sample.py", SOURCE, "text/x-python")},
    )
    assert response.status_code == 200
    return response.json()["functions"][0]


def _scan_events(client, function: dict) -> list[dict]:
    with client.websocket_connect("/ws/scan") as websocket:
        websocket.send_json(function)
        events = []
        while True:
            event = websocket.receive_json()
            events.append(event)
            if event["type"] in {"complete", "error"}:
                break
    return events


class _FakeGraph:
    seen_state = None

    async def astream(self, state):
        type(self).seen_state = state
        yield {
            "red_agent": {
                "vulnerability_found": True,
                "exploit_harness": "print('EXPLOIT_SUCCESS')",
                "pipeline_status": "RED_COMPLETE",
            }
        }
        yield {
            "blue_agent": {
                "patched_code": "def unsafe(value):\n    return value",
                "patch_diff": "- return eval(value)\n+ return value",
                "pipeline_status": "BLUE_COMPLETE",
            }
        }
        yield {
            "judge_agent": {
                "judge_verdict": "PASS",
                "pipeline_status": "COMPLETE",
            }
        }


def test_upload_and_scan_workflow(monkeypatch, tmp_path):
    monkeypatch.setattr("vulnguard.models.risk_scorer.RiskScorer.__init__", lambda self: None)
    monkeypatch.setattr(
        "vulnguard.models.risk_scorer.RiskScorer.optimal_threshold",
        property(lambda self: 65),
    )
    monkeypatch.setattr(
        "vulnguard.models.risk_scorer.RiskScorer.score",
        lambda self, code, language: RiskResult(risk_score=100.0),
    )
    monkeypatch.setattr("vulnguard.agents.graph.compile_graph", lambda: _FakeGraph())

    app = create_app(
        db_path=tmp_path / "scans.db",
        upload_root=tmp_path / "uploads",
    )
    with TestClient(app) as client:
        response = client.post(
            "/upload",
            files={
                "file": (
                    "sample.py",
                    b"import os\r\n\r\ndef unsafe(value):\r\n    return eval(value)\r\n",
                    "text/x-python",
                )
            },
        )
        assert response.status_code == 200
        function = response.json()["functions"][0]
        assert function["name"] == "unsafe"

        with client.websocket_connect("/ws/scan") as websocket:
            websocket.send_json(function)
            events = []
            while True:
                event = websocket.receive_json()
                events.append(event)
                if event["type"] in {"complete", "error"}:
                    break

        scan_id = events[-1]["scan_id"]
        result = client.get(f"/api/results/{scan_id}")
        metrics = client.get("/api/metrics")

    assert events[-1]["type"] == "complete"
    assert [event.get("agent") for event in events if event.get("agent")] == [
        "red_agent", "blue_agent", "judge_agent"
    ]
    assert _FakeGraph.seen_state["context_bundle"]["imports"] == ["import os"]
    assert result.status_code == 200
    assert result.json()["patch_diff"].startswith("- return")
    assert metrics.json()["patches_validated"] == 1


def test_zip_repository_upload(tmp_path):
    archive_data = io.BytesIO()
    with zipfile.ZipFile(archive_data, "w") as archive:
        archive.writestr("sample/main.py", "from helper import clean\n\ndef run(value):\n    return clean(value)\n")
        archive.writestr("sample/helper.py", "def clean(value):\n    return value\n")

    app = create_app(db_path=tmp_path / "scans.db", upload_root=tmp_path / "uploads")
    with TestClient(app) as client:
        response = client.post(
            "/upload",
            files={"file": ("sample.zip", archive_data.getvalue(), "application/zip")},
        )

    assert response.status_code == 200
    assert response.json()["repository"] is True
    assert response.json()["files_scanned"] == 2
    assert {item["name"] for item in response.json()["functions"]} == {"run", "clean"}


def test_zip_path_traversal_is_rejected(tmp_path):
    archive_data = io.BytesIO()
    with zipfile.ZipFile(archive_data, "w") as archive:
        archive.writestr("../escape.py", "print('nope')")

    app = create_app(db_path=tmp_path / "scans.db", upload_root=tmp_path / "uploads")
    with TestClient(app) as client:
        response = client.post(
            "/upload",
            files={"file": ("unsafe.zip", archive_data.getvalue(), "application/zip")},
        )

    assert response.status_code == 400
    assert "unsafe path" in response.json()["detail"]
class _ExplodingGraph:
    """Simulates an agent/graph failure escaping the node boundary."""

    def __init__(self, message: str):
        self.message = message

    async def astream(self, state):
        yield {
            "red_agent": {
                "vulnerability_found": False,
                "pipeline_status": "RED_COMPLETE",
            }
        }
        raise RuntimeError(self.message)


class _RedErrorGraph:
    async def astream(self, state):
        yield {
            "red_agent": {
                "vulnerability_found": False,
                "pipeline_status": "RED_ERROR",
                "judge_verdict": "RED_AGENT_ERROR",
                "error_logs": "LLM response truncated (finish_reason=length)",
            }
        }


def _fix_payload(**overrides) -> dict:
    payload = {
        "function_id": "sample.py:unsafe",
        "file_path": "sample.py",
        "pipeline_status": "COMPLETE",
        "vulnerability_found": True,
        "judge_verdict": "PASS",
        "risk_score": 91.2,
        "patch_diff": "- return eval(value)\n+ return value",
        "patch_justification": "Stop evaluating user input.",
        "red_report": {
            "vulnerability_type": "CODE_INJECTION",
            "severity": "CRITICAL",
        },
        "attempt_number": 1,
    }
    payload.update(overrides)
    return payload


def test_successful_fixes_returns_only_validated_patches(tmp_path):
    db_path = tmp_path / "scans.db"
    store = ScanStore(db_path)
    store.save("scan-pass", _fix_payload())
    store.save(
        "scan-failed",
        _fix_payload(pipeline_status="FAILED", judge_verdict="EXPLOIT_NOT_REPRODUCED"),
    )
    store.save(
        "scan-unvalidated",
        _fix_payload(judge_verdict="EXPLOIT_UNAVAILABLE"),
    )

    app = create_app(db_path=db_path, upload_root=tmp_path / "uploads")
    with TestClient(app) as client:
        response = client.get("/api/scan/successful-fixes?limit=6")

    assert response.status_code == 200
    fixes = response.json()
    assert [fix["scan_id"] for fix in fixes] == ["scan-pass"]
    fix = fixes[0]
    assert fix["risk_score"] == 91.2
    assert fix["vulnerability_type"] == "CODE_INJECTION"
    assert fix["patch_diff_preview"][0].startswith("- return")
    assert fix["attempt_number"] == 2
    assert "result_json" not in fix


def test_successful_fixes_empty_result_is_an_empty_list(tmp_path):
    app = create_app(db_path=tmp_path / "scans.db", upload_root=tmp_path / "uploads")
    with TestClient(app) as client:
        response = client.get("/api/scan/successful-fixes?limit=6")

    assert response.status_code == 200
    assert response.json() == []


def test_successful_fixes_skips_unreadable_legacy_record(tmp_path):
    db_path = tmp_path / "scans.db"
    store = ScanStore(db_path)
    store.save("scan-pass", _fix_payload())
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO scans (
                scan_id, function_id, file_path, pipeline_status,
                vulnerability_found, judge_verdict, result_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "legacy",
                "old.py:old",
                "old.py",
                "COMPLETE",
                1,
                "PASS",
                "{not valid json",
                "2020-01-01T00:00:00+00:00",
                "2020-01-01T00:00:00+00:00",
            ),
        )

    app = create_app(db_path=db_path, upload_root=tmp_path / "uploads")
    with TestClient(app) as client:
        response = client.get("/api/scan/successful-fixes")

    assert response.status_code == 200
    assert [fix["scan_id"] for fix in response.json()] == ["scan-pass"]


def test_successful_fixes_rejects_invalid_limit(tmp_path):
    app = create_app(db_path=tmp_path / "scans.db", upload_root=tmp_path / "uploads")
    with TestClient(app) as client:
        assert client.get("/api/scan/successful-fixes?limit=0").status_code == 422
        assert client.get("/api/scan/successful-fixes?limit=500").status_code == 422


def test_successful_fixes_reports_real_database_errors(monkeypatch, tmp_path):
    app = create_app(db_path=tmp_path / "scans.db", upload_root=tmp_path / "uploads")

    def _boom(self, limit: int = 20):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(ScanStore, "successful_fixes", _boom)
    with TestClient(app) as client:
        response = client.get("/api/scan/successful-fixes")

    assert response.status_code == 500
    assert response.json()["detail"] == "Failed to load successful fixes"


def test_ws_graph_failure_is_reported_with_stage_and_persisted(monkeypatch, tmp_path):
    _patch_high_risk_scorer(monkeypatch)
    monkeypatch.setattr(
        "vulnguard.agents.graph.compile_graph",
        lambda: _ExplodingGraph("LLM response truncated (finish_reason=length)"),
    )

    app = create_app(db_path=tmp_path / "scans.db", upload_root=tmp_path / "uploads")
    with TestClient(app) as client:
        function = _upload_function(client)
        events = _scan_events(client, function)
        scan_id = events[-1]["scan_id"]
        result = client.get(f"/api/results/{scan_id}")

    error_events = [event for event in events if event["type"] == "error"]
    assert error_events
    assert error_events[0]["stage"] == "red_agent"
    assert "truncated" in error_events[0]["message"]
    persisted = result.json()
    assert persisted["pipeline_status"] == "ERROR"
    assert persisted["failed_stage"] == "red_agent"
    assert "truncated" in persisted["error_logs"]


def test_ws_red_error_is_not_recorded_as_a_clean_scan(monkeypatch, tmp_path):
    _patch_high_risk_scorer(monkeypatch)
    monkeypatch.setattr("vulnguard.agents.graph.compile_graph", lambda: _RedErrorGraph())

    app = create_app(db_path=tmp_path / "scans.db", upload_root=tmp_path / "uploads")
    with TestClient(app) as client:
        function = _upload_function(client)
        events = _scan_events(client, function)
        scan_id = events[-1]["scan_id"]
        result = client.get(f"/api/results/{scan_id}")

    complete = [event for event in events if event["type"] == "complete"][0]
    assert complete["pipeline_status"] == "FAILED"
    assert complete["judge_verdict"] == "RED_AGENT_ERROR"
    persisted = result.json()
    assert persisted["pipeline_status"] == "FAILED"
    assert persisted["judge_verdict"] == "RED_AGENT_ERROR"


def test_ws_failure_does_not_block_the_next_scan(monkeypatch, tmp_path):
    _patch_high_risk_scorer(monkeypatch)
    app = create_app(db_path=tmp_path / "scans.db", upload_root=tmp_path / "uploads")

    with TestClient(app) as client:
        function = _upload_function(client)

        monkeypatch.setattr(
            "vulnguard.agents.graph.compile_graph",
            lambda: _ExplodingGraph("transient agent failure"),
        )
        failed_events = _scan_events(client, function)
        assert failed_events[-1]["type"] == "error"

        monkeypatch.setattr("vulnguard.agents.graph.compile_graph", lambda: _FakeGraph())
        second_events = _scan_events(client, function)

    assert second_events[-1]["type"] == "complete"
    assert second_events[-1]["judge_verdict"] == "PASS"


class _StreamingGraph:
    """Emits real per-agent events, exactly like the agent nodes do."""

    async def astream(self, state):
        from vulnguard.agents.streaming import emit

        emit(state, "red_started", agent="red_agent")
        emit(
            state,
            "red_diagnosis",
            agent="red_agent",
            vulnerability_found=True,
            diagnosis={"vulnerability_type": "CODE_INJECTION", "cwe_id": "CWE-95"},
        )
        emit(
            state,
            "red_harness_generated",
            agent="red_agent",
            exploit_code_harness="print('EXPLOIT_SUCCESS')",
            expected_stdout_regex="EXPLOIT_SUCCESS",
            exploit_status="AVAILABLE",
        )
        emit(
            state,
            "red_completed",
            agent="red_agent",
            vulnerability_found=True,
            exploit_status="AVAILABLE",
            pipeline_status="RED_COMPLETE",
        )
        yield {
            "red_agent": {
                "vulnerability_found": True,
                "exploit_harness": "print('EXPLOIT_SUCCESS')",
                "expected_stdout_regex": "EXPLOIT_SUCCESS",
                "exploit_status": "AVAILABLE",
                "pipeline_status": "RED_COMPLETE",
            }
        }

        emit(state, "blue_started", agent="blue_agent")
        emit(
            state,
            "blue_patch_generated",
            agent="blue_agent",
            patched_code="def unsafe(value):\n    return value",
            patch_diff="--- original\n+++ patched\n+    return value",
            patch_justification="Stop evaluating input.",
        )
        emit(
            state,
            "blue_completed",
            agent="blue_agent",
            pipeline_status="BLUE_COMPLETE",
            patched_code="def unsafe(value):\n    return value",
            patch_diff="--- original\n+++ patched\n+    return value",
            patch_justification="Stop evaluating input.",
        )
        yield {
            "blue_agent": {
                "patched_code": "def unsafe(value):\n    return value",
                "patch_diff": "--- original\n+++ patched\n+    return value",
                "patch_justification": "Stop evaluating input.",
                "pipeline_status": "BLUE_COMPLETE",
            }
        }

        emit(state, "judge_started", agent="judge_agent")
        emit(
            state,
            "judge_original_result",
            agent="judge_agent",
            ran=True,
            reproduced=True,
            success=True,
            logs="ORIGINAL_EXECUTION_LOG",
        )
        emit(
            state,
            "judge_patched_result",
            agent="judge_agent",
            ran=True,
            reproduced=False,
            success=False,
            logs="PATCHED_EXECUTION_LOG",
        )
        emit(
            state,
            "judge_completed",
            agent="judge_agent",
            judge_verdict="PASS",
            pipeline_status="COMPLETE",
            build_success=True,
            test_success=True,
            exploit_confirmed=True,
            exploit_blocked=True,
            security_validated=True,
        )
        yield {
            "judge_agent": {
                "judge_verdict": "PASS",
                "pipeline_status": "COMPLETE",
                "security_validated": True,
            }
        }


def test_ws_streams_each_agent_result_in_pipeline_order(monkeypatch, tmp_path):
    _patch_high_risk_scorer(monkeypatch)
    monkeypatch.setattr("vulnguard.agents.graph.compile_graph", lambda: _StreamingGraph())

    app = create_app(db_path=tmp_path / "scans.db", upload_root=tmp_path / "uploads")
    with TestClient(app) as client:
        function = _upload_function(client)
        events = _scan_events(client, function)

    types = [event["type"] for event in events]
    expected_order = [
        "red_started",
        "red_diagnosis",
        "red_harness_generated",
        "red_completed",
        "agent_update",
        "blue_started",
        "blue_patch_generated",
        "blue_completed",
        "judge_started",
        "judge_original_result",
        "judge_patched_result",
        "judge_completed",
    ]
    assert [types.index(name) for name in expected_order] == sorted(
        types.index(name) for name in expected_order
    )

    by_type = {event["type"]: event for event in events if event["type"] not in {"agent_update"}}
    assert by_type["red_diagnosis"]["diagnosis"]["vulnerability_type"] == "CODE_INJECTION"
    assert by_type["red_harness_generated"]["exploit_code_harness"].startswith("print")
    assert by_type["blue_patch_generated"]["patched_code"].startswith("def unsafe")
    assert by_type["judge_original_result"]["logs"] == "ORIGINAL_EXECUTION_LOG"
    assert by_type["judge_patched_result"]["logs"] == "PATCHED_EXECUTION_LOG"
    assert by_type["judge_completed"]["security_validated"] is True

    for event in events:
        if event["type"] in {"status", "complete", "error"}:
            continue
        assert event["scan_id"] == events[-1]["scan_id"]
        assert event["function_id"] == function["id"]

    assert events[-1]["type"] == "complete"
    assert events[-1]["judge_verdict"] == "PASS"
