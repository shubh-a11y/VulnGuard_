"""SQLite persistence for dashboard scan results."""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


class ScanStore:
    """SQLite persistence for dashboard scan results.

    This is the operational store for the live dashboard. The research evaluation
    run keeps its own artifacts (JSON + paper-labeled PNGs) under data/benchmarks,
    and it also mirrors finished runs here so the dashboard analytics section has
    the same data to render from.
    """

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    function_id TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    pipeline_status TEXT NOT NULL,
                    vulnerability_found INTEGER NOT NULL,
                    judge_verdict TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def save(self, scan_id: str, result: dict[str, Any]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        payload = {**result, "scan_id": scan_id}
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO scans (
                    scan_id, function_id, file_path, pipeline_status,
                    vulnerability_found, judge_verdict, result_json,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    pipeline_status = excluded.pipeline_status,
                    vulnerability_found = excluded.vulnerability_found,
                    judge_verdict = excluded.judge_verdict,
                    result_json = excluded.result_json,
                    updated_at = excluded.updated_at
                """,
                (
                    scan_id,
                    str(payload.get("function_id", "unknown")),
                    str(payload.get("file_path", "")),
                    str(payload.get("pipeline_status", "UNKNOWN")),
                    int(bool(payload.get("vulnerability_found"))),
                    str(payload.get("judge_verdict", "")),
                    json.dumps(payload, default=str),
                    now,
                    now,
                ),
            )

    def get(self, scan_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT result_json FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        return json.loads(row["result_json"]) if row else None

    def list(self, limit: int = 100) -> dict[str, dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT scan_id, result_json FROM scans ORDER BY updated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return {row["scan_id"]: json.loads(row["result_json"]) for row in rows}

    def metrics(self) -> dict[str, int | float]:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    COALESCE(SUM(vulnerability_found), 0) AS vulnerable,
                    COALESCE(SUM(CASE WHEN judge_verdict = 'PASS' THEN 1 ELSE 0 END), 0) AS patched
                FROM scans
                """
            ).fetchone()
        total = int(row["total"])
        vulnerable = int(row["vulnerable"])
        patched = int(row["patched"])
        return {
            "total_scans": total,
            "vulnerabilities_found": vulnerable,
            "patches_validated": patched,
            "patch_rate": (patched / vulnerable) if vulnerable > 0 else 0.0,
        }

    def clear_all(self) -> int:
        """Clear all recorded scans from the operational store."""
        with self._connect() as connection:
            cursor = connection.execute("DELETE FROM scans")
            count = cursor.rowcount
            connection.commit()
        return count

    def model_health(self, triage_threshold: float = 30.0) -> dict[str, float]:
        """Compute live detection recall, triage precision, and patch success rate."""
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    COALESCE(SUM(vulnerability_found), 0) AS vulnerable,
                    COALESCE(SUM(CASE WHEN judge_verdict = 'PASS' THEN 1 ELSE 0 END), 0) AS patched
                FROM scans
                """
            ).fetchone()
            total = int(row["total"])
            vulnerable = int(row["vulnerable"])
            patched = int(row["patched"])

            if total == 0:
                return {"recall": 0.0, "precision": 0.0, "patch_success_rate": 0.0}

            rows = connection.execute(
                "SELECT vulnerability_found, judge_verdict, result_json FROM scans"
            ).fetchall()

        triaged_suspicious = 0
        triaged_confirmed_vuln = 0
        red_analyzed = 0

        for r in rows:
            is_vuln = int(r["vulnerability_found"]) == 1
            try:
                payload = json.loads(r["result_json"])
            except Exception:
                payload = {}

            score = float(payload.get("risk_score", 0.0))
            if score >= triage_threshold:
                triaged_suspicious += 1
                if is_vuln:
                    triaged_confirmed_vuln += 1

            red_rep = payload.get("red_report")
            if red_rep and isinstance(red_rep, dict):
                red_analyzed += 1

        triage_precision = (
            (triaged_confirmed_vuln / triaged_suspicious)
            if triaged_suspicious > 0
            else 0.0
        )
        patch_success_rate = (
            (patched / vulnerable)
            if vulnerable > 0
            else 0.0
        )
        detection_recall = (
            (vulnerable / red_analyzed)
            if red_analyzed > 0
            else (vulnerable / total if total > 0 else 0.0)
        )

        return {
            "recall": round(detection_recall, 4),
            "precision": round(triage_precision, 4),
            "patch_success_rate": round(patch_success_rate, 4),
        }

    def chart_data(self, triage_threshold: float = 30.0) -> dict[str, Any]:
        """Return 2D chart data for:
        1. ML Agent Classification Accuracy & Distribution
        2. Blue Agent Patch Remediation Outcomes
        """
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT vulnerability_found, judge_verdict, pipeline_status, result_json FROM scans"
            ).fetchall()

        triaged_confirmed = 0
        triaged_false_alarms = 0
        safe_filtered = 0

        patches_pass = 0
        patches_failed = 0
        unpatched = 0

        for r in rows:
            is_vuln = int(r["vulnerability_found"]) == 1
            verdict = str(r["judge_verdict"] or "").upper()
            try:
                payload = json.loads(r["result_json"])
            except Exception:
                payload = {}

            score = float(payload.get("risk_score", 0.0))
            if score >= triage_threshold:
                if is_vuln:
                    triaged_confirmed += 1
                else:
                    triaged_false_alarms += 1
            else:
                safe_filtered += 1

            if is_vuln:
                if verdict == "PASS":
                    patches_pass += 1
                elif verdict in ("FAIL", "BUILD_FAILED", "TEST_FAILED", "RETRY_EXHAUSTED", "REGRESSION_FAILED"):
                    patches_failed += 1
                elif payload.get("patched_code"):
                    patches_failed += 1
                else:
                    unpatched += 1

        total_scans = len(rows)
        total_triaged = triaged_confirmed + triaged_false_alarms
        ml_accuracy = (
            ((triaged_confirmed + safe_filtered) / total_scans)
            if total_scans > 0
            else 0.0
        )
        ml_precision = (
            (triaged_confirmed / total_triaged)
            if total_triaged > 0
            else 0.0
        )

        total_vulns = triaged_confirmed
        blue_psr = (
            (patches_pass / total_vulns)
            if total_vulns > 0
            else 0.0
        )

        return {
            "total_scans": total_scans,
            "ml_classification": {
                "accuracy": round(ml_accuracy, 4),
                "precision": round(ml_precision, 4),
                "confirmed_vulnerable": triaged_confirmed,
                "false_alarms": triaged_false_alarms,
                "clean_filtered": safe_filtered,
                "labels": ["Confirmed Vulnerable (TP)", "False Alarms (FP)", "Clean / Filtered (TN)"],
                "data": [triaged_confirmed, triaged_false_alarms, safe_filtered],
            },
            "blue_patching": {
                "patch_success_rate": round(blue_psr, 4),
                "patches_pass": patches_pass,
                "patches_failed": patches_failed,
                "unpatched": unpatched,
                "total_vulnerabilities": total_vulns,
                "labels": ["Patched & Validated (PASS)", "Failed Validation / Regression", "Unpatched / Failed Gen"],
                "data": [patches_pass, patches_failed, unpatched],
            },
        }

    def verdict_distribution(self) -> dict[str, int]:
        """Count scans by judge_verdict for the analytics section."""
        rows: list[tuple[str, int]] = []
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT judge_verdict, COUNT(*) AS count
                FROM scans
                WHERE pipeline_status IN ('COMPLETE', 'FAILED')
                GROUP BY judge_verdict
                ORDER BY count DESC
                """
            ).fetchall()
        return {row["judge_verdict"]: int(row["count"]) for row in rows}

    def successful_fixes(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return the most recent PASS scans with enough context for the analytics table.

        Only scans the Judge actually validated (``judge_verdict = 'PASS'``) are
        returned; a completed scan with an unvalidated patch is never included.
        Records whose persisted payload is unreadable (legacy or partial rows)
        are logged and skipped instead of fabricating missing fields or failing
        the whole dashboard query.
        """
        limit = max(1, min(int(limit), 100))
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT scan_id, function_id, file_path, pipeline_status,
                       vulnerability_found, judge_verdict, created_at, updated_at, result_json
                FROM scans
                WHERE pipeline_status = 'COMPLETE'
                  AND judge_verdict = 'PASS'
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        out: list[dict[str, Any]] = []
        for row in rows:
            try:
                payload = json.loads(row["result_json"])
            except (TypeError, ValueError) as exc:
                logger.warning(
                    "Skipping successful-fix record %s: unreadable result_json (%s)",
                    row["scan_id"],
                    exc,
                )
                continue
            if not isinstance(payload, dict):
                logger.warning(
                    "Skipping successful-fix record %s: result_json is not an object",
                    row["scan_id"],
                )
                continue

            red_report = payload.get("red_report")
            if not isinstance(red_report, dict):
                red_report = {}
            attempt = payload.get("attempt_number", 0)
            patch_diff = payload.get("patch_diff")

            record = {key: row[key] for key in row.keys() if key != "result_json"}
            record["risk_score"] = payload.get("risk_score")
            record["patch_diff_preview"] = (
                patch_diff.splitlines()[:30] if isinstance(patch_diff, str) else []
            )
            record["patch_justification"] = payload.get("patch_justification") or ""
            record["vulnerability_type"] = red_report.get("vulnerability_type")
            record["severity"] = red_report.get("severity")
            record["attempt_number"] = attempt + 1 if isinstance(attempt, int) else 1
            out.append(record)
        return out
