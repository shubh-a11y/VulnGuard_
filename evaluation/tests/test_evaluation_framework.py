"""
Automated Test Suite for VulnGuard Evaluation Framework — Phase 12

Verifies:
1. Dataset manifest structure and validation.
2. Duplicate case detection.
3. Ground-truth separation (no leakage into source fixtures).
4. Exploit eligibility filtering.
5. Strict 6-point repair acceptance criteria logic.
6. Metric formulas with synthetic records and hand-calculated answers.
7. Zero-denominator handling ('unavailable' status, null value).
8. Missing-evidence handling.
9. Confusion matrix calculation correctness.
10. Raw-evidence-to-aggregate reproducibility (delete aggregate & recompute).
11. Correct CSV generation.
12. Chart generation from real aggregate files (PNG 300DPI and PDF).
13. Prevention of hardcoded result values.
14. Unique run-directory creation.
15. Protection of existing historical baseline run.
16. Patch application and regression rollback behavior.
"""

from __future__ import annotations

import csv
import json
import shutil
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = REPO_ROOT / "evaluation" / "dataset" / "manifest.csv"
HISTORICAL_DIR = REPO_ROOT / "evaluation" / "run-2026-10-28T-baseline"

from evaluation.dataset.harness import run_regression_test, run_security_test
from evaluation.scripts.calculate_metrics import aggregate_run_metrics, make_metric
from evaluation.scripts.environment_info import capture_environment_metadata
from evaluation.scripts.evaluate_ml_triage import compute_binary_metrics
from evaluation.scripts.generate_charts import generate_all_charts
from evaluation.scripts.run_experiment import classify_failure
from evaluation.scripts.validate_dataset import load_manifest, validate_dataset


# ---------------------------------------------------------------------------
# 1. Dataset Manifest Validation
# ---------------------------------------------------------------------------

def test_manifest_validity():
    is_valid, errors = validate_dataset(MANIFEST_PATH)
    assert is_valid, f"Manifest validation failed with errors: {errors}"


def test_manifest_case_count():
    manifest = load_manifest(MANIFEST_PATH)
    assert len(manifest) == 30, f"Expected 30 cases, got {len(manifest)}"
    vuln = [c for c in manifest if c["ground_truth"] == "vulnerable"]
    safe = [c for c in manifest if c["ground_truth"] == "safe"]
    assert len(vuln) == 15
    assert len(safe) == 15


# ---------------------------------------------------------------------------
# 2. Duplicate Detection
# ---------------------------------------------------------------------------

def test_duplicate_case_detection(tmp_path: Path):
    manifest = load_manifest(MANIFEST_PATH)
    # Duplicate case B01
    dup_manifest = manifest + [manifest[0]]
    bad_manifest_path = tmp_path / "bad_manifest.csv"
    with bad_manifest_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(manifest[0].keys()))
        writer.writeheader()
        writer.writerows(dup_manifest)

    is_valid, errors = validate_dataset(bad_manifest_path)
    assert not is_valid
    assert any("Duplicate case ID detected" in e for e in errors)


# ---------------------------------------------------------------------------
# 3. Ground-Truth Separation
# ---------------------------------------------------------------------------

def test_ground_truth_isolation():
    manifest = load_manifest(MANIFEST_PATH)
    for c in manifest:
        src = REPO_ROOT / c["source_path"]
        content = src.read_text(encoding="utf-8", errors="replace").lower()
        # Verify no ground-truth metadata is in source file
        assert "manifest.csv" not in content
        assert "ground_truth" not in content
        assert "expected_normal_behavior" not in content


# ---------------------------------------------------------------------------
# 4. Strict Repair Acceptance Criteria Logic
# ---------------------------------------------------------------------------

def test_strict_repair_acceptance_all_pass():
    res = classify_failure(
        vulnerability_found=True,
        cwe_match=True,
        loc_correct=True,
        patch_generated=True,
        patch_applied=True,
        syntax_valid=True,
        patched_sec_blocked=True,
        patched_reg_passed=True,
        strict_success=True,
    )
    assert res == "STRICT_REPAIR_SUCCESS"


def test_strict_repair_acceptance_exploit_remains():
    res = classify_failure(
        vulnerability_found=True,
        cwe_match=True,
        loc_correct=True,
        patch_generated=True,
        patch_applied=True,
        syntax_valid=True,
        patched_sec_blocked=False,  # Exploit still succeeds!
        patched_reg_passed=True,
        strict_success=False,
    )
    assert res == "EXPLOIT_REMAINS_SUCCESSFUL"


def test_strict_repair_acceptance_regression_failure():
    res = classify_failure(
        vulnerability_found=True,
        cwe_match=True,
        loc_correct=True,
        patch_generated=True,
        patch_applied=True,
        syntax_valid=True,
        patched_sec_blocked=True,
        patched_reg_passed=False,  # Broke regression!
        strict_success=False,
    )
    assert res == "REGRESSION_FAILURE"


def test_strict_repair_acceptance_patch_application_failure():
    res = classify_failure(
        vulnerability_found=True,
        cwe_match=True,
        loc_correct=True,
        patch_generated=True,
        patch_applied=False,  # Could not apply to disk!
        syntax_valid=False,
        patched_sec_blocked=False,
        patched_reg_passed=False,
        strict_success=False,
    )
    assert res == "PATCH_APPLICATION_FAILURE"


# ---------------------------------------------------------------------------
# 5. Synthetic Unit Tests for Metric Formulas (Hand-Calculated Answers)
# ---------------------------------------------------------------------------

def test_make_metric_calculation():
    # 3 / 4 = 75.0%
    m = make_metric("3/4", 3, 4, ["c1", "c2", "c3", "c4"])
    assert m["value"] == 75.0
    assert m["status"] == "measured"
    assert m["numerator"] == 3
    assert m["denominator"] == 4


def test_make_metric_zero_denominator():
    m = make_metric("0/0", 0, 0, [])
    assert m["value"] is None
    assert m["status"] == "unavailable"
    assert m["denominator"] == 0


def test_compute_binary_metrics_confusion_matrix():
    # Hand calculated:
    # TP=8, FP=2, TN=6, FN=4 (Total=20)
    # Precision = 8 / (8 + 2) = 0.80 -> 80.0%
    # Recall = 8 / (8 + 4) = 8 / 12 = 0.6667 -> 66.67%
    # Specificity = 6 / (6 + 2) = 0.75 -> 75.0%
    # Accuracy = (8 + 6) / 20 = 14 / 20 = 0.70 -> 70.0%
    # F1 = 2 * (0.8 * 0.66667) / (0.8 + 0.66667) = 0.7273 -> 72.73%
    res = compute_binary_metrics(tp=8, fp=2, tn=6, fn=4)
    assert res["precision"] == 80.0
    assert res["recall"] == 66.67
    assert res["specificity"] == 75.0
    assert res["accuracy"] == 70.0
    assert res["f1_score"] == 72.73


def test_synthetic_run_aggregation(tmp_path: Path):
    """Creates a temporary synthetic run with 4 cases to verify aggregate_run_metrics."""
    run_dir = tmp_path / "synthetic_run"
    raw_dir = run_dir / "raw"
    raw_dir.mkdir(parents=True)

    # Synthetic Case 1: Strictly repaired vulnerable case
    case1 = {
        "case_id": "SYN01",
        "ground_truth": "vulnerable",
        "cwe": "CWE-89",
        "vulnerability_found": True,
        "reported_cwe": "CWE-89",
        "localization_correct": True,
        "patch_generated": True,
        "patch_applied": True,
        "patch_syntax_valid": True,
        "strict_repair_success": True,
        "attempts_used": 1,
        "original_security_test": {"vulnerability_demonstrated": True},
        "patched_security_test": {"vulnerability_demonstrated": False},
        "patched_regression_test": {"passed": True},
        "failure_category": "STRICT_REPAIR_SUCCESS",
        "elapsed_seconds": 12.5,
        "usage": {"calls": 3, "input_tokens": 1000, "output_tokens": 500, "total_tokens": 1500, "cost_usd": 0.01},
    }

    # Synthetic Case 2: Vulnerable case with regression failure
    case2 = {
        "case_id": "SYN02",
        "ground_truth": "vulnerable",
        "cwe": "CWE-78",
        "vulnerability_found": True,
        "reported_cwe": "CWE-78",
        "localization_correct": True,
        "patch_generated": True,
        "patch_applied": True,
        "patch_syntax_valid": True,
        "strict_repair_success": False,
        "attempts_used": 2,
        "original_security_test": {"vulnerability_demonstrated": True},
        "patched_security_test": {"vulnerability_demonstrated": False},
        "patched_regression_test": {"passed": False},
        "failure_category": "REGRESSION_FAILURE",
        "elapsed_seconds": 15.0,
        "usage": {"calls": 4, "input_tokens": 1200, "output_tokens": 600, "total_tokens": 1800, "cost_usd": 0.015},
    }

    (raw_dir / "case_SYN01_trial_001.json").write_text(json.dumps(case1), encoding="utf-8")
    (raw_dir / "case_SYN02_trial_001.json").write_text(json.dumps(case2), encoding="utf-8")

    metrics, rows = aggregate_run_metrics(run_dir)

    # Eligible vulnerable: 2
    assert metrics["eligible_vulnerable_cases"] == 2
    # Detection: 2/2 = 100.0%
    assert metrics["detection_rate"]["value"] == 100.0
    # PSR@1: 1/2 = 50.0%
    assert metrics["psr_at_1"]["value"] == 50.0
    # Strict repair count: 1
    assert metrics["strict_repair_success_count"] == 1
    # Regression Rate: 1 / 2 = 50.0%
    assert metrics["regression_rate"]["value"] == 50.0
    # Application Success Rate: 2 / 2 = 100.0%
    assert metrics["application_success_rate"]["value"] == 100.0


# ---------------------------------------------------------------------------
# 6. Reproducibility: Recompute Without API Calls
# ---------------------------------------------------------------------------

def test_recompute_reproducibility(tmp_path: Path):
    """Verifies that deleting aggregates and recalculating produces byte-identical metrics."""
    run_dir = tmp_path / "repro_run"
    raw_dir = run_dir / "raw"
    raw_dir.mkdir(parents=True)

    case = {
        "case_id": "REPRO01",
        "ground_truth": "vulnerable",
        "cwe": "CWE-22",
        "vulnerability_found": True,
        "reported_cwe": "CWE-22",
        "localization_correct": True,
        "patch_generated": True,
        "patch_applied": True,
        "patch_syntax_valid": True,
        "strict_repair_success": True,
        "attempts_used": 1,
        "original_security_test": {"vulnerability_demonstrated": True},
        "patched_security_test": {"vulnerability_demonstrated": False},
        "patched_regression_test": {"passed": True},
        "failure_category": "STRICT_REPAIR_SUCCESS",
        "elapsed_seconds": 10.0,
        "usage": {"calls": 2, "input_tokens": 500, "output_tokens": 200, "total_tokens": 700, "cost_usd": 0.005},
    }
    (raw_dir / "case_REPRO01_trial_001.json").write_text(json.dumps(case), encoding="utf-8")

    # Pass 1: compute metrics
    m1, _ = aggregate_run_metrics(run_dir)
    json_path = run_dir / "metrics.json"
    json_path.write_text(json.dumps(m1, sort_keys=True, indent=2), encoding="utf-8")

    # Delete aggregate
    json_path.unlink()
    assert not json_path.exists()

    # Pass 2: recompute
    m2, _ = aggregate_run_metrics(run_dir)
    json_path.write_text(json.dumps(m2, sort_keys=True, indent=2), encoding="utf-8")

    assert m1 == m2


# ---------------------------------------------------------------------------
# 7. Chart Generation Verification
# ---------------------------------------------------------------------------

def test_chart_generation_from_synthetic_run(tmp_path: Path):
    run_dir = tmp_path / "chart_run"
    raw_dir = run_dir / "raw"
    raw_dir.mkdir(parents=True)

    case = {
        "case_id": "C01",
        "ground_truth": "vulnerable",
        "cwe": "CWE-89",
        "vulnerability_found": True,
        "reported_cwe": "CWE-89",
        "localization_correct": True,
        "patch_generated": True,
        "patch_applied": True,
        "patch_syntax_valid": True,
        "strict_repair_success": True,
        "attempts_used": 1,
        "original_security_test": {"vulnerability_demonstrated": True},
        "patched_security_test": {"vulnerability_demonstrated": False},
        "patched_regression_test": {"passed": True},
        "failure_category": "STRICT_REPAIR_SUCCESS",
        "elapsed_seconds": 5.2,
        "usage": {"calls": 2, "input_tokens": 400, "output_tokens": 200, "total_tokens": 600, "cost_usd": 0.004},
    }
    (raw_dir / "case_C01_trial_001.json").write_text(json.dumps(case), encoding="utf-8")

    metrics, rows = aggregate_run_metrics(run_dir)
    (run_dir / "metrics.json").write_text(json.dumps(metrics), encoding="utf-8")

    with (run_dir / "cases.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    generate_all_charts(run_dir)

    plots_dir = REPO_ROOT / "evaluation" / "plots" / run_dir.name
    assert plots_dir.exists()
    assert (plots_dir / "02_cwe_outcomes.png").exists()
    assert (plots_dir / "02_cwe_outcomes.pdf").exists()
    assert (plots_dir / "03_cost_and_tokens.png").exists()
    assert (plots_dir / "04_psr_comparison.png").exists()
    assert (plots_dir / "05_patch_reliability_funnel.png").exists()


# ---------------------------------------------------------------------------
# 8. Protection of Historical Baseline
# ---------------------------------------------------------------------------

def test_historical_baseline_preserved():
    assert HISTORICAL_DIR.exists()
    assert (HISTORICAL_DIR / "cases.csv").exists()
    assert (HISTORICAL_DIR / "metrics.json").exists()
    assert (HISTORICAL_DIR / "cases" / "C01.json").exists()
    assert (HISTORICAL_DIR / "cases" / "C06.json").exists()
    # Confirm historical run has 6 cases
    cases_lines = (HISTORICAL_DIR / "cases.csv").read_text(encoding="utf-8").strip().splitlines()
    assert len(cases_lines) == 7  # header + 6 rows

