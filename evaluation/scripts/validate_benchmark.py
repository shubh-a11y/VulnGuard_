"""
Benchmark Ground-Truth Validation Script — Phase 2

Independently validates the 30-case benchmark:
1. Executes security test against original vulnerable source -> confirms vulnerability is demonstrated.
2. Executes security test against safe source -> confirms security property holds (vulnerability NOT demonstrated).
3. Executes functional regression test against all 30 cases -> confirms normal expected behavior works.
4. Saves structured validation evidence to evaluation/dataset/validation_summary.json.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from evaluation.dataset.harness import run_regression_test, run_security_test
from evaluation.scripts.validate_dataset import load_manifest

VALIDATION_SUMMARY_PATH = REPO_ROOT / "evaluation" / "dataset" / "validation_summary.json"


def validate_all_cases() -> tuple[bool, dict]:
    manifest = load_manifest()
    results = []
    all_valid = True

    print(f"\n=======================================================")
    print(f"  INDEPENDENT BENCHMARK VALIDATION (30 CASES)")
    print(f"=======================================================\n")

    for case in manifest:
        cid = case["case_id"]
        gt = case["ground_truth"]
        cat = case["category"]
        src_path = REPO_ROOT / case["source_path"]

        t0 = time.perf_counter()
        # 1. Run security test
        sec_res = run_security_test(cid, src_path)
        # 2. Run regression test
        reg_res = run_regression_test(cid, src_path)
        elapsed = round(time.perf_counter() - t0, 4)

        # Expected security result
        if gt == "vulnerable":
            sec_valid = sec_res.passed and sec_res.vulnerability_demonstrated
        else:
            sec_valid = sec_res.passed and not sec_res.vulnerability_demonstrated

        reg_valid = reg_res.passed

        case_ok = sec_valid and reg_valid
        if not case_ok:
            all_valid = False

        status_icon = "PASS" if case_ok else "FAIL"
        print(f"[{status_icon}] Case {cid:3s} ({cat:18s} | {gt:10s}): "
              f"sec_demo={sec_res.vulnerability_demonstrated} (valid={sec_valid}), "
              f"regression={reg_res.passed} [{elapsed}s]")

        results.append({
            "case_id": cid,
            "category": cat,
            "cwe": case["cwe"],
            "ground_truth": gt,
            "source_path": case["source_path"],
            "target_function": case["target_function"],
            "validation_status": "VALID" if case_ok else "INVALID",
            "security_test": {
                "passed": sec_res.passed,
                "vulnerability_demonstrated": sec_res.vulnerability_demonstrated,
                "expected_demonstration": (gt == "vulnerable"),
                "is_valid": sec_valid,
                "evidence": sec_res.evidence,
                "error": sec_res.error,
            },
            "regression_test": {
                "passed": reg_res.passed,
                "evidence": reg_res.evidence,
                "error": reg_res.error,
            },
            "elapsed_seconds": elapsed,
        })

    total_valid = sum(1 for r in results if r["validation_status"] == "VALID")
    summary = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_cases": len(results),
        "valid_cases": total_valid,
        "invalid_cases": len(results) - total_valid,
        "all_benchmarks_valid": all_valid,
        "cases": results,
    }

    VALIDATION_SUMMARY_PATH.parent.mkdir(parents=True, exist_ok=True)
    VALIDATION_SUMMARY_PATH.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"\nBenchmark Validation Summary saved to: {VALIDATION_SUMMARY_PATH}")
    print(f"Result: {total_valid}/30 cases independently validated.\n")

    return all_valid, summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.parse_args()
    all_valid, _ = validate_all_cases()
    return 0 if all_valid else 1


if __name__ == "__main__":
    sys.exit(main())

