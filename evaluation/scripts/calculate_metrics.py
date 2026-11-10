"""
Deterministic Metric Aggregator — Phase 8

Calculates all research evaluation metrics strictly from saved raw observation JSON files.
Contains zero LLM calls and zero hardcoded results.
Every metric includes formula, numerator, denominator, calculated value, eligible case IDs, and status.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]


def _wilson_score_ci(k: int, n: int, z: float = 1.95996) -> tuple[float, float] | None:
    """Calculate 95% Wilson score confidence interval for a binomial proportion."""
    if n <= 0:
        return None
    p_hat = k / n
    denominator = 1 + (z ** 2) / n
    center = p_hat + (z ** 2) / (2 * n)
    spread = z * math.sqrt((p_hat * (1 - p_hat) / n) + (z ** 2) / (4 * (n ** 2)))
    lower = max(0.0, (center - spread) / denominator) * 100.0
    upper = min(1.0, (center + spread) / denominator) * 100.0
    return round(lower, 2), round(upper, 2)


def make_metric(
    formula: str,
    numerator: int | float,
    denominator: int | float,
    eligible_case_ids: list[str],
    round_digits: int = 2,
    as_percentage: bool = True,
) -> dict[str, Any]:
    if denominator == 0 or math.isnan(denominator) or denominator is None:
        return {
            "formula": formula,
            "numerator": numerator,
            "denominator": denominator,
            "value": None,
            "ci_95": None,
            "eligible_case_ids": eligible_case_ids,
            "status": "unavailable",
        }

    val = (numerator / denominator) * (100.0 if as_percentage else 1.0)
    ci = _wilson_score_ci(int(numerator), int(denominator)) if as_percentage else None
    return {
        "formula": formula,
        "numerator": numerator,
        "denominator": denominator,
        "value": round(val, round_digits),
        "ci_95": ci,
        "eligible_case_ids": eligible_case_ids,
        "status": "measured",
    }


def aggregate_run_metrics(run_dir: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    raw_dir = run_dir / "raw"
    if not raw_dir.exists():
        raise FileNotFoundError(f"Raw directory not found: {raw_dir}")

    case_files = sorted(raw_dir.glob("case_*.json"))
    if not case_files:
        raise ValueError(f"No raw case JSON files found in {raw_dir}")

    cases: list[dict[str, Any]] = []
    for f in case_files:
        cases.append(json.loads(f.read_text(encoding="utf-8")))

    # -----------------------------------------------------------------------
    # 1. Cohort and Eligibility Filtering
    # -----------------------------------------------------------------------
    vuln_cases = [c for c in cases if c.get("ground_truth") == "vulnerable"]
    safe_cases = [c for c in cases if c.get("ground_truth") == "safe"]

    # Cases eligible for repair evaluation (vulnerable cases with confirmed original flaw)
    eligible_vuln_cases = [
        c for c in vuln_cases if c.get("original_security_test", {}).get("vulnerability_demonstrated")
    ]
    eligible_vuln_ids = [c["case_id"] for c in eligible_vuln_cases]

    # -----------------------------------------------------------------------
    # 2. Vulnerability Detection Metrics
    # -----------------------------------------------------------------------
    detected_cases = [c for c in eligible_vuln_cases if c.get("vulnerability_found")]
    detected_ids = [c["case_id"] for c in detected_cases]

    # CWE Accuracy: reported_cwe matches ground_truth cwe
    correct_cwe_cases = []
    for c in detected_cases:
        gt_cwe = c.get("cwe", "").upper()
        rep_cwe = str(c.get("reported_cwe", "")).upper()
        if gt_cwe and (gt_cwe in rep_cwe or rep_cwe in gt_cwe):
            correct_cwe_cases.append(c)
    correct_cwe_ids = [c["case_id"] for c in correct_cwe_cases]

    # Localization Accuracy
    correct_loc_cases = [c for c in detected_cases if c.get("localization_correct")]
    correct_loc_ids = [c["case_id"] for c in correct_loc_cases]

    detection_rate = make_metric(
        "vulnerabilities_detected / eligible_vulnerable_cases",
        len(detected_cases),
        len(eligible_vuln_cases),
        eligible_vuln_ids,
    )
    cwe_accuracy = make_metric(
        "correct_cwe_predictions / vulnerabilities_detected",
        len(correct_cwe_cases),
        len(detected_cases),
        detected_ids,
    )
    localization_accuracy = make_metric(
        "correctly_localized_cases / vulnerabilities_detected",
        len(correct_loc_cases),
        len(detected_cases),
        detected_ids,
    )

    # -----------------------------------------------------------------------
    # 3. Patch Application & Repair Acceptance Metrics (Phase 5 Strict Criteria)
    # -----------------------------------------------------------------------
    patch_generated_cases = [c for c in eligible_vuln_cases if c.get("patch_generated")]
    patch_gen_ids = [c["case_id"] for c in patch_generated_cases]

    patch_applied_cases = [c for c in patch_generated_cases if c.get("patch_applied")]
    patch_applied_ids = [c["case_id"] for c in patch_applied_cases]

    syntax_valid_cases = [c for c in patch_generated_cases if c.get("patch_syntax_valid")]
    malformed_patch_cases = [c for c in patch_generated_cases if not c.get("patch_syntax_valid")]

    # Strict Repair Success:
    # 1. Orig sec test demonstrated
    # 2. Patch generated
    # 3. Patch applied
    # 4. Syntax / build valid
    # 5. Patched regression passed
    # 6. Patched sec test neutralized
    strict_success_cases = [c for c in eligible_vuln_cases if c.get("strict_repair_success")]
    strict_success_ids = [c["case_id"] for c in strict_success_cases]

    psr_at_1_cases = [
        c for c in strict_success_cases if c.get("attempts_used", 1) <= 1
    ]
    psr_at_1_ids = [c["case_id"] for c in psr_at_1_cases]

    psr_at_3_cases = [
        c for c in strict_success_cases if c.get("attempts_used", 1) <= 3
    ]
    psr_at_3_ids = [c["case_id"] for c in psr_at_3_cases]

    # Exploit Blocking Rate (EBR):
    # Exploits neutralized on patched source / valid exploits tested on patched source
    applied_tested_cases = [
        c for c in patch_applied_cases if "patched_security_test" in c
    ]
    applied_tested_ids = [c["case_id"] for c in applied_tested_cases]
    blocked_cases = [
        c for c in applied_tested_cases
        if not c.get("patched_security_test", {}).get("vulnerability_demonstrated")
    ]
    blocked_ids = [c["case_id"] for c in blocked_cases]

    # Regression Rate:
    # Regression failures on patched code / applied patches tested
    regression_failed_cases = [
        c for c in applied_tested_cases
        if not c.get("patched_regression_test", {}).get("passed", False)
    ]
    reg_fail_ids = [c["case_id"] for c in regression_failed_cases]

    psr_1 = make_metric(
        "strictly_accepted_repairs_attempt_1 / eligible_vulnerable_cases",
        len(psr_at_1_cases),
        len(eligible_vuln_cases),
        eligible_vuln_ids,
    )
    psr_3 = make_metric(
        "strictly_accepted_repairs_within_3_attempts / eligible_vulnerable_cases",
        len(psr_at_3_cases),
        len(eligible_vuln_cases),
        eligible_vuln_ids,
    )
    asr = make_metric(
        "successfully_applied_patches / patch_application_attempts",
        len(patch_applied_cases),
        len(patch_generated_cases),
        patch_gen_ids,
    )
    ebr = make_metric(
        "exploits_blocked_after_patching / applied_patches_tested",
        len(blocked_cases),
        len(applied_tested_cases),
        applied_tested_ids,
    )
    regression_rate = make_metric(
        "regression_failures_after_patching / applied_patches_tested",
        len(regression_failed_cases),
        len(applied_tested_cases),
        applied_tested_ids,
    )
    malformed_rate = make_metric(
        "malformed_or_invalid_syntax_patches / patches_generated",
        len(malformed_patch_cases),
        len(patch_generated_cases),
        patch_gen_ids,
    )

    # -----------------------------------------------------------------------
    # 4. Failure Breakdown
    # -----------------------------------------------------------------------
    failure_counts: dict[str, int] = {}
    for c in eligible_vuln_cases:
        cat = c.get("failure_category", "UNKNOWN")
        failure_counts[cat] = failure_counts.get(cat, 0) + 1

    # -----------------------------------------------------------------------
    # 5. Cost and Latency Metrics
    # -----------------------------------------------------------------------
    all_case_ids = [c["case_id"] for c in cases]
    total_calls = sum(c.get("usage", {}).get("calls", 0) for c in cases)
    total_prompt_tok = sum(c.get("usage", {}).get("input_tokens", 0) for c in cases)
    total_comp_tok = sum(c.get("usage", {}).get("output_tokens", 0) for c in cases)
    total_tokens = sum(c.get("usage", {}).get("total_tokens", 0) for c in cases)
    total_cost_usd = sum(c.get("usage", {}).get("cost_usd", 0.0) for c in cases)

    latencies = [c.get("elapsed_seconds", 0.0) for c in cases if c.get("elapsed_seconds", 0.0) > 0]
    mean_latency = statistics.mean(latencies) if latencies else None
    median_latency = statistics.median(latencies) if latencies else None
    p95_latency = statistics.quantiles(latencies, n=20)[18] if len(latencies) >= 20 else (max(latencies) if latencies else None)

    cost_per_case = make_metric(
        "total_cost_usd / total_evaluated_cases",
        round(total_cost_usd, 4),
        len(cases),
        all_case_ids,
        round_digits=4,
        as_percentage=False,
    )
    cost_per_accepted = make_metric(
        "total_cost_usd / strictly_accepted_repairs",
        round(total_cost_usd, 4),
        len(strict_success_cases),
        strict_success_ids,
        round_digits=4,
        as_percentage=False,
    )

    # -----------------------------------------------------------------------
    # 6. Retry Recovery Rate
    # -----------------------------------------------------------------------
    failed_first_attempt = [c for c in eligible_vuln_cases if c.get("attempts_used", 0) > 1 or not c.get("strict_repair_success")]
    recovered_cases = [c for c in strict_success_cases if c.get("attempts_used", 1) > 1]
    retry_recovery = make_metric(
        "repairs_recovered_via_retries / cases_needing_retry",
        len(recovered_cases),
        len(failed_first_attempt),
        [c["case_id"] for c in failed_first_attempt],
    )

    metrics_dict = {
        "run_id": run_dir.name,
        "total_cases_evaluated": len(cases),
        "vulnerable_cases": len(vuln_cases),
        "safe_control_cases": len(safe_cases),
        "eligible_vulnerable_cases": len(eligible_vuln_cases),
        "detection_rate": detection_rate,
        "cwe_classification_accuracy": cwe_accuracy,
        "localization_accuracy": localization_accuracy,
        "psr_at_1": psr_1,
        "psr_at_3": psr_3,
        "application_success_rate": asr,
        "exploit_blocking_rate": ebr,
        "regression_rate": regression_rate,
        "malformed_patch_rate": malformed_rate,
        "retry_recovery_rate": retry_recovery,
        "strict_repair_success_count": len(strict_success_cases),
        "strict_repair_failure_count": len(eligible_vuln_cases) - len(strict_success_cases),
        "failure_breakdown": failure_counts,
        "resource_usage": {
            "total_llm_calls": total_calls,
            "total_prompt_tokens": total_prompt_tok,
            "total_completion_tokens": total_comp_tok,
            "total_tokens": total_tokens,
            "total_cost_usd": round(total_cost_usd, 4),
            "cost_per_case_usd": cost_per_case,
            "cost_per_accepted_repair_usd": cost_per_accepted,
            "mean_latency_seconds": round(mean_latency, 2) if mean_latency is not None else None,
            "median_latency_seconds": round(median_latency, 2) if median_latency is not None else None,
            "p95_latency_seconds": round(p95_latency, 2) if p95_latency is not None else None,
        },
    }

    # Format tabular rows for cases.csv
    table_rows = []
    for c in cases:
        u = c.get("usage", {})
        table_rows.append({
            "case_id": c["case_id"],
            "ground_truth": c.get("ground_truth", ""),
            "cwe": c.get("cwe", ""),
            "language": c.get("language", ""),
            "source_path": c.get("source_path", ""),
            "target_function": c.get("target_function", ""),
            "triage_risk_score": c.get("triage", {}).get("risk_score"),
            "triage_selected": int(bool(c.get("triage", {}).get("selected", True))),
            "vulnerability_found": int(bool(c.get("vulnerability_found"))),
            "reported_cwe": c.get("reported_cwe") or "",
            "cwe_match": int(bool(c.get("cwe_match"))),
            "localization_correct": int(bool(c.get("localization_correct"))),
            "exploit_status": c.get("exploit_status") or "",
            "patch_generated": int(bool(c.get("patch_generated"))),
            "patch_applied": int(bool(c.get("patch_applied"))),
            "patch_syntax_valid": int(bool(c.get("patch_syntax_valid"))),
            "patched_sec_blocked": int(not bool(c.get("patched_security_test", {}).get("vulnerability_demonstrated", True))),
            "patched_reg_passed": int(bool(c.get("patched_regression_test", {}).get("passed"))),
            "attempts_used": c.get("attempts_used", 0),
            "strict_repair_success": int(bool(c.get("strict_repair_success"))),
            "failure_category": c.get("failure_category") or "",
            "elapsed_seconds": round(c.get("elapsed_seconds", 0.0), 3),
            "llm_calls": u.get("calls", 0),
            "prompt_tokens": u.get("input_tokens", 0),
            "completion_tokens": u.get("output_tokens", 0),
            "total_tokens": u.get("total_tokens", 0),
            "cost_usd": round(u.get("cost_usd", 0.0), 5),
        })

    return metrics_dict, table_rows


def export_markdown_table(metrics: dict[str, Any], out_path: Path):
    lines = [
        f"# Research Evaluation Metric Summary: {metrics['run_id']}",
        "",
        f"**Evaluated Cases:** {metrics['total_cases_evaluated']} total "
        f"({metrics['vulnerable_cases']} vulnerable, {metrics['safe_control_cases']} safe controls, "
        f"{metrics['eligible_vulnerable_cases']} eligible)",
        "",
        "| Metric Name | Formula | Numerator / Denominator | Calculated Value | 95% Confidence Interval | Status |",
        "|---|---|---:|---:|---:|:---:|",
    ]

    metric_keys = [
        ("Detection Rate (DR)", metrics["detection_rate"]),
        ("CWE Classification Accuracy", metrics["cwe_classification_accuracy"]),
        ("Localization Accuracy", metrics["localization_accuracy"]),
        ("Patch Success Rate @ 1 (PSR@1)", metrics["psr_at_1"]),
        ("Patch Success Rate @ 3 (PSR@3)", metrics["psr_at_3"]),
        ("Application Success Rate (ASR)", metrics["application_success_rate"]),
        ("Exploit Blocking Rate (EBR)", metrics["exploit_blocking_rate"]),
        ("Regression Rate (RR)", metrics["regression_rate"]),
        ("Malformed Patch Rate", metrics["malformed_patch_rate"]),
        ("Retry Recovery Rate", metrics["retry_recovery_rate"]),
    ]

    for label, m in metric_keys:
        num = m["numerator"]
        den = m["denominator"]
        val_str = f"{m['value']}%" if m["value"] is not None else "N/A"
        ci = m.get("ci_95")
        ci_str = f"[{ci[0]}%, {ci[1]}%]" if ci else "N/A"
        lines.append(f"| **{label}** | `{m['formula']}` | {num} / {den} | **{val_str}** | {ci_str} | `{m['status']}` |")

    lines.append("")
    lines.append("## Resource and Cost Footprint")
    lines.append("")
    ru = metrics["resource_usage"]
    lines.append(f"- **Total LLM Calls:** {ru['total_llm_calls']}")
    lines.append(f"- **Total Tokens:** {ru['total_tokens']:,} (Prompt: {ru['total_prompt_tokens']:,}, Completion: {ru['total_completion_tokens']:,})")
    lines.append(f"- **Total Estimated Cost:** ${ru['total_cost_usd']:.4f}")
    if ru["cost_per_case_usd"]["value"] is not None:
        lines.append(f"- **Cost Per Case:** ${ru['cost_per_case_usd']['value']:.4f}")
    if ru["cost_per_accepted_repair_usd"]["value"] is not None:
        lines.append(f"- **Cost Per Strictly Accepted Repair:** ${ru['cost_per_accepted_repair_usd']['value']:.4f}")
    lines.append(f"- **Mean Latency:** {ru['mean_latency_seconds']} s (Median: {ru['median_latency_seconds']} s, P95: {ru['p95_latency_seconds']} s)")
    lines.append("")

    lines.append("## Strict Repair Failure Breakdown")
    lines.append("")
    lines.append("| Failure Category | Case Count |")
    lines.append("|---|---:|")
    for cat, count in sorted(metrics["failure_breakdown"].items(), key=lambda x: -x[1]):
        lines.append(f"| `{cat}` | {count} |")

    out_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Calculate metrics from raw evaluation JSON")
    parser.add_argument("--run-dir", type=str, required=True, help="Path to evaluation/runs/<run_id>")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    if not run_dir.exists():
        print(f"Error: run directory does not exist: {run_dir}")
        return 1

    metrics, table_rows = aggregate_run_metrics(run_dir)

    # Write metrics.json
    metrics_path = run_dir / "metrics.json"
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(f"Wrote metrics JSON to: {metrics_path}")

    # Write cases.csv
    if table_rows:
        cases_csv_path = run_dir / "cases.csv"
        with cases_csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(table_rows[0].keys()))
            writer.writeheader()
            writer.writerows(table_rows)
        print(f"Wrote cases CSV to: {cases_csv_path}")

    # Write metrics.md
    metrics_md_path = run_dir / "metrics.md"
    export_markdown_table(metrics, metrics_md_path)
    print(f"Wrote metrics Markdown to: {metrics_md_path}")

    print("\nCalculation complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
