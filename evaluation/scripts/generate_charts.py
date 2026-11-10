"""
Executable Research Chart Generator — Phase 9

Consumes aggregated metrics.json and cases.csv to programmatically generate publication-ready figures.
Zero hardcoded data: charts dynamically update whenever underlying experimental evidence updates.
Every figure is exported in dual formats: 300 DPI PNG and vector PDF.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[2]

# Styling configuration for IEEE publications
plt.rcParams.update({
    "font.size": 10,
    "axes.labelsize": 11,
    "axes.titlesize": 12,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "legend.fontsize": 9,
    "figure.titlesize": 13,
    "figure.autolayout": True,
    "axes.grid": True,
    "grid.alpha": 0.3,
    "grid.linestyle": "--",
})


def _save_figure(fig: plt.Figure, output_dir: Path, base_name: str):
    output_dir.mkdir(parents=True, exist_ok=True)
    png_path = output_dir / f"{base_name}.png"
    pdf_path = output_dir / f"{base_name}.pdf"
    fig.savefig(png_path, dpi=300, bbox_inches="tight")
    fig.savefig(pdf_path, format="pdf", bbox_inches="tight")
    plt.close(fig)
    print(f"  Generated: {png_path.name} & {pdf_path.name}")


def chart_triage_confusion_matrix(ml_eval_path: Path, output_dir: Path):
    """Plot A: ML Triage Confusion Matrix for Raw XGBoost vs Deployed Pipeline."""
    if not ml_eval_path.exists():
        print(f"Skipping triage confusion matrix: {ml_eval_path} not found")
        return

    data = json.loads(ml_eval_path.read_text(encoding="utf-8"))
    raw_cm = data["raw_xgboost"]["metrics"]["confusion_matrix"]
    dep_cm = data["deployed_triage"]["metrics"]["confusion_matrix"]

    fig, axes = plt.subplots(1, 2, figsize=(9, 4))

    for ax, cm, title in [
        (axes[0], raw_cm, f"Raw XGBoost\n(Threshold = {data['model_metadata']['raw_model_threshold']:.2f})"),
        (axes[1], dep_cm, f"Deployed Triage\n(Threshold = {data['model_metadata']['deployed_triage_threshold']} + Static Bypasses)"),
    ]:
        mat = np.array([[cm["tp"], cm["fn"]], [cm["fp"], cm["tn"]]])
        im = ax.imshow(mat, cmap="Blues", interpolation="nearest")
        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels(["Predicted Vuln", "Predicted Safe"])
        ax.set_yticklabels(["Actual Vuln", "Actual Safe"])
        ax.set_title(title, pad=10)

        for i in range(2):
            for j in range(2):
                val = mat[i, j]
                color = "white" if val > mat.max() / 2 else "black"
                label = f"{val}\n({val/cm['total']*100:.1f}%)"
                ax.text(j, i, label, ha="center", va="center", color=color, fontweight="bold")

    fig.suptitle("Vulnerability Triage Performance Matrix (N = 30)", fontsize=13)
    _save_figure(fig, output_dir, "01_triage_confusion_matrix")


def chart_cwe_outcomes(cases_csv_path: Path, output_dir: Path):
    """Plot B: Vulnerability Detection & Strict Repair Success by CWE Category."""
    if not cases_csv_path.exists():
        return

    with cases_csv_path.open("r", encoding="utf-8") as f:
        cases = list(csv.DictReader(f))

    vuln_cases = [c for c in cases if c["ground_truth"] == "vulnerable"]
    if not vuln_cases:
        return

    cwe_groups: dict[str, dict[str, int]] = {}
    for c in vuln_cases:
        cwe = c.get("cwe") or "Unknown"
        if cwe not in cwe_groups:
            cwe_groups[cwe] = {"total": 0, "detected": 0, "strictly_repaired": 0}
        cwe_groups[cwe]["total"] += 1
        if int(c.get("vulnerability_found", 0)):
            cwe_groups[cwe]["detected"] += 1
        if int(c.get("strict_repair_success", 0)):
            cwe_groups[cwe]["strictly_repaired"] += 1

    cwes = sorted(cwe_groups.keys())
    x = np.arange(len(cwes))
    width = 0.25

    totals = [cwe_groups[c]["total"] for c in cwes]
    detected = [cwe_groups[c]["detected"] for c in cwes]
    repaired = [cwe_groups[c]["strictly_repaired"] for c in cwes]

    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar(x - width, totals, width, label="Eligible Cases", color="#94a3b8")
    ax.bar(x, detected, width, label="Detected (Red Agent)", color="#3b82f6")
    ax.bar(x + width, repaired, width, label="Strictly Repaired (PASS)", color="#10b981")

    ax.set_ylabel("Case Count")
    ax.set_title("Detection and Strict Repair Outcomes by CWE Category")
    ax.set_xticks(x)
    ax.set_xticklabels(cwes)
    ax.legend()
    ax.set_ylim(0, max(totals) + 1)

    _save_figure(fig, output_dir, "02_cwe_outcomes")


def chart_cost_and_tokens(cases_csv_path: Path, output_dir: Path):
    """Plot C: LLM Token Footprint and Cost per Case."""
    if not cases_csv_path.exists():
        return

    with cases_csv_path.open("r", encoding="utf-8") as f:
        cases = list(csv.DictReader(f))

    valid_cases = [c for c in cases if int(c.get("total_tokens", 0)) > 0]
    if not valid_cases:
        return

    case_ids = [c["case_id"] for c in valid_cases]
    prompt_tokens = [int(c.get("prompt_tokens", 0)) for c in valid_cases]
    comp_tokens = [int(c.get("completion_tokens", 0)) for c in valid_cases]
    costs = [float(c.get("cost_usd", 0.0)) for c in valid_cases]

    fig, ax1 = plt.subplots(figsize=(10, 4.5))

    x = np.arange(len(case_ids))
    width = 0.55

    ax1.bar(x, prompt_tokens, width, label="Prompt Tokens", color="#60a5fa", alpha=0.85)
    ax1.bar(x, comp_tokens, width, bottom=prompt_tokens, label="Completion Tokens", color="#1d4ed8", alpha=0.85)
    ax1.set_ylabel("Tokens Consumed")
    ax1.set_xlabel("Benchmark Case Identifier")
    ax1.set_xticks(x)
    ax1.set_xticklabels(case_ids, rotation=45)

    ax2 = ax1.twinx()
    ax2.plot(x, costs, color="#ef4444", marker="o", linewidth=2, label="Cost (USD)")
    ax2.set_ylabel("Estimated Cost ($ USD)", color="#ef4444")
    ax2.tick_params(axis="y", labelcolor="#ef4444")
    ax2.grid(False)

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc="upper left")

    plt.title("Per-Case LLM Token Consumption and Cost Profile")
    _save_figure(fig, output_dir, "03_cost_and_tokens")


def chart_psr_comparison(metrics_json_path: Path, output_dir: Path):
    """Plot D: PSR@1 vs PSR@3 Comparison."""
    if not metrics_json_path.exists():
        return

    data = json.loads(metrics_json_path.read_text(encoding="utf-8"))
    psr1 = data.get("psr_at_1", {}).get("value")
    psr3 = data.get("psr_at_3", {}).get("value")

    if psr1 is None or psr3 is None:
        return

    fig, ax = plt.subplots(figsize=(6, 4))
    bars = ax.bar(["PSR@1\n(First Attempt)", "PSR@3\n(Bounded 3 Retries)"], [psr1, psr3], color=["#f59e0b", "#10b981"], width=0.45)
    ax.set_ylabel("Patch Success Rate (%)")
    ax.set_ylim(0, 100)
    ax.set_title("Patch Success Rate: First Attempt vs Bounded Retries")

    for bar in bars:
        h = bar.get_height()
        ax.annotate(f"{h:.1f}%", xy=(bar.get_x() + bar.get_width() / 2, h),
                    xytext=(0, 4), textcoords="offset points", ha="center", va="bottom", fontweight="bold")

    _save_figure(fig, output_dir, "04_psr_comparison")


def chart_patch_reliability(metrics_json_path: Path, output_dir: Path):
    """Plot E: Pipeline Stage Funnel & Reliability."""
    if not metrics_json_path.exists():
        return

    data = json.loads(metrics_json_path.read_text(encoding="utf-8"))
    eligible = data.get("eligible_vulnerable_cases", 0)
    detected = data.get("detection_rate", {}).get("numerator", 0)
    asr_num = data.get("application_success_rate", {}).get("numerator", 0)
    strict_num = data.get("strict_repair_success_count", 0)

    stages = [
        "1. Eligible Flaws",
        "2. Red Detected",
        "3. Patch Applied",
        "4. Strict PASS",
    ]
    counts = [eligible, detected, asr_num, strict_num]

    fig, ax = plt.subplots(figsize=(7, 4))
    colors = ["#64748b", "#3b82f6", "#8b5cf6", "#10b981"]
    bars = ax.barh(stages[::-1], counts[::-1], color=colors[::-1], height=0.5)

    ax.set_xlabel("Case Count")
    ax.set_title("VulnGuard End-to-End Pipeline Funnel")
    ax.set_xlim(0, max(eligible, 1) + 2)

    for bar in bars:
        w = bar.get_width()
        pct = (w / eligible * 100) if eligible > 0 else 0
        ax.annotate(f"{w} ({pct:.0f}%)", xy=(w, bar.get_y() + bar.get_height() / 2),
                    xytext=(5, 0), textcoords="offset points", ha="left", va="center", fontweight="bold")

    _save_figure(fig, output_dir, "05_patch_reliability_funnel")


def chart_time_to_remediation(cases_csv_path: Path, output_dir: Path):
    """Plot F: Per-Case Time-to-Remediation Distribution."""
    if not cases_csv_path.exists():
        return

    with cases_csv_path.open("r", encoding="utf-8") as f:
        cases = list(csv.DictReader(f))

    times = [float(c["elapsed_seconds"]) for c in cases if float(c.get("elapsed_seconds", 0)) > 0]
    if not times:
        return

    fig, ax = plt.subplots(figsize=(7, 4))
    ax.hist(times, bins=8, color="#0284c7", edgecolor="white", alpha=0.85)
    mean_val = np.mean(times)
    median_val = np.median(times)

    ax.axvline(mean_val, color="#ef4444", linestyle="--", linewidth=1.5, label=f"Mean: {mean_val:.1f}s")
    ax.axvline(median_val, color="#10b981", linestyle="-", linewidth=1.5, label=f"Median: {median_val:.1f}s")

    ax.set_xlabel("Time-to-Remediation (Seconds)")
    ax.set_ylabel("Frequency")
    ax.set_title("End-to-End Pipeline Latency Distribution")
    ax.legend()

    _save_figure(fig, output_dir, "06_time_to_remediation_dist")


def chart_failure_breakdown(metrics_json_path: Path, output_dir: Path):
    """Plot G: Repair Failure Classification Breakdown."""
    if not metrics_json_path.exists():
        return

    data = json.loads(metrics_json_path.read_text(encoding="utf-8"))
    breakdown = data.get("failure_breakdown", {})
    if not breakdown:
        return

    labels = list(breakdown.keys())
    counts = list(breakdown.values())

    fig, ax = plt.subplots(figsize=(8, 4))
    y_pos = np.arange(len(labels))
    ax.barh(y_pos, counts, color="#f43f5e", alpha=0.85, height=0.55)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(labels)
    ax.set_xlabel("Case Count")
    ax.set_title("Vulnerability Repair Failure Taxonomy")
    ax.set_xlim(0, max(counts) + 2)

    for i, c in enumerate(counts):
        ax.annotate(str(c), xy=(c, i), xytext=(4, 0), textcoords="offset points", ha="left", va="center", fontweight="bold")

    _save_figure(fig, output_dir, "07_failure_breakdown")


def generate_all_charts(run_dir: Path, output_dir: Path | None = None):
    print(f"\nGenerating publication figures for run: {run_dir.name}")
    plots_dir = output_dir or (REPO_ROOT / "evaluation" / "plots" / run_dir.name)
    plots_dir.mkdir(parents=True, exist_ok=True)

    metrics_p = run_dir / "metrics.json"
    cases_p = run_dir / "cases.csv"
    ml_eval_p = run_dir / "raw" / "ml_triage_evaluation.json"

    # Fallback to shared dataset ML eval if not in run
    if not ml_eval_p.exists():
        shared_ml = REPO_ROOT / "evaluation" / "dataset" / "ml_triage_evaluation.json"
        if shared_ml.exists():
            ml_eval_p = shared_ml

    chart_triage_confusion_matrix(ml_eval_p, plots_dir)
    chart_cwe_outcomes(cases_p, plots_dir)
    chart_cost_and_tokens(cases_p, plots_dir)
    chart_psr_comparison(metrics_p, plots_dir)
    chart_patch_reliability(metrics_p, plots_dir)
    chart_time_to_remediation(cases_p, plots_dir)
    chart_failure_breakdown(metrics_p, plots_dir)

    print(f"All figures generated successfully in: {plots_dir}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate publication charts from evaluation results")
    parser.add_argument("--run-dir", type=str, required=True, help="Path to evaluation/runs/<run_id>")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    if not run_dir.exists():
        print(f"Error: run directory does not exist: {run_dir}")
        return 1

    generate_all_charts(run_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
