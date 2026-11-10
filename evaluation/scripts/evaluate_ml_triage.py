"""
ML Triage and Classifier Evaluation — Phase 3

Evaluates:
Part A: Raw XGBoost probabilistic predictions (model threshold = 0.50)
Part B: Deployed triage decisions (combines model score, risk threshold, and static security signal bypasses)

Calculates separate confusion matrices:
- True Positives (TP), False Positives (FP), True Negatives (TN), False Negatives (FN)
- Precision, Recall (Sensitivity), F1-Score, Specificity, False Positive Rate (FPR)
- Vulnerability Retention Rate, Function Selection Ratio
"""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from vulnguard.config import cfg
from vulnguard.data.feature_extractor import FEATURE_NAMES, extract_features
from vulnguard.data.parser import read_source_file
from vulnguard.models.risk_scorer import RiskScorer
from evaluation.scripts.validate_dataset import load_manifest


def compute_binary_metrics(tp: int, fp: int, tn: int, fn: int) -> dict[str, Any]:
    total = tp + fp + tn + fn
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else None
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else None
    f1 = (2 * precision * recall / (precision + recall)) if (precision and recall) else None
    specificity = (tn / (tn + fp)) if (tn + fp) > 0 else None
    fpr = (fp / (fp + tn)) if (fp + tn) > 0 else None
    accuracy = ((tp + tn) / total) if total > 0 else None

    # Retention rate: fraction of known vulnerable cases selected
    vulnerability_retention = (tp / (tp + fn)) if (tp + fn) > 0 else None
    # Selection ratio: fraction of all evaluated functions selected
    selection_ratio = ((tp + fp) / total) if total > 0 else None

    return {
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "total": total},
        "accuracy": round(accuracy * 100, 2) if accuracy is not None else None,
        "precision": round(precision * 100, 2) if precision is not None else None,
        "recall": round(recall * 100, 2) if recall is not None else None,
        "f1_score": round(f1 * 100, 2) if f1 is not None else None,
        "specificity": round(specificity * 100, 2) if specificity is not None else None,
        "false_positive_rate": round(fpr * 100, 2) if fpr is not None else None,
        "vulnerability_retention": round(vulnerability_retention * 100, 2) if vulnerability_retention is not None else None,
        "selection_ratio": round(selection_ratio * 100, 2) if selection_ratio is not None else None,
    }


def evaluate_triage(manifest_path: Path | None = None, latency_repeats: int = 50) -> dict[str, Any]:
    manifest = load_manifest(manifest_path or (REPO_ROOT / "evaluation" / "dataset" / "manifest.csv"))
    scorer = RiskScorer()
    model = scorer._model
    model_threshold = getattr(scorer, "_threshold", 0.5)
    deployed_threshold = cfg.triage.risk_threshold

    # Model metadata
    model_path = cfg.triage.model_path
    model_hash = hashlib.sha256(model_path.read_bytes()).hexdigest() if model_path.exists() else "unknown"

    raw_results = []
    deployed_results = []
    latencies: dict[str, list[float]] = {"python": [], "c": [], "all": []}

    # Confusion matrix counters
    raw_counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    dep_counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}

    for case in manifest:
        cid = case["case_id"]
        gt = case["ground_truth"]
        is_vuln_gt = (gt == "vulnerable")
        lang = case["language"]
        src_path = REPO_ROOT / case["source_path"]
        code = src_path.read_text(encoding="utf-8", errors="replace")

        # 1. Feature extraction
        feat_res = extract_features(code, lang)
        X = feat_res.vector.reshape(1, -1)

        # 2. Raw model prediction
        try:
            proba = float(model.predict_proba(X)[0, 1])
        except Exception:
            proba = 0.0
        raw_pred_vuln = (proba >= model_threshold)

        if is_vuln_gt and raw_pred_vuln:
            raw_counts["tp"] += 1
        elif not is_vuln_gt and raw_pred_vuln:
            raw_counts["fp"] += 1
        elif not is_vuln_gt and not raw_pred_vuln:
            raw_counts["tn"] += 1
        else:
            raw_counts["fn"] += 1

        raw_results.append({
            "case_id": cid,
            "ground_truth": gt,
            "language": lang,
            "raw_probability": round(proba, 4),
            "threshold": model_threshold,
            "predicted_label": "vulnerable" if raw_pred_vuln else "safe",
            "correct": (raw_pred_vuln == is_vuln_gt),
        })

        # 3. Deployed triage scoring (with static security signals)
        t0 = time.perf_counter()
        dep_score_res = scorer.score(code, lang)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        latencies["all"].append(elapsed_ms)
        if lang in latencies:
            latencies[lang].append(elapsed_ms)

        final_score = dep_score_res.risk_score
        dep_selected = (final_score >= deployed_threshold)

        if is_vuln_gt and dep_selected:
            dep_counts["tp"] += 1
        elif not is_vuln_gt and dep_selected:
            dep_counts["fp"] += 1
        elif not is_vuln_gt and not dep_selected:
            dep_counts["tn"] += 1
        else:
            dep_counts["fn"] += 1

        deployed_results.append({
            "case_id": cid,
            "ground_truth": gt,
            "language": lang,
            "raw_probability": round(proba, 4),
            "final_risk_score": round(final_score, 2),
            "deployed_threshold": deployed_threshold,
            "bypass_reason": dep_score_res.bypass_reason or "NONE",
            "selected_for_analysis": dep_selected,
            "correct": (dep_selected == is_vuln_gt),
            "latency_ms": round(elapsed_ms, 3),
        })

    # Additional repeated latency profiling
    latency_profile = {}
    for l_key, l_vals in latencies.items():
        if l_vals:
            latency_profile[l_key] = {
                "count": len(l_vals),
                "mean_ms": round(statistics.mean(l_vals), 3),
                "median_ms": round(statistics.median(l_vals), 3),
                "p95_ms": round(statistics.quantiles(l_vals, n=20)[18], 3) if len(l_vals) >= 20 else round(max(l_vals), 3),
                "min_ms": round(min(l_vals), 3),
                "max_ms": round(max(l_vals), 3),
            }

    raw_metrics = compute_binary_metrics(**raw_counts)
    dep_metrics = compute_binary_metrics(**dep_counts)

    return {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "model_metadata": {
            "model_path": str(model_path),
            "model_sha256": model_hash,
            "raw_model_threshold": model_threshold,
            "deployed_triage_threshold": deployed_threshold,
        },
        "raw_xgboost": {
            "metrics": raw_metrics,
            "cases": raw_results,
        },
        "deployed_triage": {
            "metrics": dep_metrics,
            "cases": deployed_results,
        },
        "latency_profile": latency_profile,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate ML triage classifier")
    parser.add_argument("--out", type=str, default=None, help="Output JSON path")
    args = parser.parse_args()

    results = evaluate_triage()
    raw_m = results["raw_xgboost"]["metrics"]
    dep_m = results["deployed_triage"]["metrics"]

    print("\n=======================================================")
    print("  PHASE 3: ML TRIAGE EVALUATION RESULTS")
    print("=======================================================")
    print(f"\nPart A: Raw XGBoost Classifier (Threshold = {results['model_metadata']['raw_model_threshold']}):")
    print(f"  TP: {raw_m['confusion_matrix']['tp']}, FP: {raw_m['confusion_matrix']['fp']}, "
          f"TN: {raw_m['confusion_matrix']['tn']}, FN: {raw_m['confusion_matrix']['fn']}")
    print(f"  Accuracy:    {raw_m['accuracy']}%")
    print(f"  Precision:   {raw_m['precision']}%")
    print(f"  Recall:      {raw_m['recall']}%")
    print(f"  Specificity: {raw_m['specificity']}%")
    print(f"  F1-Score:    {raw_m['f1_score']}%")
    print(f"  Retention:   {raw_m['vulnerability_retention']}%")
    print(f"  Selection:   {raw_m['selection_ratio']}%")

    print(f"\nPart B: Deployed Triage Decisions (Threshold = {results['model_metadata']['deployed_triage_threshold']} + Static Bypasses):")
    print(f"  TP: {dep_m['confusion_matrix']['tp']}, FP: {dep_m['confusion_matrix']['fp']}, "
          f"TN: {dep_m['confusion_matrix']['tn']}, FN: {dep_m['confusion_matrix']['fn']}")
    print(f"  Accuracy:    {dep_m['accuracy']}%")
    print(f"  Precision:   {dep_m['precision']}%")
    print(f"  Recall:      {dep_m['recall']}%")
    print(f"  Specificity: {dep_m['specificity']}%")
    print(f"  F1-Score:    {dep_m['f1_score']}%")
    print(f"  Retention:   {dep_m['vulnerability_retention']}%")
    print(f"  Selection:   {dep_m['selection_ratio']}%")

    print("\nTriage Latency Profile:")
    for lang, stat in results["latency_profile"].items():
        print(f"  {lang:8s} -> Median: {stat['median_ms']} ms, Mean: {stat['mean_ms']} ms, P95: {stat['p95_ms']} ms")

    if args.out:
        out_p = Path(args.out)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"\nSaved evaluation output to: {out_p}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
