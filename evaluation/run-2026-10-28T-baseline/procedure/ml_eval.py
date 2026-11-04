"""External, read-only measurement driver for the ML triage layer (evaluation-side).

Loads the existing trained artifact through the application's own RiskScorer and
measures, without retraining or modifying the model:

  1. Per-function score / bypass reason / threshold decision for every function
     extracted from the labeled fixture cohort (`data/test_vulns`).
  2. Per-function inference latency (median/p95 over repeated runs, after
     warm-up), reported per language and overall.
  3. Repository-wide triage selection ratio on unlabeled code (the project's own
     `vulnguard/` package): functions above the deployed threshold / functions
     extracted. This is a *selection ratio*, not an accuracy metric, because the
     repository is not labeled.

No labels are invented. The only ground truth used is the one the application
itself declares in `vulnguard.evaluation.KNOWN_VULN_FUNCTIONS`.

Usage:
    python evaluation/run-2026-10-28T-baseline/procedure/ml_eval.py --out <dir>
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from vulnguard.data.parser import detect_language, iter_source_files, parse_file, read_source_file  # noqa: E402
from vulnguard.evaluation import KNOWN_VULN_FUNCTIONS  # noqa: E402
from vulnguard.models.risk_scorer import RiskScorer  # noqa: E402

REPEATS = 25


def _pct(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    pos = (len(ordered) - 1) * q
    low = int(pos)
    high = min(low + 1, len(ordered) - 1)
    frac = pos - low
    return ordered[low] * (1 - frac) + ordered[high] * frac


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    scorer = RiskScorer()
    threshold = scorer.optimal_threshold
    model_threshold = getattr(scorer, "_threshold", None)

    # ── 1. Labeled cohort scoring ────────────────────────────────────────
    labeled_rows = []
    for spec in KNOWN_VULN_FUNCTIONS:
        path = PROJECT_ROOT / spec["relative_path"]
        language = spec["language"]
        source = read_source_file(path)
        chunks = parse_file(str(path), source, language)
        target = next(
            (c for c in chunks if c.function_name == spec["function_id"].split(":")[-1]),
            None,
        )
        if target is None:
            labeled_rows.append({"function_id": spec["function_id"], "error": "not parsed"})
            continue
        result = scorer.score(target.raw_source, language)
        labeled_rows.append(
            {
                "function_id": spec["function_id"],
                "relative_path": spec["relative_path"],
                "language": language,
                "label": "vulnerable",
                "label_source": "vulnguard.evaluation.KNOWN_VULN_FUNCTIONS",
                "risk_score": result.risk_score,
                "bypass_reason": result.bypass_reason,
                "flagged_at_threshold": bool(
                    result.risk_score >= threshold or result.bypass_reason
                ),
                "model_probability": round(result.risk_score / 100.0, 4),
            }
        )

    # ── 2. Inference latency ────────────────────────────────────────────
    latency = {"overall": [], "by_language": {}}
    for spec in KNOWN_VULN_FUNCTIONS:
        path = PROJECT_ROOT / spec["relative_path"]
        language = spec["language"]
        source = read_source_file(path)
        chunks = parse_file(str(path), source, language)
        target = next(
            (c for c in chunks if c.function_name == spec["function_id"].split(":")[-1]),
            None,
        )
        if target is None:
            continue
        scorer.score(target.raw_source, language)  # warm-up (model already loaded)
        for _ in range(REPEATS):
            started = time.perf_counter()
            scorer.score(target.raw_source, language)
            elapsed_ms = (time.perf_counter() - started) * 1000
            latency["overall"].append(elapsed_ms)
            latency["by_language"].setdefault(language, []).append(elapsed_ms)

    overall = latency["overall"]
    latency_summary = {
        "samples": len(overall),
        "repeats_per_function": REPEATS,
        "median_ms": round(statistics.median(overall), 3) if overall else None,
        "mean_ms": round(statistics.fmean(overall), 3) if overall else None,
        "p95_ms": round(_pct(overall, 0.95), 3),
        "by_language": {
            lang: {
                "samples": len(values),
                "median_ms": round(statistics.median(values), 3),
                "mean_ms": round(statistics.fmean(values), 3),
                "p95_ms": round(_pct(values, 0.95), 3),
            }
            for lang, values in latency["by_language"].items()
        },
    }

    # ── 2b. Triage selection over every function parsed from the fixture dir ─
    fixture_total = 0
    fixture_flagged = 0
    fixture_rows = []
    for filepath in sorted((PROJECT_ROOT / "data/test_vulns").rglob("*")):
        if not filepath.is_file():
            continue
        language = detect_language(filepath)
        if not language:
            continue
        source = read_source_file(filepath)
        for chunk in parse_file(str(filepath), source, language):
            fixture_total += 1
            result = scorer.score(chunk.raw_source, language)
            flagged = bool(result.risk_score >= threshold or result.bypass_reason)
            fixture_flagged += int(flagged)
            fixture_rows.append(
                {
                    "function_id": f"{filepath.relative_to(PROJECT_ROOT / 'data/test_vulns').as_posix()}:{chunk.function_name}",
                    "language": language,
                    "risk_score": result.risk_score,
                    "bypass_reason": result.bypass_reason,
                    "flagged": flagged,
                }
            )

    # ── 3. Repository selection ratio (unlabeled) ───────────────────────
    repo_root = PROJECT_ROOT / "vulnguard"
    total = 0
    flagged = 0
    unsupported = 0
    per_file = []
    for filepath in iter_source_files(repo_root):
        language = detect_language(filepath)
        if not language:
            continue
        source = read_source_file(filepath)
        chunks = parse_file(str(filepath), source, language)
        file_total = 0
        file_flagged = 0
        for chunk in chunks:
            file_total += 1
            total += 1
            result = scorer.score(chunk.raw_source, language)
            if result.bypass_reason and result.bypass_reason.startswith("LANGUAGE_UNSUPPORTED"):
                unsupported += 1
            if result.risk_score >= threshold or result.bypass_reason:
                file_flagged += 1
                flagged += 1
        if file_total:
            per_file.append(
                {
                    "file": filepath.relative_to(PROJECT_ROOT).as_posix(),
                    "functions": file_total,
                    "flagged": file_flagged,
                }
            )

    payload = {
        "model_path": str((PROJECT_ROOT / "vulnguard/models/artifacts/vulnguard_classifier.joblib")),
        "deployed_risk_threshold_0_100": threshold,
        "model_probability_threshold": model_threshold,
        "template_dampening_factor": 0.5,
        "mega_function_loc_limit": 2000,
        "labeled_cohort": labeled_rows,
        "labeled_summary": {
            "labeled_examples": len([r for r in labeled_rows if "risk_score" in r]),
            "labeled_positives": len([r for r in labeled_rows if r.get("label") == "vulnerable"]),
            "labeled_negatives": 0,
            "flagged": len([r for r in labeled_rows if r.get("flagged_at_threshold")]),
        },
        "latency": latency_summary,
        "fixture_selection": {
            "functions_parsed": fixture_total,
            "functions_flagged": fixture_flagged,
            "selection_ratio": (fixture_flagged / fixture_total) if fixture_total else None,
            "rows": fixture_rows,
        },
        "repo_selection": {
            "repository": "vulnguard/",
            "labeled": False,
            "functions_extracted": total,
            "functions_flagged": flagged,
            "selection_ratio": (flagged / total) if total else None,
            "languages_unsupported": unsupported,
            "per_file": per_file,
        },
        "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    (out_dir / "ml_eval.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(f"threshold={threshold} model_p_threshold={model_threshold}")
    for row in labeled_rows:
        print(
            f"{row.get('function_id')}: score={row.get('risk_score')} "
            f"bypass={row.get('bypass_reason')} flagged={row.get('flagged_at_threshold')}"
        )
    print("labeled_summary", payload["labeled_summary"])
    print("latency", latency_summary)
    print("fixture_selection", {k: v for k, v in payload["fixture_selection"].items() if k != "rows"})
    print("repo_selection", {k: v for k, v in payload["repo_selection"].items() if k != "per_file"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
