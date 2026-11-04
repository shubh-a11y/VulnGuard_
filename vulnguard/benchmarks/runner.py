"""Repository benchmark runner for ML triage and installed SAST baselines."""

from __future__ import annotations

import time
from pathlib import Path

from vulnguard.benchmarks.evaluator import ApproachMetrics, BenchmarkReport, create_empty_report
from vulnguard.benchmarks.static_analyzer import run_all_sast
from vulnguard.data.parser import detect_language, iter_source_files, parse_file, read_source_file
from vulnguard.models.risk_scorer import RiskScorer


def benchmark_repository(
    repo_path: str | Path,
    max_files: int = 100,
    threshold: int | None = None,
) -> BenchmarkReport:
    """Benchmark VulnGuard triage and available SAST tools on a repository."""
    root = Path(repo_path).resolve()
    if not root.exists():
        raise FileNotFoundError(root)

    files = list(iter_source_files(root))[:max_files]
    scorer = RiskScorer()
    risk_threshold = threshold if threshold is not None else scorer.optimal_threshold
    triage = ApproachMetrics(approach_name="VulnGuard ML Triage")
    started = time.perf_counter()

    for file_path in files:
        language = detect_language(file_path)
        if not language:
            continue
        source = read_source_file(file_path)
        for unit in parse_file(str(file_path), source, language):
            triage.total_functions += 1
            result = scorer.score(unit.raw_source, language)
            if result.risk_score >= risk_threshold or result.bypass_reason:
                triage.vulnerabilities_detected += 1

    triage.total_time_seconds = time.perf_counter() - started
    report = create_empty_report()
    report.dataset_info = {
        "name": root.name,
        "path": str(root),
        "files": len(files),
        "functions": triage.total_functions,
        "risk_threshold": risk_threshold,
        "unavailable_tools": [],
    }
    report.approaches.append(triage)

    for sast in run_all_sast(str(root)):
        if not sast.available:
            report.dataset_info["unavailable_tools"].append(sast.tool)
            continue
        report.approaches.append(
            ApproachMetrics(
                approach_name=f"SAST ({sast.tool})",
                total_functions=triage.total_functions,
                vulnerabilities_detected=len(sast.findings),
                total_time_seconds=sast.elapsed_seconds,
            )
        )

    return report
