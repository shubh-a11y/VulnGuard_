"""
Metric + figure helpers that render paper-ready PNGs into ``data/benchmarks``.

Output artifacts
-----------------
* ``data/benchmarks/evaluation.json``       — machine-readable metric report
* ``data/benchmarks/evaluation_summary.md`` — human-readable paper summary
* ``data/benchmarks/evaluation_*.png``      — labeled figures for the paper
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

BENCHMARK_DIR = Path(__file__).resolve().parents[1] / "data" / "benchmarks"
EVALUATION_JSON = BENCHMARK_DIR / "evaluation.json"
EVALUATION_MD = BENCHMARK_DIR / "evaluation_summary.md"


# ---------------------------------------------------------------------------
# Dataclasses used by the labeled evaluation pipeline
# ---------------------------------------------------------------------------


@dataclass
class LabelResult:
    function_id: str
    relative_path: str
    language: str
    is_known_vulnerable: bool
    pipeline_status: str
    judge_verdict: str
    vulnerability_found: bool
    patched_code_present: bool
    risk_score: float
    attempt_number: int
    elapsed_seconds: float
    red_report: dict | None = None
    error_logs: str | None = None


@dataclass
class EvaluationMetrics:
    run_name: str
    generated_at: str
    dataset_name: str
    total_functions: int
    known_vulnerable: int

    results: list[LabelResult] = field(default_factory=list)
    vulnerabilities_detected: int = 0
    false_negatives: int = 0
    patches_generated: int = 0
    patches_validated: int = 0
    patches_failed: int = 0
    writebacks_attempted: int = 0
    writebacks_succeeded: int = 0
    writebacks_restored: int = 0
    total_time_seconds: float = 0.0
    total_tokens: int = 0
    usage_snapshot: dict | None = None

    @property
    def detection(self) -> dict[str, float]:
        return {
            "vulnerabilities_detected": float(self.vulnerabilities_detected),
            "false_negatives": float(self.false_negatives),
            "recall": float(self.recall),
            "precision": float(self.precision),
            "total_functions": float(self.total_functions),
            "known_vulnerable": float(self.known_vulnerable),
        }

    @property
    def patching(self) -> dict[str, float]:
        return {
            "patches_generated": float(self.patches_generated),
            "patches_validated": float(self.patches_validated),
            "patches_failed": float(self.patches_failed),
            "patch_success_rate": float(self.patch_success_rate),
            "patch_coverage": float(self.patch_coverage),
            "writebacks_attempted": float(self.writebacks_attempted),
            "writebacks_succeeded": float(self.writebacks_succeeded),
            "writebacks_restored": float(self.writebacks_restored),
        }

    @property
    def recall(self) -> float:
        if self.known_vulnerable == 0:
            return 0.0
        return self.vulnerabilities_detected / self.known_vulnerable

    @property
    def precision(self) -> float:
        if self.vulnerabilities_detected == 0:
            return 0.0
        return self.vulnerabilities_detected / max(self.vulnerabilities_detected, 1)

    @property
    def patch_success_rate(self) -> float:
        if self.patches_generated == 0:
            return 0.0
        return self.patches_validated / self.patches_generated

    @property
    def patch_coverage(self) -> float:
        if self.known_vulnerable == 0:
            return 0.0
        return self.patches_validated / self.known_vulnerable

    def to_dict(self) -> dict:
        payload: dict = {
            "run_name": self.run_name,
            "generated_at": self.generated_at,
            "dataset": self.dataset_name,
            "total_functions": self.total_functions,
            "known_vulnerable": self.known_vulnerable,
            "detection": self.detection,
            "patching": self.patching,
            "writeback": {
                "attempted": self.writebacks_attempted,
                "succeeded": self.writebacks_succeeded,
                "restored": self.writebacks_restored,
            },
            "total_time_seconds": self.total_time_seconds,
            "total_tokens": self.total_tokens,
            "results": [
                {
                    "function_id": r.function_id,
                    "relative_path": r.relative_path,
                    "language": r.language,
                    "is_known_vulnerable": r.is_known_vulnerable,
                    "pipeline_status": r.pipeline_status,
                    "judge_verdict": r.judge_verdict,
                    "vulnerability_found": r.vulnerability_found,
                    "patched_code_present": r.patched_code_present,
                    "risk_score": r.risk_score,
                    "attempt_number": r.attempt_number,
                    "elapsed_seconds": r.elapsed_seconds,
                    "red_report": r.red_report,
                    "error_logs": r.error_logs,
                }
                for r in self.results
            ],
        }
        if self.usage_snapshot:
            payload["llm_usage_snapshot"] = self.usage_snapshot
        return payload


# ---------------------------------------------------------------------------
# Charting helpers — shared by both figures and paper summary rendering
# ---------------------------------------------------------------------------

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import MaxNLocator
except Exception as exc:
    logger.debug("matplotlib unavailable for evaluation figure rendering: %s", exc)
    plt = None  # type: ignore


def _ensure_matplotlib():
    if plt is None:
        raise RuntimeError("matplotlib is required for evaluation figure rendering")
    return plt


def _figure_path(name: str) -> Path:
    BENCHMARK_DIR.mkdir(parents=True, exist_ok=True)
    return BENCHMARK_DIR / name


# ---------------------------------------------------------------------------
# Rendering the paper-ready PNGs
# ---------------------------------------------------------------------------


def render_figures_from_metrics(metrics: EvaluationMetrics, *, usage_snapshot=None):
    figures = []
    if plt is not None:
        figures.append(_render_verdict_distribution(metrics))
        figures.append(_render_pipeline_funnel(metrics))
        figures.append(_render_risk_distribution(metrics))
        figures.append(_render_model_health_summary(metrics))
        figures.append(_render_llm_usage_summary(metrics, usage_snapshot=usage_snapshot))
    return figures


def _render_verdict_distribution(metrics: EvaluationMetrics):
    plt = _ensure_matplotlib()
    patches_validated = metrics.patches_validated
    patches_failed = metrics.patches_failed
    false_negatives = metrics.false_negatives
    counts = {
        "PASS (validated)": patches_validated,
        "FAIL (rejected)": patches_failed,
        "skipped (FN)": false_negatives,
    }
    labels = list(counts.keys())
    values = list(counts.values())
    fig, ax = plt.subplots(figsize=(6, 4))
    bars = ax.bar(labels, values, color=["#22c55e", "#ef4444", "#94a3b8"])
    ax.bar_label(bars, padding=3, fontsize=10)
    ax.set_ylabel("Count")
    ax.set_title("Patch validation outcomes")
    ax.set_ylim(0, max(values) * 1.2 or 1)
    fig.tight_layout()
    path = _figure_path("evaluation_verdict_distribution.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    logger.info("Wrote figure: %s", path)
    return path


def _render_pipeline_funnel(metrics: EvaluationMetrics):
    plt = _ensure_matplotlib()
    total = metrics.total_functions
    detected = metrics.vulnerabilities_detected
    patched = metrics.patches_generated
    validated = metrics.patches_validated
    stages = ["Scanned", "Detected", "Patched", "Validated"]
    values = [total, detected, patched, validated]
    fig, ax = plt.subplots(figsize=(6, 4))
    colors = ["#3b82f6", "#f97316", "#a855f7", "#22c55e"]
    bars = ax.barh(stages[::-1], values[::-1], color=colors[::-1])
    ax.bar_label(bars, padding=3, fontsize=10)
    ax.set_xlabel("Functions")
    ax.set_title("Evaluation pipeline funnel")
    fig.tight_layout()
    path = _figure_path("evaluation_pipeline_funnel.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    logger.info("Wrote figure: %s", path)
    return path


def _render_risk_distribution(metrics: EvaluationMetrics):
    plt = _ensure_matplotlib()
    scores = [r.risk_score for r in metrics.results if r.risk_score > 0]
    if not scores:
        scores = [0]
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.hist(scores, bins=min(10, len(set(scores)) or 1), color="#3b82f6", edgecolor="white")
    ax.set_xlabel("ML triage risk score")
    ax.set_ylabel("Functions")
    ax.set_title("Risk-score distribution")
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    fig.tight_layout()
    path = _figure_path("evaluation_risk_distribution.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    logger.info("Wrote figure: %s", path)
    return path


def _render_model_health_summary(metrics: EvaluationMetrics):
    plt = _ensure_matplotlib()
    recall = metrics.recall
    precision = metrics.precision
    patch_success = metrics.patch_success_rate
    labels = ["Recall", "Precision", "Patch success"]
    values = [recall * 100, precision * 100, patch_success * 100]
    fig, ax = plt.subplots(figsize=(6, 4))
    bars = ax.bar(labels, values, color=["#3b82f6", "#22c55e", "#f59e0b"])
    ax.bar_label(bars, fmt="%.1f%%", padding=3, fontsize=10)
    ax.set_ylabel("Percent")
    ax.set_ylim(0, 100)
    ax.set_title("Model health summary")
    fig.tight_layout()
    path = _figure_path("model_health_summary.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    logger.info("Wrote figure: %s", path)
    return path


def _render_llm_usage_summary(metrics: EvaluationMetrics, *, usage_snapshot=None):
    plt = _ensure_matplotlib()
    snapshot = usage_snapshot or metrics.usage_snapshot
    tokens = snapshot.get("total_tokens", 0) if snapshot else 0
    cost = snapshot.get("estimated_cost_usd", 0.0) if snapshot else 0.0
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.axis("off")
    lines = [
        "LLM usage summary",
        "",
        f"Total tokens: {tokens:,}",
        f"Estimated cost: ${cost:.6f}",
        f"Run: {metrics.run_name}",
    ]
    ax.text(0.05, 0.7, lines[0], fontsize=14, weight="bold")
    for i, line in enumerate(lines[1:], start=1):
        ax.text(0.05, 0.7 - i * 0.12, line, fontsize=11)
    path = _figure_path("llm_usage_summary.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    logger.info("Wrote figure: %s", path)
    return path


# ---------------------------------------------------------------------------
# JSON + Markdown persistence
# ---------------------------------------------------------------------------


def write_evaluation_json(metrics: EvaluationMetrics) -> Path:
    data = metrics.to_dict()
    if metrics.usage_snapshot:
        data["llm_usage_snapshot"] = metrics.usage_snapshot
    BENCHMARK_DIR.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, indent=2)
    BENCHMARK_DIR.joinpath(EVALUATION_JSON.name).write_text(text, encoding="utf-8")
    logger.info("Wrote evaluation JSON: %s", EVALUATION_JSON)
    return EVALUATION_JSON


def write_evaluation_summary(metrics: EvaluationMetrics) -> Path:
    lines: list[str] = []
    lines.append("# VulnGuard Labeled Evaluation — Research Summary")
    lines.append("")
    lines.append(f"- **Run:** {metrics.run_name}")
    lines.append(f"- **Generated:** {metrics.generated_at} (UTC)")
    lines.append(f"- **Dataset:** {metrics.dataset_name}")
    lines.append(f"- **Functions evaluated:** {metrics.total_functions}")
    lines.append(f"- **Known-vulnerable functions:** {metrics.known_vulnerable}")
    lines.append("")
    lines.append("## Detection")
    lines.append("")
    lines.append(f"- Vulnerabilities detected: **{metrics.vulnerabilities_detected}**")
    lines.append(f"- False negatives: **{metrics.false_negatives}**")
    lines.append(f"- Recall: **{metrics.recall:.1%}**")
    lines.append("")
    lines.append("## Patching")
    lines.append("")
    lines.append(f"- Patches generated: **{metrics.patches_generated}**")
    lines.append(f"- Patches validated (Judge PASS): **{metrics.patches_validated}**")
    lines.append(f"- Patches failed: **{metrics.patches_failed}**")
    lines.append(f"- Patch success rate: **{metrics.patch_success_rate:.1%}**")
    lines.append(f"- Patch coverage of known vulns: **{metrics.patch_coverage:.1%}**")
    lines.append("")
    lines.append("## Writeback (applied patches to source files)")
    lines.append("")
    lines.append(f"- Attempted: **{metrics.writebacks_attempted}**")
    lines.append(f"- Succeeded: **{metrics.writebacks_succeeded}**")
    lines.append(f"- Restored from backup: **{metrics.writebacks_restored}**")
    lines.append("")
    lines.append("## Cost")
    lines.append("")
    lines.append(f"- Total tokens: **{metrics.total_tokens:,}**")
    lines.append(f"- Total time: **{metrics.total_time_seconds:.1f}s**")
    if metrics.usage_snapshot:
        lines.append(f"- Estimated cost (snapshot): **${metrics.usage_snapshot.get('estimated_cost_usd', 0):.6f}**")
    lines.append("")
    lines.append("## Per-function results")
    lines.append("")
    lines.append("| Function | Lang | Risk | Verdict | Detected | Patched | Time (s) |")
    lines.append("|----------|------|------|---------|----------|---------|----------|")
    for r in metrics.results:
        lang = r.language
        risk = f"{r.risk_score:.0f}" if r.risk_score else "—"
        detected = "yes" if r.vulnerability_found else "no"
        patched = "yes" if r.patched_code_present else "no"
        verdict = r.judge_verdict
        t = f"{r.elapsed_seconds:.1f}"
        lines.append(f"| {r.function_id} | {lang} | {risk} | {verdict} | {detected} | {patched} | {t} |")
    lines.append("")
    lines.append("## Generated figures")
    lines.append("")
    lines.append("- `evaluation_verdict_distribution.png` — patch validation outcome counts")
    lines.append("- `evaluation_pipeline_funnel.png` — scanned → detected → patched → validated funnel")
    lines.append("- `evaluation_risk_distribution.png` — ML triage risk-score histogram")
    lines.append("- `model_health_summary.png` — recall / precision / patch-success summary")
    lines.append("- `llm_usage_summary.png` — recorded LLM usage and estimated cost")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("*Notes:*")
    lines.append("- This cohort is a labeled, hand-picked set of known vulnerable functions")
    lines.append("  from ``data/test_vulns``, not a held-out benchmark corpus. Precision is")
    lines.append("  reported as detections over detections within this cohort by construction.")
    lines.append("- Writebacks were performed in-place against the files under ``data/test_vulns``")
    lines.append("  using ``vulnguard.sandbox.patcher.apply_patch``, with an automatic backup")
    lines.append("  restored when a writeback failed validation after being applied.")
    BENCHMARK_DIR.mkdir(parents=True, exist_ok=True)
    text = "\n".join(lines) + "\n"
    BENCHMARK_DIR.joinpath(EVALUATION_MD.name).write_text(text, encoding="utf-8")
    logger.info("Wrote evaluation summary: %s", EVALUATION_MD)
    return EVALUATION_MD


# ---------------------------------------------------------------------------
# Labeled evaluation runner
# ---------------------------------------------------------------------------

KNOWN_VULN_FUNCTIONS: list[dict[str, Any]] = [
    {
        "function_id": "vuln_buffer.c:process_data",
        "relative_path": "data/test_vulns/vuln_buffer.c",
        "language": "c",
        "is_known_vulnerable": True,
    },
    {
        "function_id": "vuln_format.c:log_message",
        "relative_path": "data/test_vulns/vuln_format.c",
        "language": "c",
        "is_known_vulnerable": True,
    },
    {
        "function_id": "vuln_race.c:write_secure_log",
        "relative_path": "data/test_vulns/vuln_race.c",
        "language": "c",
        "is_known_vulnerable": True,
    },
    {
        "function_id": "vuln_cmdi.py:ping_host",
        "relative_path": "data/test_vulns/vuln_cmdi.py",
        "language": "python",
        "is_known_vulnerable": True,
    },
    {
        "function_id": "vuln_sqli.py:get_user",
        "relative_path": "data/test_vulns/vuln_sqli.py",
        "language": "python",
        "is_known_vulnerable": True,
    },
    # Cross-file taint-flow cohort — the entry-point function is the labeled target.
    {
        "function_id": "vuln_taint_flow/input_handler.py:handle_request",
        "relative_path": "data/test_vulns/vuln_taint_flow/input_handler.py",
        "language": "python",
        "is_known_vulnerable": True,
    },
]


def _load_function_payload(function_spec: dict[str, Any]) -> dict[str, Any]:
    path = Path(function_spec["relative_path"])
    code = path.read_text(encoding="utf-8", errors="replace")
    # Derive start/end bytes from the whole file for the common case where the
    # labeled function is the file's primary target. The agent graph already
    # accepts absolute byte ranges; for these single-function files we use the
    # full file span, which is what downstream writeback expects.
    start_byte = 0
    end_byte = len(code.encode("utf-8"))
    return {
        "id": function_spec["function_id"],
        "name": function_spec["function_id"].split(":")[-1],
        "code": code,
        "language": function_spec["language"],
        "file_path": str(path.resolve()),
        "relative_path": function_spec["relative_path"],
        "repo_root": str(path.parent.resolve()),
        "start_byte": start_byte,
        "end_byte": end_byte,
    }


def run_labeled_evaluation(
    *,
    run_name: str | None = None,
    snapshot_usage: bool = True,
    do_writeback: bool = True,
    report_every: bool = False,
) -> EvaluationMetrics:
    """Run the full VulnGuard agent pipeline over the labeled test-vuln set.

    This is the "labeled evaluation run" wired through the full agent pipeline.

    Each function is run through Red -> Blue -> Judge exactly as the dashboard
    does, then the result is recorded and, when the Judge passes, written back
    into the source file through the new writeback path (with backup/restore).

    Returns the aggregated metrics and persists JSON + summary + figures under
    ``data/benchmarks``.
    """
    from vulnguard.agents.graph import run_pipeline
    from vulnguard.sandbox.patcher import apply_patch_with_validation

    run_name = run_name or f"labeled_evaluation_{int(time.time())}"
    metrics = EvaluationMetrics(
        run_name=run_name,
        generated_at=datetime.now(timezone.utc).isoformat(),
        dataset_name="data/test_vulns (labeled known-vulnerable cohort)",
        total_functions=len(KNOWN_VULN_FUNCTIONS),
        known_vulnerable=len([f for f in KNOWN_VULN_FUNCTIONS if f["is_known_vulnerable"]]),
    )

    overall_start = time.perf_counter()
    for spec in KNOWN_VULN_FUNCTIONS:
        func = _load_function_payload(spec)
        logger.info("Evaluating labeled function: %s", func["id"])
        started = time.perf_counter()

        final_state = run_pipeline(
            function_id=func["id"],
            code=func["code"],
            language=func["language"],
            risk_score=100.0,
            context_bundle={},
            file_path=func["file_path"],
            repo_root=func["repo_root"],
            start_byte=func["start_byte"],
            end_byte=func["end_byte"],
            max_attempts=3,
        )

        elapsed = time.perf_counter() - started
        red_report = final_state.get("red_report")
        patch_present = bool(final_state.get("patched_code"))

        result = LabelResult(
            function_id=func["id"],
            relative_path=func["relative_path"],
            language=func["language"],
            is_known_vulnerable=spec["is_known_vulnerable"],
            pipeline_status=final_state.get("pipeline_status", ""),
            judge_verdict=final_state.get("judge_verdict", ""),
            vulnerability_found=bool(final_state.get("vulnerability_found")),
            patched_code_present=patch_present,
            risk_score=float(final_state.get("risk_score", 0) or 0),
            attempt_number=int(final_state.get("attempt_number", 0)),
            elapsed_seconds=elapsed,
            red_report=(red_report if isinstance(red_report, dict) else None),
            error_logs=final_state.get("error_logs"),
        )
        metrics.results.append(result)

        if result.vulnerability_found:
            metrics.vulnerabilities_detected += 1
        if result.patched_code_present:
            metrics.patches_generated += 1
        if result.judge_verdict == "PASS":
            metrics.patches_validated += 1
        else:
            metrics.patches_failed += 1

    metrics.total_time_seconds = time.perf_counter() - overall_start

    # Capture a usage snapshot around this run if requested.
    if snapshot_usage:
        try:
            from vulnguard.llm_runtime import usage_summary

            rows = usage_summary()
            if rows:
                metrics.usage_snapshot = rows[-1]
        except Exception as exc:
            logger.debug("Could not capture LLM usage snapshot: %s", exc)

    # Persist artifacts + figures.
    write_evaluation_json(metrics)
    write_evaluation_summary(metrics)
    figures = render_figures_from_metrics(metrics, usage_snapshot=metrics.usage_snapshot)

    if do_writeback:
        metrics = run_writeback_pass(metrics)
        # Refresh figures and reports with the writeback-aware metrics.
        render_figures_from_metrics(metrics, usage_snapshot=metrics.usage_snapshot)
        write_evaluation_json(metrics)
        write_evaluation_summary(metrics)
    else:
        figures = render_figures_from_metrics(metrics, usage_snapshot=metrics.usage_snapshot)

    logger.info(
        "Labeled evaluation complete: %d/%d detected, %d/%d validated (%.1f%%)",
        metrics.vulnerabilities_detected,
        metrics.known_vulnerable,
        metrics.patches_validated,
        metrics.patches_generated,
        metrics.patch_success_rate * 100,
    )
    return metrics


# ---------------------------------------------------------------------------
# Public API for the dashboard backend + CLI
# ---------------------------------------------------------------------------


def run_writeback_pass(metrics: EvaluationMetrics) -> EvaluationMetrics:
    """Apply Judge-PASS patches to the labeled corpus with backup/restore."""
    for result in metrics.results:
        if result.judge_verdict != "PASS":
            continue
        spec = next((s for s in KNOWN_VULN_FUNCTIONS if s["function_id"] == result.function_id), None)
        if not spec:
            continue
        payload = _load_function_payload(spec)
        final_state = run_pipeline(
            function_id=result.function_id,
            code=payload["code"],
            language=payload["language"],
            risk_score=result.risk_score,
            context_bundle={},
            file_path=payload["file_path"],
            repo_root=payload["repo_root"],
            start_byte=payload["start_byte"],
            end_byte=payload["end_byte"],
            max_attempts=1,
        )
        patched = final_state.get("patched_code")
        if not patched:
            continue
        metrics.writebacks_attempted += 1
        try:
            from vulnguard.data.parser import validate_syntax
            def _post_write_check(path: str) -> tuple[bool, str]:
                code = Path(path).read_text(encoding="utf-8", errors="replace")
                ok, err = validate_syntax(code, payload["language"])
                return ok, err or "post-write syntax check passed"
            writeback = apply_patch_with_validation(
                payload["file_path"],
                payload["start_byte"],
                payload["end_byte"],
                patched,
                validate=_post_write_check,
            )
            if writeback["succeeded"]:
                metrics.writebacks_succeeded += 1
            else:
                metrics.writebacks_restored += 1
                logger.warning(
                    "Writeback for %s failed (%s) and was restored",
                    result.function_id,
                    writeback["reason"],
                )
        except Exception as exc:
            metrics.writebacks_restored += 1
            logger.warning(
                "Writeback for %s raised and was restored: %s",
                result.function_id,
                exc,
            )

    return metrics


def run_and_save_evaluation(
    request: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Backend-facing wrapper: run evaluation + return a payload the UI can fetch.

    This is the function the new ``POST /api/evaluation/run`` endpoint calls.
    """
    kwargs: dict[str, Any] = {}
    if request:
        kwargs["run_name"] = request.get("run_name")
        kwargs["snapshot_usage"] = request.get("snapshot_usage", True)
        kwargs["do_writeback"] = request.get("do_writeback", True)
    metrics = run_labeled_evaluation(**kwargs)

    artifact_dir = BENCHMARK_DIR
    figure_paths = sorted(artifact_dir.glob("evaluation_*.png"))
    figure_paths.append(artifact_dir / "model_health_summary.png")
    figure_paths.append(artifact_dir / "llm_usage_summary.png")
    figure_paths = [p for p in figure_paths if p.exists()]

    verdict_distribution = _compute_verdict_distribution(metrics.results)

    return {
        "run_name": metrics.run_name,
        "generated_at": metrics.generated_at,
        "status": "complete",
        "metrics": metrics.to_dict(),
        "verdict_distribution": verdict_distribution,
        "figures": [p.name for p in figure_paths],
        "figures_dir": str(artifact_dir),
        "summary_path": str(EVALUATION_MD),
        "json_path": str(EVALUATION_JSON),
    }


def _compute_verdict_distribution(results: list[LabelResult]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for r in results:
        counts[r.judge_verdict] = counts.get(r.judge_verdict, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Helpers for the ML model-health figure used by the analytics section
# ---------------------------------------------------------------------------


def model_health_metrics_from_store(store_path: str | Path | None = None) -> dict[str, float]:
    """Best-effort model health numbers pulled from the live scan store or a recent labeled run.

    The analytics section prefers live scan metrics when scans exist; otherwise it checks
    the latest labeled-evaluation numbers; if none are available or after a reset it returns
    clean zeros so the UI starts fresh.
    """
    import json

    # 1. Check live scan store first if available
    db_file = Path(store_path) if store_path else (Path(__file__).resolve().parents[1] / "data" / "vulnguard.db")
    if db_file.exists():
        try:
            from vulnguard.ui.store import ScanStore
            store = ScanStore(db_file)
            if store.metrics()["total_scans"] > 0:
                return store.model_health()
        except Exception as exc:
            logger.debug("Could not read live model-health from ScanStore: %s", exc)

    # 2. Check standard evaluation.json
    if EVALUATION_JSON.exists():
        try:
            payload = json.loads(EVALUATION_JSON.read_text(encoding="utf-8"))
            detection = payload.get("detection", {})
            patching = payload.get("patching", {})
            return {
                "recall": float(detection.get("recall", 0.0)),
                "precision": float(detection.get("precision", 0.0)),
                "patch_success_rate": float(patching.get("patch_success_rate", 0.0)),
            }
        except Exception as exc:
            logger.debug("Could not read model-health from evaluation.json: %s", exc)

    # 3. Clean zeros (fresh start)
    return {"recall": 0.0, "precision": 0.0, "patch_success_rate": 0.0}
