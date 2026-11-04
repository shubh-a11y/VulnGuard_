"""
VulnGuard AI — CLI entry point.

Subcommands:
  vulnguard doctor      - Verify Gemini and Docker prerequisites
  vulnguard train       - Train/retrain the ML triage model
  vulnguard scan        - Full pipeline scan of a repository
  vulnguard benchmark   - Run comparative benchmarks
  vulnguard dashboard   - Launch the web dashboard
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from vulnguard.config import cfg


def _setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s │ %(name)-28s │ %(levelname)-7s │ %(message)s",
        datefmt="%H:%M:%S",
    )


def cmd_doctor(args):
    """Validate the runtime configuration before starting the dashboard."""
    problems = []
    if sys.version_info[:2] != (3, 12):
        problems.append(
            f"Use Python 3.12 in .venv; current interpreter is {sys.version.split()[0]}"
        )
    else:
        print(f"[OK] Python: {sys.version.split()[0]}")

    try:
        import sklearn
        import xgboost

        if sklearn.__version__ != "1.8.0":
            problems.append(
                f"Install scikit-learn 1.8.0; current version is {sklearn.__version__}"
            )
        else:
            print("[OK] scikit-learn: 1.8.0")
        if xgboost.__version__ != "3.3.0":
            problems.append(f"Install xgboost 3.3.0; current version is {xgboost.__version__}")
        else:
            print("[OK] xgboost: 3.3.0")
    except ImportError as exc:
        problems.append(f"Install Python requirements: {exc}")

    if not cfg.llm.api_key or cfg.llm.api_key.startswith("your-"):
        problems.append("Set GEMINI_API_KEY in .env")
    else:
        print("[OK] Gemini API key is configured")

    routes = {
        cfg.llm.provider,
        cfg.routing.high_risk_provider,
        cfg.routing.medium_risk_provider,
    }
    if routes != {"gemini"}:
        problems.append(f"All LLM routes must use Gemini; found: {', '.join(sorted(routes))}")
    else:
        print(
            "[OK] Gemini routes: "
            f"{cfg.routing.high_risk_model} / {cfg.routing.medium_risk_model}"
        )

    if cfg.llm.api_key and routes == {"gemini"}:
        try:
            from vulnguard.llm_runtime import completion, response_text

            response = completion(
                model=f"gemini/{cfg.routing.high_risk_model}",
                messages=[{"role": "user", "content": "Reply with OK."}],
                max_tokens=256,
            )
            response_text(response)
            print("[OK] Gemini live request")
        except Exception as exc:
            problems.append(f"Gemini live request failed: {exc}")

    try:
        from vulnguard.sandbox.docker_runner import ensure_sandbox_ready

        ensure_sandbox_ready(build_if_missing=args.build_sandbox)
        print(f"[OK] Docker sandbox: {cfg.sandbox.sandbox_image}")
    except Exception as exc:
        problems.append(str(exc))

    if problems:
        print("\nSetup is not ready:")
        for problem in problems:
            print(f"[FAIL] {problem}")
        raise SystemExit(1)

    print("\nVulnGuard is ready. Start the backend and frontend in two terminals.")


# ── Subcommand: train ─────────────────────────────────────────────────────

def cmd_train(args):
    """Train or retrain the ML triage classifier."""
    from vulnguard.data.fetch_dataset import fetch_dataset
    from vulnguard.models.train_classifier import train

    _setup_logging(args.verbose)
    logger = logging.getLogger("vulnguard.train")

    language = getattr(args, "language", "python")

    logger.info("Loading %s dataset…", language)
    df = fetch_dataset(max_samples=args.max_samples, language=language)

    logger.info("Training classifier (language=%s)…", language)
    model, metrics = train(df, use_smote=args.smote, language=language)

    logger.info("Training complete!")
    logger.info("AUC-PR: %.4f | F1: %.4f | MCC: %.4f", metrics["auc_pr"], metrics["f1"], metrics["mcc"])


# ── Subcommand: scan ──────────────────────────────────────────────────────

def cmd_scan(args):
    """Scan a repository or specific function for vulnerabilities."""
    from vulnguard.data.context_gatherer import gather_context
    from vulnguard.data.parser import (
        CodeUnit,
        detect_language,
        iter_source_files,
        parse_file,
        read_source_file,
    )
    from vulnguard.models.risk_scorer import RiskScorer

    _setup_logging(args.verbose)
    logger = logging.getLogger("vulnguard.scan")

    repo_path = Path(args.repo_path).resolve()
    if not repo_path.exists():
        logger.error("Path does not exist: %s", repo_path)
        sys.exit(1)

    # ── Single file scan ──────────────────────────────────
    if repo_path.is_file():
        language = detect_language(repo_path)
        if not language:
            logger.error("Unsupported source file: %s", repo_path)
            return

        code = read_source_file(repo_path)

        try:
            from vulnguard.models.risk_scorer import RiskScorer
            scorer = RiskScorer()
            threshold = args.threshold if args.threshold is not None else scorer.optimal_threshold
        except FileNotFoundError:
            logger.warning("No trained model found — using bypass mode (all functions flagged)")
            scorer = None
            threshold = args.threshold if args.threshold is not None else cfg.triage.risk_threshold

        chunks = parse_file(str(repo_path), code, language)
        if not chunks:
            chunks = [
                CodeUnit(
                    file_path=str(repo_path),
                    function_name=repo_path.name,
                    class_name=None,
                    start_byte=0,
                    end_byte=len(code.encode("utf-8")),
                    start_line=1,
                    end_line=len(code.splitlines()),
                    raw_source=code,
                    language=language,
                )
            ]
        logger.info("Parsed %d functions from %s", len(chunks), repo_path.name)

        for chunk in chunks:
            if scorer:
                result = scorer.score(chunk.raw_source, chunk.language)
                risk_score = result.risk_score
                bypass = result.bypass_reason is not None
            else:
                risk_score = 100.0
                bypass = True

            logger.info("Function '%s' Risk score: %.1f/100 (threshold: %d)%s",
                         chunk.function_name, risk_score, threshold, f" [BYPASS]" if bypass else "")

            if risk_score < threshold and not bypass:
                logger.info("✅ Below threshold — function '%s' is likely safe", chunk.function_name)
                continue

            # Gather context
            ctx = gather_context(
                func_code=chunk.raw_source,
                file_path=repo_path,
                repo_root=repo_path.parent,
                language=chunk.language,
            )
            # Merge tree-sitter context
            ctx.imports.extend(chunk.imports)
            ctx.callee_signatures.extend(chunk.callees)

            if getattr(args, "async_scan", False):
                logger.info("Enqueuing scan asynchronously...")
                from vulnguard.queue import enqueue_scan
                job = enqueue_scan(
                    function_id=f"{repo_path.name}:{chunk.function_name}",
                    code=chunk.raw_source,
                    language=chunk.language,
                    risk_score=risk_score,
                    context_bundle=ctx.to_dict(),
                    file_path=str(repo_path),
                    repo_root=str(repo_path.parent),
                    start_byte=chunk.start_byte,
                    end_byte=chunk.end_byte,
                )
                logger.info("Task enqueued with Job ID: %s", job.id)
                continue

            if args.no_docker:
                logger.info("Running in report-only mode (--no-docker)")
                from vulnguard.agents.graph import run_pipeline
                # Still run the pipeline — sandbox will gracefully skip
                final_state = run_pipeline(
                    function_id=f"{repo_path.name}:{chunk.function_name}",
                    code=chunk.raw_source,
                    language=chunk.language,
                    risk_score=risk_score,
                    context_bundle=ctx.to_dict(),
                    file_path=str(repo_path),
                    repo_root=str(repo_path.parent),
                    start_byte=chunk.start_byte,
                    end_byte=chunk.end_byte,
                    max_attempts=args.max_retries,
                )
            else:
                from vulnguard.agents.graph import run_pipeline
                final_state = run_pipeline(
                    function_id=f"{repo_path.name}:{chunk.function_name}",
                    code=chunk.raw_source,
                    language=chunk.language,
                    risk_score=risk_score,
                    context_bundle=ctx.to_dict(),
                    file_path=str(repo_path),
                    repo_root=str(repo_path.parent),
                    start_byte=chunk.start_byte,
                    end_byte=chunk.end_byte,
                    max_attempts=args.max_retries,
                )

            # Print result summary
            _print_scan_result(final_state)

    else:
        # ── Directory scan — find all source files ────────
        logger.info("Scanning repository: %s", repo_path)
        source_files = list(iter_source_files(repo_path))

        logger.info("Found %d source files", len(source_files))

        try:
            from vulnguard.models.risk_scorer import RiskScorer
            scorer = RiskScorer()
            threshold = args.threshold if args.threshold is not None else scorer.optimal_threshold
        except FileNotFoundError:
            scorer = None
            threshold = args.threshold if args.threshold is not None else cfg.triage.risk_threshold
            logger.warning("No trained model — all files will be scanned")

        high_risk = []
        total_functions = 0
        for filepath in source_files:
            language = detect_language(filepath)
            if not language:
                continue
            code = read_source_file(filepath)
            chunks = parse_file(str(filepath), code, language)
            if not chunks:
                continue
            total_functions += len(chunks)
            for chunk in chunks:
                if scorer:
                    result = scorer.score(chunk.raw_source, language)
                    if result.risk_score >= threshold or result.bypass_reason:
                        high_risk.append((filepath, chunk, result.risk_score))
                else:
                    high_risk.append((filepath, chunk, 100.0))

        logger.info("%d/%d functions above threshold (%d)", len(high_risk), total_functions, threshold)

        for filepath, chunk, score in high_risk:
            logger.info("─" * 60)
            logger.info("Scanning: %s:%s (risk: %.1f)", filepath.name, chunk.function_name, score)

            ctx = gather_context(
                func_code=chunk.raw_source,
                file_path=filepath,
                repo_root=repo_path,
                language=chunk.language,
            )
            ctx.imports.extend(chunk.imports)
            ctx.callee_signatures.extend(chunk.callees)

            from vulnguard.agents.graph import run_pipeline
            final_state = run_pipeline(
                function_id=f"{filepath.relative_to(repo_path).as_posix()}:{chunk.function_name}",
                code=chunk.raw_source,
                language=chunk.language,
                risk_score=score,
                context_bundle=ctx.to_dict(),
                file_path=str(filepath),
                repo_root=str(repo_path),
                start_byte=chunk.start_byte,
                end_byte=chunk.end_byte,
                max_attempts=args.max_retries,
            )
            _print_scan_result(final_state)


def _print_scan_result(state: dict):
    """Print a concise scan result to console."""
    status = state.get("pipeline_status", "UNKNOWN")
    verdict = state.get("judge_verdict", "")
    vuln = state.get("vulnerability_found", False)

    if status == "RED_ERROR" or verdict == "RED_AGENT_ERROR":
        # A generation/parse failure is not a clean negative result.
        print("  ❌ Analysis failed — no reliable conclusion for this function")
        if state.get("error_logs"):
            print(f"  {str(state['error_logs'])[:500]}")
    elif not vuln:
        print(f"  ✅ No vulnerability found")
    elif verdict == "PASS":
        print(f"  🛡️  Vulnerability found & PATCHED")
        if state.get("patch_diff"):
            print(f"  Diff:\n{state['patch_diff'][:500]}")
    else:
        print(f"  ⚠️  Vulnerability found — patch status: {verdict}")
        if state.get("red_report"):
            report = state["red_report"]
            print(f"  Type: {report.get('vulnerability_type', '?')}")
            print(f"  Severity: {report.get('severity', '?')}")


# ── Subcommand: benchmark ────────────────────────────────────────────────

def cmd_benchmark(args):
    """Run comparative benchmarks."""
    _setup_logging(args.verbose)
    from vulnguard.benchmarks.runner import benchmark_repository

    repo_path = Path(args.repo_path).resolve()
    output_dir = Path(args.output_dir).resolve()
    report = benchmark_repository(repo_path, max_files=args.max_files, threshold=args.threshold)
    json_path = output_dir / "benchmark.json"
    markdown_path = output_dir / "benchmark.md"
    report.to_json(json_path)
    report.to_markdown(markdown_path)
    print(report.to_markdown())
    print(f"JSON: {json_path}")
    print(f"Markdown: {markdown_path}")


# ── Subcommand: dashboard ────────────────────────────────────────────────

def cmd_dashboard(args):
    """Launch the web dashboard."""
    _setup_logging(args.verbose)
    logger = logging.getLogger("vulnguard.dashboard")

    if args.backend == "streamlit":
        import subprocess
        app_path = Path(__file__).parent / "ui" / "app.py"
        logger.info("Launching Streamlit dashboard…")
        subprocess.run([sys.executable, "-m", "streamlit", "run", str(app_path)])
    else:
        from vulnguard.ui.server import create_app
        import uvicorn
        logger.info("Launching FastAPI backend on port %d…", args.port)
        app = create_app()
        uvicorn.run(app, host="0.0.0.0", port=args.port)


# ── Argument parser ──────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnguard",
        description="VulnGuard AI — Intelligent Cybersecurity Framework",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    sub = parser.add_subparsers(dest="command", required=True)

    # doctor
    p_doctor = sub.add_parser("doctor", help="Verify Gemini and Docker prerequisites")
    p_doctor.add_argument(
        "--build-sandbox",
        action="store_true",
        help="Build the sandbox image through the Docker API when it is missing",
    )
    p_doctor.set_defaults(func=cmd_doctor)

    # train
    p_train = sub.add_parser("train", help="Train the ML triage classifier")
    p_train.add_argument("--max-samples", type=int, default=None, help="Cap dataset size (for testing)")
    p_train.add_argument("--smote", action="store_true", help="Enable SMOTE oversampling")
    p_train.add_argument("--language", default="python", choices=["python", "c", "cpp"], help="Target language for training")
    p_train.set_defaults(func=cmd_train)

    # scan
    p_scan = sub.add_parser("scan", help="Scan a repo or file for vulnerabilities")
    p_scan.add_argument("repo_path", help="Path to repository or source file")
    p_scan.add_argument("--threshold", type=int, default=None, help="Risk score threshold (0-100)")
    p_scan.add_argument("--max-retries", type=int, default=3, help="Max Blue Agent retry attempts")
    p_scan.add_argument("--no-docker", action="store_true", help="Run without Docker (report-only mode)")
    p_scan.add_argument("--async-scan", action="store_true", help="Run scan in background via RQ")
    p_scan.set_defaults(func=cmd_scan)

    # benchmark
    p_bench = sub.add_parser("benchmark", help="Run comparative benchmarks")
    p_bench.add_argument("repo_path", nargs="?", default="data/test_vulns", help="Path to repository")
    p_bench.add_argument("--max-files", type=int, default=100, help="Maximum source files to benchmark")
    p_bench.add_argument("--threshold", type=int, default=None, help="Risk threshold override (0-100)")
    p_bench.add_argument("--output-dir", default="data/benchmarks", help="Report output directory")
    p_bench.set_defaults(func=cmd_benchmark)

    # dashboard
    p_dash = sub.add_parser("dashboard", help="Launch the web dashboard")
    p_dash.add_argument("--backend", choices=["fastapi", "streamlit"], default="streamlit")
    p_dash.add_argument("--port", type=int, default=8000, help="FastAPI port")
    p_dash.set_defaults(func=cmd_dashboard)

    # usage
    def cmd_usage(args):
        from vulnguard.llm_runtime import usage_summary

        rows = usage_summary()
        if args.json:
            print(json.dumps(rows, indent=2))
            return
        if not rows:
            print("No LLM usage recorded yet.")
            return
        print(
            f"{'Provider':<12} {'Model':<32} {'Calls':>6} {'Input':>10} "
            f"{'Output':>10} {'Cost USD':>12} {'Avg ms':>10}"
        )
        for row in rows:
            print(
                f"{row['provider']:<12} {row['model']:<32} {row['calls']:>6} "
                f"{row['input_tokens']:>10} {row['output_tokens']:>10} "
                f"{row['estimated_cost_usd']:>12.6f} {row['avg_latency_ms']:>10.1f}"
            )

    p_usage = sub.add_parser("usage", help="Summarize recorded LLM token usage and cost")
    p_usage.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    p_usage.set_defaults(func=cmd_usage)

    # worker
    def cmd_worker(args):
        from vulnguard.worker import start_worker
        start_worker()

    p_work = sub.add_parser("worker", help="Start the RQ background worker")
    p_work.set_defaults(func=cmd_worker)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
