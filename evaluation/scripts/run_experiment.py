"""
Unified Experiment Runner — Phases 4, 5, 6, 7

Executes genuine, reproducible evaluation runs under configurable ablation settings:
- Full VulnGuard pipeline with ML triage
- Triage-bypassed pipeline
- Single-pass baseline
- Retry bound ablation (k=1 vs k=3)

Enforces strict 6-point repair acceptance criteria and captures per-case raw JSON observations.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import logging
import os
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from vulnguard.agents.graph import run_pipeline
from vulnguard.config import cfg
from vulnguard.data.parser import detect_language, validate_syntax
from vulnguard.models.risk_scorer import RiskScorer
from vulnguard.sandbox.patcher import apply_patch

from evaluation.dataset.harness import run_regression_test, run_security_test
from evaluation.scripts.calculate_metrics import aggregate_run_metrics, export_markdown_table
from evaluation.scripts.environment_info import capture_environment_metadata
from evaluation.scripts.evaluate_ml_triage import evaluate_triage
from evaluation.scripts.generate_charts import generate_all_charts
from evaluation.scripts.validate_dataset import load_manifest

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("vulnguard.evaluation")

USAGE_FILE = REPO_ROOT / "data" / "llm_usage.jsonl"


def _read_usage_lines() -> list[dict[str, Any]]:
    if not USAGE_FILE.exists():
        return []
    records = []
    with USAGE_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except Exception:
                    pass
    return records


def _run_single_pass_llm(code: str, language: str, function_name: str) -> dict[str, Any]:
    """Genuine single-pass baseline: diagnose and patch in a single prompt without iteration."""
    from vulnguard.agents.red_agent import _call_llm
    prompt = (
        f"You are a secure code analysis and automated patching assistant.\n"
        f"Analyze the following {language} function '{function_name}':\n\n"
        f"```\n{code}\n```\n\n"
        f"Perform vulnerability analysis and repair in a single pass. Return a JSON object with keys:\n"
        f"- vulnerability_found (bool)\n"
        f"- cwe_id (string, e.g. 'CWE-89' or null)\n"
        f"- vulnerability_type (string or null)\n"
        f"- patched_code (the full replacement code for the function, or null if no vuln)\n"
        f"- justification (brief explanation)\n"
    )
    res = _call_llm(prompt, temperature=0.0)
    text = res.get("text", "").strip()

    # Parse response JSON
    data = {}
    try:
        cleaned = text
        if cleaned.startswith("```"):
            lines = cleaned.splitlines()
            if len(lines) > 2 and lines[-1].strip() == "```":
                cleaned = "\n".join(lines[1:-1])
        data = json.loads(cleaned)
    except Exception:
        # Fallback heuristic extraction
        data = {
            "vulnerability_found": "cwe" in text.lower(),
            "cwe_id": "CWE-UNKNOWN",
            "patched_code": None,
            "justification": text,
        }
    return data


def classify_failure(
    vulnerability_found: bool,
    cwe_match: bool,
    loc_correct: bool,
    patch_generated: bool,
    patch_applied: bool,
    syntax_valid: bool,
    patched_sec_blocked: bool,
    patched_reg_passed: bool,
    strict_success: bool,
) -> str:
    if strict_success:
        return "STRICT_REPAIR_SUCCESS"
    if not vulnerability_found:
        return "RED_DETECTION_FAILURE"
    if not cwe_match:
        return "INCORRECT_CWE_CLASSIFICATION"
    if not loc_correct:
        return "INCORRECT_LOCALIZATION"
    if not patch_generated:
        return "BLUE_GENERATION_FAILURE"
    if not patch_applied:
        return "PATCH_APPLICATION_FAILURE"
    if not syntax_valid:
        return "BUILD_SYNTAX_FAILURE"
    if not patched_reg_passed:
        return "REGRESSION_FAILURE"
    if not patched_sec_blocked:
        return "EXPLOIT_REMAINS_SUCCESSFUL"
    return "UNKNOWN_FAILURE"


def run_experiment(config_path: Path, run_id_override: str | None = None) -> Path:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    exp_id = config.get("experiment_id", "exp_run")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = run_id_override or f"run-{timestamp}-{exp_id}"
    run_dir = REPO_ROOT / "evaluation" / "runs" / run_id
    raw_dir = run_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    # 1. Save metadata
    (run_dir / "experiment_config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
    env_meta = capture_environment_metadata()
    (run_dir / "environment.json").write_text(json.dumps(env_meta, indent=2), encoding="utf-8")

    # 2. Run ML Triage evaluation and cache
    ml_eval_results = evaluate_triage()
    (raw_dir / "ml_triage_evaluation.json").write_text(json.dumps(ml_eval_results, indent=2), encoding="utf-8")
    shared_ml = REPO_ROOT / "evaluation" / "dataset" / "ml_triage_evaluation.json"
    shared_ml.parent.mkdir(parents=True, exist_ok=True)
    shared_ml.write_text(json.dumps(ml_eval_results, indent=2), encoding="utf-8")

    # 3. Load manifest cases
    all_manifest = load_manifest()
    target_ids = set(config.get("cases", [c["case_id"] for c in all_manifest]))
    eval_cases = [c for c in all_manifest if c["case_id"] in target_ids]

    logger.info("Starting experiment: %s (%d cases) -> %s", exp_id, len(eval_cases), run_dir)

    scorer = RiskScorer()
    triage_threshold = config.get("triage_threshold", cfg.triage.risk_threshold)
    triage_enabled = config.get("triage_enabled", True)
    multi_agent = config.get("multi_agent", True)
    single_pass = config.get("single_pass_baseline", False)
    max_attempts = config.get("max_attempts", 3)

    for idx, case in enumerate(eval_cases, start=1):
        cid = case["case_id"]
        gt = case["ground_truth"]
        cwe = case["cwe"]
        lang = case["language"]
        func_name = case["target_function"]
        src_path = REPO_ROOT / case["source_path"]
        code = src_path.read_text(encoding="utf-8", errors="replace")

        logger.info("[%d/%d] Evaluating Case %s (%s, %s, %s)", idx, len(eval_cases), cid, case["category"], gt, lang)

        # Baseline Ground-Truth Validation on Original Source
        orig_sec = run_security_test(cid, src_path)
        orig_reg = run_regression_test(cid, src_path)

        # Triage Layer
        triage_info = {"enabled": triage_enabled, "selected": True, "risk_score": 100.0, "bypass_reason": None}
        if triage_enabled:
            score_res = scorer.score(code, lang)
            triage_info["risk_score"] = score_res.risk_score
            triage_info["bypass_reason"] = score_res.bypass_reason
            triage_info["selected"] = (score_res.risk_score >= triage_threshold)

        if not triage_info["selected"]:
            # Filtered out by ML triage
            case_record = {
                "run_id": run_id,
                "case_id": cid,
                "ground_truth": gt,
                "cwe": cwe,
                "language": lang,
                "source_path": case["source_path"],
                "target_function": func_name,
                "triage": triage_info,
                "vulnerability_found": False,
                "pipeline_status": "TRIAGE_FILTERED",
                "failure_category": "TRIAGE_FILTERED",
                "strict_repair_success": False,
                "original_security_test": orig_sec.to_dict(),
                "original_regression_test": orig_reg.to_dict(),
                "elapsed_seconds": 0.0,
                "usage": {"calls": 0, "input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "cost_usd": 0.0},
            }
            (raw_dir / f"case_{cid}_trial_001.json").write_text(json.dumps(case_record, indent=2), encoding="utf-8")
            continue

        # Setup isolated workspace
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as ws_dir:
            ws_path = Path(ws_dir)
            ws_file = ws_path / src_path.name
            ws_file.write_text(code, encoding="utf-8")

            # Snapshot usage log before execution
            usage_before = len(_read_usage_lines())
            t0 = time.perf_counter()

            # Execute pipeline
            if single_pass:
                sp_res = _run_single_pass_llm(code, lang, func_name)
                elapsed = time.perf_counter() - t0
                vuln_found = bool(sp_res.get("vulnerability_found"))
                reported_cwe = sp_res.get("cwe_id") or ""
                reported_type = sp_res.get("vulnerability_type") or ""
                patched_code = sp_res.get("patched_code")
                exploit_status = "NONE"
                attempts_used = 1
                judge_verdict = "PASS" if patched_code else "NONE"
                pipeline_status = "COMPLETE" if patched_code else "NO_VULN"
            else:
                final_state = run_pipeline(
                    function_id=f"{src_path.name}:{func_name}",
                    code=code,
                    language=lang,
                    risk_score=triage_info["risk_score"],
                    file_path=str(ws_file),
                    repo_root=str(ws_path),
                    start_byte=0,
                    end_byte=len(code.encode("utf-8")),
                    max_attempts=max_attempts,
                )
                elapsed = time.perf_counter() - t0
                vuln_found = bool(final_state.get("vulnerability_found"))
                red_rep = final_state.get("red_report") or {}
                reported_cwe = red_rep.get("cwe_id") or ""
                reported_type = red_rep.get("vulnerability_type") or ""
                patched_code = final_state.get("patched_code")
                exploit_status = final_state.get("exploit_status") or "NONE"
                attempts_used = int(final_state.get("attempt_number", 0)) + (1 if patched_code else 0)
                judge_verdict = final_state.get("judge_verdict") or ""
                pipeline_status = final_state.get("pipeline_status") or ""

            # Snapshot usage log after execution
            usage_after = _read_usage_lines()
            case_usage_records = usage_after[usage_before:]
            case_calls = len(case_usage_records)
            case_in_tok = sum(r.get("input_tokens", 0) for r in case_usage_records)
            case_out_tok = sum(r.get("output_tokens", 0) for r in case_usage_records)
            case_total_tok = sum(r.get("total_tokens", 0) for r in case_usage_records)
            case_cost = sum(r.get("cost_usd", 0.0) for r in case_usage_records)

            patch_generated = bool(patched_code)
            patch_applied = False
            apply_error = None
            syntax_valid = False
            patched_sec_blocked = False
            patched_reg_passed = False

            # Physical Patch Application to Isolated Workspace
            if patch_generated and patched_code:
                try:
                    apply_patch(
                        str(ws_file),
                        start_byte=0,
                        end_byte=len(code.encode("utf-8")),
                        new_code=patched_code,
                        backup_dir=ws_path / "backups",
                    )
                    patch_applied = True
                except Exception as exc:
                    patch_applied = False
                    apply_error = str(exc)

            # Independent Validation of Patched Source
            patched_sec_dict = {}
            patched_reg_dict = {}
            if patch_applied:
                syntax_valid = validate_syntax(ws_file.read_text(encoding="utf-8", errors="replace"), lang)
                p_sec = run_security_test(cid, ws_file)
                p_reg = run_regression_test(cid, ws_file)
                patched_sec_dict = p_sec.to_dict()
                patched_reg_dict = p_reg.to_dict()
                # Exploit blocked means vulnerability is NOT demonstrated on patched file
                patched_sec_blocked = not p_sec.vulnerability_demonstrated
                patched_reg_passed = p_reg.passed

            # Evaluation Accuracies
            cwe_match = False
            if cwe and reported_cwe:
                cwe_match = (cwe.upper() in reported_cwe.upper() or reported_cwe.upper() in cwe.upper())
            loc_correct = vuln_found  # target function level

            # Strict 6-point criteria evaluation
            strict_success = (
                orig_sec.vulnerability_demonstrated
                and patch_generated
                and patch_applied
                and syntax_valid
                and patched_reg_passed
                and patched_sec_blocked
            )

            fail_cat = classify_failure(
                vulnerability_found=vuln_found,
                cwe_match=cwe_match,
                loc_correct=loc_correct,
                patch_generated=patch_generated,
                patch_applied=patch_applied,
                syntax_valid=syntax_valid,
                patched_sec_blocked=patched_sec_blocked,
                patched_reg_passed=patched_reg_passed,
                strict_success=strict_success,
            )

            case_record = {
                "run_id": run_id,
                "case_id": cid,
                "ground_truth": gt,
                "cwe": cwe,
                "language": lang,
                "source_path": case["source_path"],
                "target_function": func_name,
                "triage": triage_info,
                "vulnerability_found": vuln_found,
                "reported_cwe": reported_cwe,
                "reported_type": reported_type,
                "cwe_match": cwe_match,
                "localization_correct": loc_correct,
                "exploit_status": exploit_status,
                "patch_generated": patch_generated,
                "patched_code": patched_code,
                "patch_applied": patch_applied,
                "patch_apply_error": apply_error,
                "patch_syntax_valid": syntax_valid,
                "attempts_used": attempts_used,
                "judge_verdict": judge_verdict,
                "pipeline_status": pipeline_status,
                "strict_repair_success": strict_success,
                "failure_category": fail_cat,
                "original_security_test": orig_sec.to_dict(),
                "original_regression_test": orig_reg.to_dict(),
                "patched_security_test": patched_sec_dict,
                "patched_regression_test": patched_reg_dict,
                "elapsed_seconds": round(elapsed, 3),
                "usage": {
                    "calls": case_calls,
                    "input_tokens": case_in_tok,
                    "output_tokens": case_out_tok,
                    "total_tokens": case_total_tok,
                    "cost_usd": round(case_cost, 6),
                },
            }

            raw_file = raw_dir / f"case_{cid}_trial_001.json"
            raw_file.write_text(json.dumps(case_record, indent=2), encoding="utf-8")
            logger.info("  -> Verdict: strict_success=%s, failure_cat=%s, time=%.2fs, cost=$%.4f",
                        strict_success, fail_cat, elapsed, case_cost)

    # 4. Deterministic Aggregation
    logger.info("Aggregating metrics for run: %s", run_id)
    metrics, table_rows = aggregate_run_metrics(run_dir)
    (run_dir / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    import csv
    if table_rows:
        with (run_dir / "cases.csv").open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(table_rows[0].keys()))
            writer.writeheader()
            writer.writerows(table_rows)

    export_markdown_table(metrics, run_dir / "metrics.md")

    # 5. Publication Charts
    logger.info("Generating publication figures...")
    generate_all_charts(run_dir)

    logger.info("Experiment run complete: %s", run_dir)
    return run_dir


def main() -> int:
    parser = argparse.ArgumentParser(description="VulnGuard Experiment Runner")
    parser.add_argument("--config", type=str, required=True, help="Path to experiment JSON config")
    parser.add_argument("--run-id", type=str, default=None, help="Optional run ID override")
    args = parser.parse_args()

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        print(f"Error: Config not found: {cfg_path}")
        return 1

    run_dir = run_experiment(cfg_path, run_id_override=args.run_id)
    print(f"\nExperiment execution finished successfully.\nOutputs saved in: {run_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

