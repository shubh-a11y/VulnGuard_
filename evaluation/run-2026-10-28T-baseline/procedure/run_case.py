"""External measurement driver for the VulnGuard evaluation (evaluation-side only).

This is NOT part of the application and is not imported by it. It calls the
application's existing public entry point ``vulnguard.agents.graph.run_pipeline``
(the same function the FastAPI/WebSocket dashboard calls) for one fixture case
and serialises the returned final state to JSON inside the evaluation evidence
directory.

It performs no writes to application source, fixtures, or datasets: the pipeline
splices patches in memory only, and the repository-apply path
(``vulnguard.sandbox.patcher``) is never invoked here.

Usage:
    python evaluation/run-2026-10-28T-baseline/procedure/run_case.py \
        --case-id C01 --rel-path data/test_vulns/vuln_sqli.py \
        --function get_user --out evaluation/run-2026-10-28T-baseline/cases

Token/cost attribution: the application appends one JSON record per provider
call to ``data/llm_usage.jsonl``. This driver snapshots the number of lines
before and after the run and copies only the records added by that run into the
case evidence, so usage can be attributed per case.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from vulnguard.agents.graph import run_pipeline  # noqa: E402
from vulnguard.data.parser import detect_language, parse_file, read_source_file  # noqa: E402
from vulnguard.models.risk_scorer import RiskScorer  # noqa: E402

USAGE_LOG = PROJECT_ROOT / "data" / "llm_usage.jsonl"

SERIALISED_KEYS = [
    "function_id",
    "language",
    "risk_score",
    "file_path",
    "repo_root",
    "start_byte",
    "end_byte",
    "red_report",
    "vulnerability_found",
    "exploit_status",
    "exploit_error",
    "exploit_harness",
    "exploit_type",
    "expected_stdout_regex",
    "patched_code",
    "patch_justification",
    "patch_diff",
    "build_success",
    "test_success",
    "exploit_blocked",
    "judge_verdict",
    "error_logs",
    "attempt_number",
    "attempt_history",
    "max_attempts",
    "pipeline_status",
    "timestamps",
]


def _usage_count() -> int:
    if not USAGE_LOG.exists():
        return 0
    with USAGE_LOG.open("r", encoding="utf-8", errors="replace") as handle:
        return sum(1 for _ in handle)


def _usage_since(offset: int) -> list[dict]:
    records: list[dict] = []
    if not USAGE_LOG.exists():
        return records
    with USAGE_LOG.open("r", encoding="utf-8", errors="replace") as handle:
        for index, line in enumerate(handle):
            if index < offset:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--rel-path", required=True)
    parser.add_argument("--function", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--max-attempts", type=int, default=3)
    args = parser.parse_args()

    rel_path = Path(args.rel_path)
    file_path = (PROJECT_ROOT / rel_path).resolve()
    language = detect_language(file_path)
    if not language:
        print(f"unsupported source file: {file_path}", file=sys.stderr)
        return 2

    source = read_source_file(file_path)
    chunks = parse_file(str(file_path), source, language)
    chunk = next((c for c in chunks if c.function_name == args.function), None)
    if chunk is None:
        print(
            f"function {args.function!r} not found in {rel_path}; "
            f"available={[c.function_name for c in chunks]}",
            file=sys.stderr,
        )
        return 3

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Triage the way `vulnguard.main.cmd_scan` does, so the recorded risk score
    # and model routing match the deployed CLI path.
    risk = RiskScorer().score(chunk.raw_source, language)

    usage_offset = _usage_count()
    started_wall = time.time()
    started = time.perf_counter()
    error = None
    final_state: dict = {}
    try:
        final_state = run_pipeline(
            function_id=f"{rel_path.as_posix()}:{chunk.function_name}",
            code=chunk.raw_source,
            language=language,
            risk_score=risk.risk_score,
            context_bundle={},
            file_path=str(file_path),
            repo_root=str(file_path.parent),
            start_byte=chunk.start_byte,
            end_byte=chunk.end_byte,
            max_attempts=args.max_attempts,
        )
    except Exception as exc:  # a crash is itself an observation
        error = f"{type(exc).__name__}: {exc}"
    elapsed = time.perf_counter() - started
    finished_wall = time.time()
    usage_records = _usage_since(usage_offset)

    record = {
        "case_id": args.case_id,
        "relative_path": rel_path.as_posix(),
        "function": chunk.function_name,
        "language": language,
        "triage": {
            "risk_score": risk.risk_score,
            "bypass_reason": risk.bypass_reason,
            "parse_errors": risk.parse_errors,
        },
        "start_byte": chunk.start_byte,
        "end_byte": chunk.end_byte,
        "started_wall": started_wall,
        "finished_wall": finished_wall,
        "elapsed_seconds": round(elapsed, 3),
        "exception": error,
        "usage": {
            "calls": len(usage_records),
            "input_tokens": sum(int(r.get("input_tokens") or 0) for r in usage_records),
            "output_tokens": sum(int(r.get("output_tokens") or 0) for r in usage_records),
            "total_tokens": sum(int(r.get("total_tokens") or 0) for r in usage_records),
            "cost_usd": sum(float(r.get("estimated_cost_usd") or 0.0) for r in usage_records),
            "models": sorted({str(r.get("model")) for r in usage_records}),
            "records": usage_records,
        },
        "final_state": {k: final_state.get(k) for k in SERIALISED_KEYS},
    }

    out_file = out_dir / f"{args.case_id}.json"
    out_file.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")

    print(
        f"{args.case_id} {rel_path.as_posix()}:{chunk.function_name} "
        f"status={record['final_state'].get('pipeline_status')!r} "
        f"verdict={record['final_state'].get('judge_verdict')!r} "
        f"found={record['final_state'].get('vulnerability_found')} "
        f"attempts={record['final_state'].get('attempt_number')} "
        f"calls={record['usage']['calls']} tokens={record['usage']['total_tokens']} "
        f"cost=${record['usage']['cost_usd']:.6f} elapsed={elapsed:.1f}s "
        f"error={error}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
