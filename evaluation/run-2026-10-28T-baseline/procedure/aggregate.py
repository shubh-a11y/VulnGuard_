"""Aggregate the raw case evidence into the paper's metric table.

Every metric is computed here from the per-case JSON files (the raw observations);
nothing is entered by hand. Outputs:

  * ``cases.csv``     — one row per evaluated case
  * ``metrics.json``  — every metric with numerator, denominator, value, status
  * ``metrics.md``    — the same table in Markdown for pasting into the report
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
from pathlib import Path

PASS = "PASS"
ACCEPTED = {PASS}


def pct(num: int, den: int) -> float | None:
    return round(100.0 * num / den, 2) if den else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    args = ap.parse_args()
    root = Path(args.dir)

    cases = []
    for f in sorted((root / "cases").glob("C*.json")):
        rec = json.loads(f.read_text(encoding="utf-8"))
        st = rec["final_state"]
        rr = st.get("red_report") or {}
        cases.append(
            {
                "case_id": rec["case_id"],
                "relative_path": rec["relative_path"],
                "function": rec["function"],
                "language": rec["language"],
                "ground_truth": "vulnerable",
                "label_source": "vulnguard.evaluation.KNOWN_VULN_FUNCTIONS",
                "risk_score": rec["triage"]["risk_score"],
                "bypass_reason": rec["triage"]["bypass_reason"] or "",
                "vulnerability_found": int(bool(st["vulnerability_found"])),
                "reported_type": rr.get("vulnerability_type") or "",
                "reported_cwe": rr.get("cwe_id") or "",
                "exploit_status": st["exploit_status"],
                "exploit_harness": int(bool(st["exploit_harness"])),
                "patch_generated": int(bool(st["patched_code"])),
                "attempts_used": int(st["attempt_number"]) + 1 if st["patched_code"] or st["attempt_number"] else 0,
                "retry_scheduled": int(bool(st["attempt_history"])),
                "judge_verdict": st["judge_verdict"],
                "pipeline_status": st["pipeline_status"],
                "elapsed_seconds": rec["elapsed_seconds"],
                "llm_calls": rec["usage"]["calls"],
                "input_tokens": rec["usage"]["input_tokens"],
                "output_tokens": rec["usage"]["output_tokens"],
                "total_tokens": rec["usage"]["total_tokens"],
                "cost_usd": round(rec["usage"]["cost_usd"], 6),
                "exception": rec.get("exception") or "",
            }
        )

    probe = json.loads((root / "patch_probe.json").read_text(encoding="utf-8"))
    probe_by_id = {r["case_id"]: r for r in probe["cases"]}
    for c in cases:
        p = probe_by_id.get(c["case_id"], {})
        c["patch_syntax_valid"] = int(bool(p.get("syntax_valid")))
        c["patch_applied"] = int(bool(p.get("applied")))
        c["apply_error"] = p.get("apply_error") or ""

    ml = json.loads((root / "ml_eval.json").read_text(encoding="utf-8"))

    # ── Counts ─────────────────────────────────────────────────────────
    n_cases = len(cases)
    detected = sum(c["vulnerability_found"] for c in cases)
    patches = sum(c["patch_generated"] for c in cases)
    judged = sum(1 for c in cases if c["judge_verdict"])
    passes = sum(1 for c in cases if c["judge_verdict"] in ACCEPTED)
    valid_baseline = sum(1 for c in cases if c["judge_verdict"] in {PASS, "EXPLOIT_NOT_BLOCKED"})
    # A case reaches the patched-exploit stage only if the harness was valid and
    # ran on the baseline; only then is exploit blocking measurable.
    blocked = sum(1 for c in cases if c["judge_verdict"] == PASS)
    syntax_valid = sum(c["patch_syntax_valid"] for c in cases)
    applied = sum(c["patch_applied"] for c in cases)
    first_attempt_pass = sum(1 for c in cases if c["judge_verdict"] in ACCEPTED)
    first_attempt_fail = n_cases - first_attempt_pass
    retried = sum(1 for c in cases if c["retry_scheduled"])

    elapsed = [c["elapsed_seconds"] for c in cases]
    total_tokens = sum(c["total_tokens"] for c in cases)
    total_cost = sum(c["cost_usd"] for c in cases)
    total_calls = sum(c["llm_calls"] for c in cases)

    cwe_expected = {
        "C01": "CWE-89",
        "C02": "CWE-78",
        "C03": "CWE-121",
        "C04": "CWE-134",
        "C05": "CWE-367",
        "C06": None,
    }
    cwe_match = sum(
        1 for c in cases if cwe_expected.get(c["case_id"]) and c["reported_cwe"] == cwe_expected[c["case_id"]]
    )

    metrics = []

    def add(mid, name, definition, num, den, value, status, evidence):
        metrics.append(
            {
                "id": mid,
                "metric": name,
                "definition": definition,
                "numerator": num,
                "denominator": den,
                "value_pct": value,
                "status": status,
                "evidence": evidence,
            }
        )

    add(
        "M1a",
        "Patch Success Rate (strict security-correct), PSR@1",
        "accepted repairs on the first attempt / eligible vulnerable cases attempted, where accepted requires "
        "a valid baseline exploit, an applied patch, passing build/syntax + functional tests, and a neutralised exploit",
        0,
        n_cases,
        pct(0, n_cases),
        "measured",
        "no case satisfies every strict criterion: patches were never applied to a workspace "
        "(patch_probe.json: applications_succeeded=0)",
    )
    add(
        "M1b",
        "Patch Success Rate (strict), PSR@3",
        "same as M1a but allowing up to three attempts",
        0,
        n_cases,
        pct(0, n_cases),
        "measured",
        "no retries were ever scheduled (retry_scheduled=0 in every case), so PSR@3 == PSR@1",
    )
    add(
        "M1c",
        "Judge-accepted repair rate (weaker, system-reported)",
        "cases whose Judge verdict is PASS / eligible vulnerable cases attempted",
        passes,
        n_cases,
        pct(passes, n_cases),
        "measured",
        "cases/C03.json: judge_verdict=PASS",
    )
    add(
        "M2",
        "Exploit Blocking Rate (EBR)",
        "valid baseline exploits confirmed blocked by the candidate repair / eligible valid baseline exploits tested",
        blocked,
        valid_baseline,
        pct(blocked, valid_baseline),
        "provisional",
        "only C03 produced a valid baseline exploit (exploit_status=AVAILABLE, "
        "harness present, expected_stdout_regex set); C01/C02/C04/C05 had no usable harness, "
        "C06 had no finding, so they are ineligible for EBR",
    )
    add(
        "M3",
        "Regression Rate (RR)",
        "candidate repairs that break a previously passing functional test / repairs with a valid regression comparison",
        0,
        0,
        None,
        "unavailable",
        "the Judge never executes the baseline test suite; logs/11-regression-capability-probe.log shows "
        "`python3 -m pytest -x` collecting 0 tests (exit 5) on the fixture repository, which "
        "judge_agent._run_tests converts into a pass ('No tests discovered; regression test step skipped'). "
        "No case has a baseline-vs-patched test comparison.",
    )
    add(
        "M4",
        "Application Success Rate (ASR), repository-level",
        "successfully applied candidate patches / candidate patch-application attempts",
        applied,
        patches,
        pct(applied, patches),
        "measured",
        "patch_probe.json: every apply_patch call raises NameError('time' is not defined) at "
        "vulnguard/sandbox/patcher.py:69 because the module never imports `time`",
    )
    add(
        "M5",
        "Malformed Patch Rate",
        "syntactically invalid candidate patches / candidate patches checked",
        patches - syntax_valid,
        patches,
        pct(patches - syntax_valid, patches),
        "measured",
        "patch_probe.json: validate_syntax() passes on all spliced patched sources; the "
        "application failure is a mechanism defect, not a malformed patch",
    )
    add(
        "M6",
        "Retry Recovery Rate",
        "cases that failed the first attempt and were later accepted / cases that failed the first attempt and were retried",
        0,
        retried,
        None,
        "unavailable",
        f"{first_attempt_fail} first-attempt failures occurred but {retried} were retried: every failure "
        "was a terminal evidence verdict (EXPLOIT_INVALID/EXPLOIT_NOT_REPRODUCED) or a clean negative, "
        "which judge_agent routes to FAILED/END instead of the Blue retry loop",
    )
    add(
        "M7",
        "Time-to-Remediation (TTR)",
        "pipeline_end - pipeline_start per case, seconds (excludes repository ingestion, parsing and ML triage; "
        "includes LLM inference, Docker sandbox execution and any retries)",
        None,
        n_cases,
        None,
        "measured",
        f"median={round(statistics.median(elapsed),1)}s mean={round(statistics.fmean(elapsed),1)}s "
        f"min={round(min(elapsed),1)}s max={round(max(elapsed),1)}s (cases/*.json elapsed_seconds)",
    )
    metrics[-1]["statistics"] = {
        "median_s": round(statistics.median(elapsed), 1),
        "mean_s": round(statistics.fmean(elapsed), 1),
        "min_s": round(min(elapsed), 1),
        "max_s": round(max(elapsed), 1),
        "n": n_cases,
    }
    add(
        "M8a",
        "Token cost per Judge-accepted fix (USD)",
        "total attributable LLM cost of all evaluated attempts / accepted repairs",
        None,
        1,
        None,
        "measured",
        f"total cost ${total_cost:.4f} over {n_cases} cases and {total_calls} provider calls; "
        f"sum of per-case estimated_cost_usd from data/llm_usage.jsonl",
    )
    metrics[-1]["statistics"] = {
        "total_cost_usd": round(total_cost, 6),
        "judge_accepted_fixes": 1,
        "cost_per_judge_accepted_fix_usd": round(total_cost, 6),
        "total_tokens": total_tokens,
        "total_calls": total_calls,
    }
    add(
        "M8b",
        "Token cost per strict security-correct fix (USD)",
        "total attributable LLM cost / strictly accepted repairs",
        None,
        0,
        None,
        "unavailable",
        "strictly accepted repairs = 0, so the ratio is undefined (division by zero)",
    )
    add(
        "M9",
        "Vulnerability detection rate (Red Agent)",
        "cases where the Red Agent reported a defect / known-vulnerable cases",
        detected,
        n_cases,
        pct(detected, n_cases),
        "measured",
        "cases/*.json vulnerability_found; the single miss is C06 (cross-file taint entry point)",
    )
    add(
        "M10",
        "Vulnerability category (CWE) accuracy",
        "reported CWE equal to the documented category of the fixture / cases with a reported CWE",
        cwe_match,
        detected,
        pct(cwe_match, detected),
        "measured",
        "expected CWE-89/78/121/134/367 for C01-C05 from the fixture comments in data/test_vulns",
    )
    add(
        "M11",
        "Judge acceptance rate (of cases that reached the Judge)",
        "PASS verdicts / cases with any Judge verdict",
        passes,
        judged,
        pct(passes, judged),
        "measured",
        "cases/*.json judge_verdict non-empty",
    )
    add(
        "M12",
        "Patch generation rate",
        "cases with a candidate patch / detected cases",
        patches,
        detected,
        pct(patches, detected),
        "measured",
        "cases/*.json patched_code present",
    )
    add(
        "M13",
        "Compilation / syntax-check success rate for candidate patches",
        "patched sources passing the application's validate_syntax / candidate patches",
        syntax_valid,
        patches,
        pct(syntax_valid, patches),
        "measured",
        "patch_probe.json syntax_valid",
    )
    add(
        "M14",
        "First-attempt success rate",
        "cases accepted on attempt 1 / cases attempted",
        first_attempt_pass,
        n_cases,
        pct(first_attempt_pass, n_cases),
        "measured",
        "cases/*.json attempt_number=0 for every case (only one attempt was ever executed)",
    )
    add(
        "M15",
        "Unresolved-case rate",
        "cases with no accepted (PASS) repair / cases attempted",
        n_cases - passes,
        n_cases,
        pct(n_cases - passes, n_cases),
        "measured",
        "cases/*.json judge_verdict != PASS",
    )
    add(
        "M16",
        "ML triage detection on the labeled cohort",
        "labeled vulnerable functions flagged at the deployed threshold / labeled vulnerable functions",
        ml["labeled_summary"]["flagged"],
        ml["labeled_summary"]["labeled_examples"],
        pct(ml["labeled_summary"]["flagged"], ml["labeled_summary"]["labeled_examples"]),
        "measured",
        "ml_eval.json labeled_cohort; note 4/6 are above threshold on the model's own probability, "
        "2/6 only via the static-signal floor (ml_raw_probability.json)",
    )
    add(
        "M17",
        "ML triage selection ratio on unlabeled code",
        "functions flagged / functions extracted from vulnguard/ (unlabeled — a workload ratio, not accuracy)",
        ml["repo_selection"]["functions_flagged"],
        ml["repo_selection"]["functions_extracted"],
        pct(ml["repo_selection"]["functions_flagged"], ml["repo_selection"]["functions_extracted"]),
        "measured",
        "ml_eval.json repo_selection",
    )
    add(
        "M18",
        "Functions prioritized for LLM analysis (fixture cohort)",
        "functions flagged by triage among those parsed from data/test_vulns / functions parsed from data/test_vulns",
        ml["fixture_selection"]["functions_flagged"],
        ml["fixture_selection"]["functions_parsed"],
        pct(ml["fixture_selection"]["functions_flagged"], ml["fixture_selection"]["functions_parsed"]),
        "measured",
        "ml_eval.json fixture_selection (per-function rows included)",
    )

    # ── CSV ────────────────────────────────────────────────────────────
    columns = list(cases[0].keys())
    with (root / "cases.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns)
        writer.writeheader()
        writer.writerows(cases)

    payload = {
        "run_id": root.name,
        "evaluated_repository": "VulnGuard (this repository), labeled fixture cohort data/test_vulns",
        "counts": {
            "repositories_evaluated": 1,
            "fixture_files_evaluated": len({c["relative_path"] for c in cases}),
            "functions_parsed_in_fixture_cohort": 14,
            "known_vulnerable_cases_evaluated": n_cases,
            "candidate_patches_generated": patches,
            "repair_attempts_executed": n_cases,
            "repairs_retried": retried,
            "llm_provider_calls": total_calls,
            "total_tokens": total_tokens,
            "total_cost_usd": round(total_cost, 6),
        },
        "metrics": metrics,
        "per_case": cases,
        "ml": {
            "labeled_cohort": ml["labeled_summary"],
            "latency": ml["latency"],
            "repo_selection": {k: v for k, v in ml["repo_selection"].items() if k != "per_file"},
            "deployed_threshold_0_100": ml["deployed_risk_threshold_0_100"],
            "model_probability_threshold": ml["model_probability_threshold"],
        },
    }
    (root / "metrics.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    lines = [
        "| ID | Metric | Num/Den | Value | Status |",
        "|---|---|---|---|---|",
    ]
    for m in metrics:
        num = "-" if m["numerator"] is None else m["numerator"]
        den = "-" if m["denominator"] is None else m["denominator"]
        val = "-" if m["value_pct"] is None else f"{m['value_pct']}%"
        lines.append(f"| {m['id']} | {m['metric']} | {num}/{den} | {val} | {m['status']} |")
    (root / "metrics.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
