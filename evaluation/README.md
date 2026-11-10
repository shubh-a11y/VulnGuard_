# VulnGuard Reproducible Research Evaluation Framework

## 1. Overview and Primary Objective

This evaluation framework provides an evidence-driven, fully reproducible experimental pipeline for evaluating **VulnGuard AI** on automated vulnerability detection, localization, and program repair.

Designed to generate empirical results for IEEE research publication, the framework enforces:
- **Zero Fabrication:** All metrics, tables, and figures are generated programmatically from independently captured runtime evidence. No numbers or charts are hand-crafted or AI-generated.
- **Ground-Truth Isolation:** Target analysis context receives only source code. Evaluation metadata (`manifest.csv`), security tests, and regression assertions are strictly isolated.
- **Strict 6-Point Repair Acceptance:** Candidate patches are accepted as successful if and only if independent dynamic exploit blocking and functional regression verification succeed on the physical workspace.
- **Dual Representation of ML Triage:** Distinct metrics are calculated for the raw XGBoost probabilistic classifier and the deployed policy-augmented triage decisions.
- **Pure Re-computability:** All metrics and publication charts can be completely reconstructed from saved raw JSON evidence without making any LLM provider API calls.

---

## 2. Framework Architecture and Directory Structure

```text
evaluation/
├── dataset/
│   ├── manifest.csv               # Ground-truth metadata (isolated from target analysis context)
│   ├── README.md                  # Dataset documentation, CWE mappings, descriptions
│   ├── harness.py                 # Independent execution engine for security & regression tests
│   ├── vulnerable/                # 15 isolated positive vulnerability fixtures
│   │   ├── sql/                   # CWE-89 (sqli_01.py, sqli_02.py, sqli_03.py)
│   │   ├── command/               # CWE-78 (cmdi_01.py, cmdi_02.py, cmdi_03.py)
│   │   ├── path/                  # CWE-22 (path_01.py, path_02.py, path_03.c)
│   │   ├── memory/                # CWE-120 (mem_01.c, mem_02.c, mem_03.c)
│   │   └── format/                # CWE-134 (fmt_01.c, fmt_02.c, fmt_03.c)
│   ├── safe/                      # 15 isolated safe counter-example fixtures
│   │   ├── sql/                   # CWE-89 (safe_sql_01.py, safe_sql_02.py, safe_sql_03.py)
│   │   ├── command/               # CWE-78 (safe_cmd_01.py, safe_cmd_02.py, safe_cmd_03.py)
│   │   ├── path/                  # CWE-22 (safe_path_01.py, safe_path_02.py, safe_path_03.c)
│   │   ├── memory/                # CWE-120 (safe_mem_01.c, safe_mem_02.c, safe_mem_03.c)
│   │   └── format/                # CWE-134 (safe_fmt_01.c, safe_fmt_02.c, safe_fmt_03.c)
│   └── tests/
│       ├── security/              # test_security_all.py (pytest suite for exploit harnesses)
│       └── regression/            # test_regression_all.py (pytest suite for functional tests)
├── configs/                       # Configurable ablation experiment profiles
│   ├── full_pipeline.json         # Deployed triage + multi-agent + bounded retries (k=3)
│   ├── triage_bypass.json         # Triage bypass ablation
│   ├── single_pass_comparison.json# Single-pass LLM diagnosis and repair baseline
│   └── retry_comparison.json      # First attempt (k=1) ablation
├── runs/                          # Immutable run directories
│   ├── run-2026-10-28T-baseline/  # Historical baseline run (archived and protected)
│   └── <run-id>/                  # Generated experimental runs
│       ├── raw/                   # Per-case raw JSON observation records
│       │   ├── case_B01_trial_001.json
│       │   ├── ml_triage_evaluation.json
│       │   └── ...
│       ├── cases.csv              # Deterministic tabular summary across all cases
│       ├── metrics.json           # All computed metrics with formulas, CIs, and denominators
│       ├── metrics.md             # Publication-ready Markdown table
│       ├── experiment_config.json # Complete snapshot of runtime parameters
│       └── environment.json       # Git SHA, Python, OS, package versions, hardware info
├── plots/
│   └── <run-id>/                  # Programmatically generated publication figures
│       ├── 01_triage_confusion_matrix.png & .pdf
│       ├── 02_cwe_outcomes.png & .pdf
│       ├── 03_cost_and_tokens.png & .pdf
│       ├── 04_psr_comparison.png & .pdf
│       ├── 05_patch_reliability_funnel.png & .pdf
│       ├── 06_time_to_remediation_dist.png & .pdf
│       └── 07_failure_breakdown.png & .pdf
├── scripts/
│   ├── validate_dataset.py        # Validates manifest structure, file existence, and hashes
│   ├── validate_benchmark.py      # Independent ground-truth validation runner
│   ├── evaluate_ml_triage.py      # Pure ML triage evaluation & latency profiling
│   ├── run_experiment.py          # Unified experiment driver for VulnGuard pipeline
│   ├── calculate_metrics.py       # Pure deterministic metric aggregator (no LLM calls)
│   ├── generate_charts.py         # Code-based matplotlib chart generator (PNG + PDF)
│   └── environment_info.py        # Environmental telemetry capture
├── tests/                         # Unit tests verifying the evaluation framework itself
│   └── test_evaluation_framework.py
└── README_AUDIT.md                # Full architectural repository audit report
```

---

## 3. Strict 6-Point Repair Acceptance Criteria

In accordance with Phase 5 of the evaluation specification, a candidate repair is classified as **strictly successful** (`STRICT_REPAIR_SUCCESS`) if and only if **all six** independent criteria are met:

1. **Independent Exploit Confirmation:** The original fixture is independently demonstrated to be vulnerable via its security test harness (`vulnerability_demonstrated == True`).
2. **Patch Generation:** VulnGuard's Blue Agent generates a non-empty replacement code block.
3. **Physical Workspace Application:** The patch is physically applied to the source file in an isolated workspace via `vulnguard.sandbox.patcher.apply_patch` without disk or syntax errors.
4. **Syntax & Build Validation:** The patched source compiles or validates cleanly under `validate_syntax`.
5. **Functional Regression Preservation:** The independent functional regression test passes completely on the patched source (`passed == True`).
6. **Exploit Neutralization:** The same independent security test harness is executed against the patched source and **fails** to demonstrate the flaw (`vulnerability_demonstrated == False`).

A Judge Agent `PASS` verdict alone is insufficient. A patch that blocks an exploit but breaks legitimate behavior is recorded as `REGRESSION_FAILURE`.

### Failure Taxonomy
- `RED_DETECTION_FAILURE`: Red Agent failed to detect vulnerability.
- `INCORRECT_CWE_CLASSIFICATION`: Detected flaw but assigned incorrect CWE ID.
- `INCORRECT_LOCALIZATION`: Flaw localized to wrong function or boundary.
- `BLUE_GENERATION_FAILURE`: Blue Agent produced empty or unparseable output.
- `PATCH_APPLICATION_FAILURE`: Patch failed disk writeback or AST span alignment.
- `BUILD_SYNTAX_FAILURE`: Patched file contains syntax errors or fails compilation.
- `REGRESSION_FAILURE`: Patched file breaks normal functional test cases.
- `EXPLOIT_REMAINS_SUCCESSFUL`: Patched file still reproduces the security vulnerability.
- `TRIAGE_FILTERED`: Filtered out by the ML triage layer prior to deep agent analysis.

---

## 4. Execution Workflow and CLI Reference

### 4.1 Validate Dataset Manifest and Hash Integrity
```bash
python -m evaluation.scripts.validate_dataset
```
Checks:
- Manifest syntax and required columns.
- Source file existence and SHA-256 hash matching.
- Category balances (3 vulnerable, 3 safe per category).
- Absence of ground-truth leakage in source files.

### 4.2 Independently Validate Benchmark Ground Truth
```bash
python -m evaluation.scripts.validate_benchmark
```
Executes independent security and regression tests across all 30 benchmark cases against original implementations. Outputs `evaluation/dataset/validation_summary.json`.

### 4.3 Evaluate ML Triage Layer and Latency
```bash
python -m evaluation.scripts.evaluate_ml_triage --out evaluation/dataset/ml_triage_evaluation.json
```
Computes confusion matrices, precision, recall, specificity, F1-score, and latency distributions for:
- Part A: Raw XGBoost Model (Threshold = 0.494)
- Part B: Deployed Triage Decisions (Threshold = 30 + Static Bypasses)

### 4.4 Run End-to-End Evaluation Experiments
Run full deployed pipeline:
```bash
python -m evaluation.scripts.run_experiment --config evaluation/configs/full_pipeline.json
```
Run triage-bypass ablation:
```bash
python -m evaluation.scripts.run_experiment --config evaluation/configs/triage_bypass.json
```
Run single-pass LLM baseline:
```bash
python -m evaluation.scripts.run_experiment --config evaluation/configs/single_pass_comparison.json
```
Run retry ablation (k=1 vs k=3):
```bash
python -m evaluation.scripts.run_experiment --config evaluation/configs/retry_comparison.json
```

### 4.5 Deterministic Metric Recalculation (Zero API Calls)
```bash
python -m evaluation.scripts.calculate_metrics --run-dir evaluation/runs/<run-id>
```
Reads raw observations in `evaluation/runs/<run-id>/raw/` and independently generates:
- `metrics.json`
- `cases.csv`
- `metrics.md`

### 4.6 Regenerate Publication Figures
```bash
python -m evaluation.scripts.generate_charts --run-dir evaluation/runs/<run-id>
```
Generates 7 dual-format publication figures (300 DPI PNG and vector PDF) under `evaluation/plots/<run-id>/`.

### 4.7 Run the Framework Unit Test Suite
```bash
pytest evaluation/tests/test_evaluation_framework.py -v
```
Runs 15 automated verification tests covering manifest validation, zero-denominator handling, confusion matrix accuracy, synthetic metric verification, chart generation, and historical baseline protection.

---

## 5. Statistical Rigor and Transparency

Every reported metric conforms to the following schema in `metrics.json`:
```json
{
  "formula": "strictly_accepted_repairs_within_3_attempts / eligible_vulnerable_cases",
  "numerator": 12,
  "denominator": 15,
  "value": 80.0,
  "ci_95": [54.81, 92.95],
  "eligible_case_ids": ["B01", "B02", "B03", "..."],
  "status": "measured"
}
```
- All proportions report **Wilson score 95% confidence intervals** (`ci_95`).
- If a denominator is zero, value is reported as `null` and status as `"unavailable"`. Never converted to 0%.
- Latency and token expenditures report mean, median, and 95th percentile dispersion.

