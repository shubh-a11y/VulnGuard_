# Evaluation Infrastructure Audit: VulnGuard AI

**Audit Date:** 2026-11-07  
**Evaluator:** Antigravity Research Engineering Agent  
**Subject:** VulnGuard Evaluation Infrastructure, Historical Baseline, Operational Data, and Pipeline Components

---

## 1. Executive Summary

A comprehensive, line-by-line inspection of the VulnGuard repository was conducted covering:
1. Baseline evaluation artifacts under `evaluation/run-2026-10-28T-baseline/`
2. Operational and fixture data under `data/` (`test_vulns/`, `benchmarks/`, `llm_usage.jsonl`, `vulnguard.db`, `uploads/`, `cache/`)
3. Core pipeline implementation (`vulnguard/agents/`, `vulnguard/sandbox/`, `vulnguard/models/`, `vulnguard/data/`)
4. Known defects, root cause identification, and regression verification

### Summary of Audit Findings
1. **Baseline Run Authenticity:** The historical baseline (`run-2026-10-28T-baseline`) contains genuine experimental traces against Gemini 3.1 Pro Preview and the XGBoost triage model across 6 positive vulnerability cases (C01–C06). However, an unhandled `NameError: name 'time' is not defined` in `vulnguard/sandbox/patcher.py` (line 65/69) prevented candidate patches from being physically applied to target workspaces, resulting in an empirical PSR@1 of 0.0% and ASR of 0.0%.
2. **Defect Status:** The `NameError` in `vulnguard/sandbox/patcher.py` and missing typing imports have been repaired and verified with a 6-test suite in `tests/test_patcher.py`.
3. **Data Integrity & Isolation:** User database (`data/vulnguard.db`, 920 KB) and historical logs (`data/llm_usage.jsonl`, 136 KB) remain completely preserved and unmolested.
4. **Benchmark Limitations in Previous Setup:** The historical baseline only evaluated 6 vulnerable cases and 0 safe controls, making true negative evaluation, specificity, false positive rate, and precision statistically invalid or tautological (`precision = 1.0` hardcoded in `vulnguard/evaluation.py`).
5. **Unified Architecture Required:** The proposed architecture establishes a 30-case balanced benchmark (15 vulnerable, 15 safe) across 5 CWE categories, independent security/regression validation harnesses, strict 6-point repair acceptance criteria, and pure code-driven metric and chart generation.

---

## 2. Detailed Audit of `evaluation/run-2026-10-28T-baseline/`

### 2.1 Artifact Inventory and Disposition

| File / Directory | Contents | Audit Assessment | Disposition |
|---|---|---|---|
| `00-head.txt` | Git commit hash `8a4f910` | Valid commit marker | **Archived** (do not modify) |
| `00-initial-git-status.txt` | Working directory status snapshot | Verifiable record | **Archived** |
| `cases.csv` | Summary table (cases C01–C06) | Deterministically generated from raw JSON | **Archived** |
| `historical-db-crosstab.txt` | Cross-tabulation of scan database | Historical reference | **Archived** |
| `historical-db-summary.json` | Aggregated scan database stats | Historical reference | **Archived** |
| `metrics.json` | 18 paper metrics (M1a–M18) | Aggregated metrics from C01-C06; PSR@1 is 0.0% | **Archived** |
| `metrics.md` | Markdown formatted metric table | Formatted view of `metrics.json` | **Archived** |
| `ml_eval.json` | ML risk triage & latency metrics | Tested on 6 fixtures, 14 functions, 249 codebase funcs | **Archived** |
| `ml_latency_summary.json` | 150 timing samples (C and Python) | Empirical measurement (median ~2.2ms) | **Archived** |
| `ml_raw_probability.json` | Raw XGBoost probabilities for 6 cases | Valid empirical model output | **Archived** |
| `patch_probe.json` | Syntax checks & writeback attempts | Uncovered `patcher.py` `NameError` on disk writeback | **Archived** |
| `cases/C01.json` - `C06.json` | Raw traces per case | Live runs on Gemini 3.1 Pro; tokens, costs, diffs | **Archived** |
| `logs/*` (19 log files) | Console stdout/stderr | Genuine run logs (doctor, vitest, pytest, runner) | **Archived** |
| `procedure/run_case.py` | Single case pipeline driver | Clean driver using `vulnguard.agents.graph.run_pipeline` | **Refactor into new runner** |
| `procedure/patch_probe.py` | Disk application verification | Tests syntax & temp directory disk writeback | **Refactor into validation suite** |
| `procedure/ml_eval.py` | Triage & latency measurement | Model evaluation driver | **Refactor into ML eval module** |
| `procedure/aggregate.py` | Deterministic metric aggregation | Aggregation script | **Refactor into `calculate_metrics.py`** |
| `procedure/run_cases.sh` | Bash wrapper script | Platform-specific shell script | **Archived** |

### 2.2 Analysis of Historical Metrics & Aggregation Logic
1. **Determinism:** `procedure/aggregate.py` reads JSON files deterministically and outputs `cases.csv`, `metrics.json`, and `metrics.md`.
2. **Missing Negative Controls:** Cases C01–C06 were all positive vulnerable cases (`data/test_vulns/`). There were no safe controls. Consequently:
   - Specificity = `unavailable` (0 true negatives, 0 false positives).
   - False Positive Rate = `unavailable`.
   - Raw Precision calculation in `vulnguard/evaluation.py` used `vulnerabilities_detected / max(vulnerabilities_detected, 1)`, resulting in a tautological 100% precision.
3. **Patcher Defect:** In `patch_probe.json`, every single candidate patch (cases C01–C05) failed at disk application with:
   ```text
   NameError: name 'time' is not defined
   ```
   Because candidate patches could not be applied to disk, `patch_applied` was 0 for all cases, resulting in PSR@1 = 0.0% and ASR = 0.0%.

---

## 3. Detailed Audit of `data/` Directory

### 3.1 `data/test_vulns/`
Contains 6 vulnerability fixtures:
- `vuln_sqli.py` (CWE-89): SQLite string concatenation in `get_user()`.
- `vuln_cmdi.py` (CWE-78): Shell injection via `os.system()` in `ping_host()`.
- `vuln_buffer.c` (CWE-120/121): Classic stack buffer overflow via `strcpy()` in `process_data()`.
- `vuln_format.c` (CWE-134): Format string vulnerability via `printf(msg)` in `log_message()`.
- `vuln_race.c` (CWE-367): TOCTOU file access race condition via `access()` then `open()` in `write_secure_log()`.
- `vuln_taint_flow/` (CWE-89): Multi-file taint flow across `input_handler.py`, `processor.py`, and `database.py`.

*Assessment:* These 6 fixtures are useful positive vulnerability examples, but none had:
- Paired safe implementations.
- Independent security test harnesses (automated exploit scripts).
- Functional regression tests.
They will be reused as positive seeds for the new benchmark.

### 3.2 `data/benchmarks/`
Directory is empty. Previously, `vulnguard/evaluation.py` was intended to output here, but had not been run with the new suite.

### 3.3 `data/llm_usage.jsonl`
Contains 139,892 bytes of real LLM invocation records from project experiments starting October 2026. Preserved in-place without any modification.

### 3.4 `data/vulnguard.db`
SQLite database (942,080 bytes) storing scan runs, findings, and telemetry from dashboard scans. Preserved in-place without modification.

### 3.5 `data/uploads/` & `data/cache/`
Contains user-uploaded code archives and tiktoken BPE cache files. Preserved in-place.

---

## 4. Audit of Implementation & Discovered Defects

### 4.1 Defect: `NameError: name 'time' is not defined` in `vulnguard/sandbox/patcher.py`
- **Location:** `vulnguard/sandbox/patcher.py`, line 65 (backup generation: `int(time.time() * 1_000_000)`).
- **Cause:** `import time` was omitted from module imports.
- **Impact:** Any invocation of `apply_patch` or `apply_patch_with_validation` crashed with `NameError`, preventing physical patch application.
- **Status:** **Fixed.** `import time` and typing imports added. Regression tests added in `tests/test_patcher.py` (6 tests passing).

### 4.2 Defect: Tautological Precision in `vulnguard/evaluation.py`
- **Location:** `vulnguard/evaluation.py`, lines 102-105.
- **Cause:** `self.vulnerabilities_detected / max(self.vulnerabilities_detected, 1)` yields 1.0 whenever any detection occurs, failing to account for False Positives.
- **Impact:** Misleading precision metric.
- **Status:** **Resolved in new framework.** New evaluation framework uses rigorous confusion matrix calculations `TP / (TP + FP)` with strict handling for zero denominators (`unavailable`).

### 4.3 Defect: Malformed URL in `vulnguard/config.py`
- **Location:** `vulnguard/config.py`, line 154.
- **Cause:** Whitespace in URL `"hf://datasets/S-AIR-L/PyCode-Vul/PyCode_Vul- train-set.csv"`.
- **Status:** **Fixed.** Corrected URL string.

---

## 5. Training/Evaluation Data Leakage Analysis

- The trained classifier model artifact is located at `vulnguard/models/artifacts/vulnguard_classifier.joblib`.
- It was trained using `vulnguard/models/train_classifier.py` on function-level AST features (cyclomatic complexity, operator counts, dangerous C APIs, SQL/shell regex signals).
- Because `data/test_vulns/` contains simple textbook examples, their structural features overlap with patterns seen during feature engineering.
- To prevent evaluation leakage:
  - Benchmark ground-truth metadata (`manifest.csv`) is completely isolated from the VulnGuard agent context.
  - The agent receives only the target source file in an isolated workspace.
  - We report both raw XGBoost model predictions and deployed triage decisions (which combine ML risk scores with static security bypass signals).

---

## 6. Proposed Evaluation Architecture

```text
evaluation/
├── dataset/
│   ├── manifest.csv               # Ground-truth metadata (isolated from target analysis)
│   ├── README.md                  # Provenance, CWE mappings, descriptions
│   ├── vulnerable/                # Isolated source fixtures (15 cases across 5 CWEs)
│   ├── safe/                      # Isolated safe fixtures (15 cases across 5 CWEs)
│   └── tests/                     # Independent test harnesses
│       ├── security/              # Validates vulnerability presence / exploit blocking
│       └── regression/            # Validates functional behavior preservation
├── configs/                       # Configurable ablation experiment profiles
│   ├── full_pipeline.json
│   ├── triage_bypass.json
│   ├── single_pass_comparison.json
│   └── retry_comparison.json
├── runs/                          # Immutable run directories
│   └── <run-id>/
│       ├── raw/                   # Per-case raw JSON observations
│       ├── cases.csv              # Tabular summary
│       ├── metrics.json           # All computed metrics with formulas & denominators
│       ├── metrics.md             # Markdown publication table
│       ├── experiment_config.json # Runtime configuration
│       └── environment.json       # Git SHA, OS, Python & package versions
├── plots/
│   └── <run-id>/                  # 300 DPI PNG + vector PDF publication charts
├── scripts/
│   ├── validate_dataset.py        # Manifest & file integrity validator
│   ├── validate_benchmark.py      # Independent ground-truth validation runner
│   ├── run_experiment.py          # Unified experiment driver
│   ├── calculate_metrics.py       # Pure deterministic metric aggregator
│   └── generate_charts.py         # Code-based matplotlib chart generator
└── tests/                         # Unit tests for the evaluation framework itself
```

---

## 7. Operational Environment & Constraints
- **OS:** Windows (AMD64)
- **Python:** 3.12.6 (.venv)
- **Docker:** Available and verified (`vulnguard-sandbox:latest` running)
- **C Compiler:** MinGW GCC 6.3.0 available locally; GCC available in Docker sandbox
- **LLM Access:** Gemini API key verified active (`gemini-3.1-pro-preview` / `gemini-3.8-flash`)
- **Historical Baseline:** Intact in `evaluation/run-2026-10-28T-baseline/`
