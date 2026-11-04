# VulnGuard AI — Empirical Evaluation Report

**Run identifier:** `run-2026-10-28T-baseline`
**Report date:** 2026-10-28
**Evaluation type:** Non-invasive, empirical pilot evaluation of the existing implementation (no application changes)
**Evidence directory:** `evaluation/run-2026-10-28T-baseline/`

> Every number in this report is derived from raw evidence in the evidence directory, by the
> scripts in `evaluation/run-2026-10-28T-baseline/procedure/` acting on the records in
> `evaluation/run-2026-10-28T-baseline/cases/`. Nothing here is estimated, projected, or
> illustrative. Metrics that could not be measured are labelled **unavailable** with the reason.

---

## 1. Evaluation objective

Measure, on the implementation as it exists today, what the VulnGuard AI pipeline actually does:
whether the ML triage layer flags known-vulnerable code, whether the Red Agent detects and
characterises the defect, whether it produces an exploit that reproduces on the unpatched code,
whether the Blue Agent's patch can be applied to a workspace, whether the Judge's validation
accepts it, and what it costs in tokens, money and wall-clock time. The evaluation also verifies
the claimed sandbox, retry, and original-repository-preservation behaviour.

No component was redesigned, refactored, repaired, or reconfigured. In particular, the two defects
reported in §13 were **observed and documented, not fixed**, because repair was outside the
authorised scope.

---

## 2. Exact codebase evaluated

| Item | Value |
|---|---|
| Repository root | `C:/Users/singh/OneDrive/Desktop/AI Projects/VulnGuard` |
| Git branch | `main` |
| Commit (HEAD) | `7474c6d34d4d7774f0a029003717dbbc28ad4d7c` ("Use Python 3.12 in CI") |
| Working tree at start | **dirty** — 19 `M` (modified tracked), 2 `D` unstaged deletions (`package.json`, `package-lock.json`), 5,093 `D ` staged deletions (all of `node_modules/`), 11 `R` staged renames (fixtures/sample scripts moved into `samples/`, `scripts/debug/`), 1 `RM`, 11 untracked files (see `00-initial-git-status.txt`) |
| Evaluated code | the **working tree**, i.e. HEAD *plus the pre-existing uncommitted modifications* |
| Evaluation-caused source changes | none (§17) |

The working tree was already dirty before this evaluation began. `vulnguard/agents/*.py`,
`vulnguard/sandbox/patcher.py`, `vulnguard/ui/*.py`, `tests/*.py` and the UI sources were all
modified relative to HEAD, and `vulnguard/agents/llm_calls.py`, `llm_parsing.py`,
`vulnguard/evaluation.py` are untracked. **The measurements describe this working tree, not commit
`7474c6d`.** The full pre-evaluation `git status --porcelain` is preserved verbatim as
`00-initial-git-status.txt` and is used as the baseline for the integrity check in §17.

---

## 3. Environment and tool versions

| Component | Version | Source |
|---|---|---|
| OS / shell | Windows, bash (Git Bash) | `logs/00-env.txt` |
| Python (evaluation interpreter) | 3.12.6 (`./.venv/Scripts/python.exe`) | `logs/00-env.txt` |
| pytest / pluggy | 9.1.1 / 1.7.0 | `logs/02-pytest-docker-marked.log` |
| xgboost / scikit-learn | 3.3.0 / 1.8.0 | `logs/04-doctor.log` |
| Docker engine | 29.1.3 | `docker version` |
| Sandbox image | `vulnguard-sandbox:latest` (present locally; `docker images`) | `logs/04-doctor.log` |
| Node.js / npm | 22.14.0 / 10.9.2 | `node --version` |
| Vitest (via `ui/node_modules`) | 5.0.5 | `logs/03-ui-vitest-retry.log` |
| LLM provider / model | Gemini, routed to `gemini-3.1-pro-preview` (both risk tiers) | `logs/04-doctor.log`, case JSON `usage.models` |
| Triage threshold (deployed) | **30** on the 0–100 scale (`VULNGUARD_RISK_THRESHOLD=30`), model probability threshold `0.49373` | `ml_eval.json` |
| Agent retry budget | `max_attempts = 3` (`VULNGUARD_MAX_RETRIES=3`) | `vulnguard/config.py`, case JSON `max_attempts` |
| LLM temperature | 0.0 (`VULNGUARD_LLM_TEMPERATURE` default) | `vulnguard/config.py` |

A second interpreter exists at `venv/Scripts/python.exe` (Python 3.13.2); it was **not** used. All
Python measurements used `.venv` (3.12.6), matching the documented 3.12 runtime.

---

## 4. Test dataset and fixture inventory

### 4.1 What exists in the repository

| Artifact | Path | Content | Label status |
|---|---|---|---|
| Labeled fixture cohort | `data/test_vulns/*.c`, `data/test_vulns/*.py`, `data/test_vulns/vuln_taint_flow/` | 6 files, **14 parseable functions** | The 6 target functions are declared vulnerable in `vulnguard/evaluation.py::KNOWN_VULN_FUNCTIONS`; the fixtures also carry `// VULNERABILITY:` comments naming the defect |
| Sample sources | `samples/*.py`, `samples/*.c`, `samples/cross_file_test/` | hand-written vulnerable/unlabelled samples | **unlabelled** |
| Trained ML artifact | `vulnguard/models/artifacts/vulnguard_classifier.joblib` (112,119 bytes, dated 2026-09-16) | XGBoost classifier bundle (`{"model", "threshold"}`) | model present |
| Labeled ML dataset / train-test split | — | **absent**; `vulnguard/data/fetch_dataset.py` downloads external HuggingFace datasets, but no local CSV/Parquet/JSONL dataset exists (`find` for `*.csv`/`*.parquet` → none) | no |
| Historic operational records | `data/vulnguard.db` (SQLite, table `scans`, 92 rows) | dashboard scan history 2026-10-25 → 2026-10-26 | labels unknown (see §12) |
| Historic LLM usage log | `data/llm_usage.jsonl` (87 records at start, 123 at end) | per-call tokens/cost/latency | n/a |
| Existing tests | `tests/test_*.py` (12 modules) + `ui/src/components/AgentFeed.test.tsx` | 179 Python tests, 12 UI component tests | n/a |
| Prior evaluation output | `data/benchmarks/` | **empty** — no `evaluation.json` exists, so no prior run is being reused | n/a |

There is **no** labeled negative class, **no** known-good/fixed variants of the fixtures, **no**
per-case exploit fixture, and **no** pre-existing baseline-vs-patched regression pair anywhere in
the repository. This bounds what can be measured (§14).

### 4.2 Unit-of-analysis vocabulary (kept strictly separate)

| Term | Count in this evaluation | Note |
|---|---|---|
| Repositories evaluated | 1 | the labeled fixture cohort `data/test_vulns` of this project |
| Fixture **files** scanned by the agents | 6 | 5 single-function files + 1 three-file package |
| **Functions** parsed from those files | 14 | all six documented targets + 3 C `main`s + 5 helper functions |
| **Unique vulnerability cases** with ground truth | 6 | the `KNOWN_VULN_FUNCTIONS` entries, all labelled vulnerable |
| **Candidate patches** generated | 5 | one per detected case |
| **Repair attempts** executed | 6 | one attempt per case |
| **Repairs retried** | 0 | no case entered the retry loop |
| **Strictly accepted repairs** | 0 | §11 M1a |
| **Judge-accepted repairs** | 1 | C03 |

No repository or LLM-generated hypothesis is re-labelled as a confirmed benchmark case: only the
six functions the implementation itself declares vulnerable are used as positives.

---

## 5. Inclusion and exclusion criteria

**Included**
- Labeled functions listed in `vulnguard/evaluation.py::KNOWN_VULN_FUNCTIONS` (all six).
- Runs executed with the deployed configuration (real Gemini provider, real Docker sandbox, no
  mock mode, no flag overrides except `--max-attempts` left at its default).
- All six attempts are reported, including the failure and the miss. No run was discarded.

**Excluded from the primary metrics (and reported separately)**
- The 92 historic `data/vulnguard.db` rows: produced by earlier sessions against a different
  code state, with no per-attempt records and no ground-truth labels (§12).
- The 8 unlabeled helper functions parsed from the fixture files: they are not labeled positives or
  negatives, so they are used only for triage-selection ratios, never for accuracy.
- `samples/*`: unlabelled; not scored by the agents in this run.
- Repository-level scans (`vulnguard.main scan <dir>`): not executed, because each flagged function
  triggers paid LLM calls; a full-directory scan would exceed the resource budget for this pilot.

---

## 6. Exact commands and working directories

All commands were run from the repository root unless stated. `PY` = `.venv/Scripts/python.exe`.

| # | Command | CWD | Purpose | Log |
|---|---|---|---|---|
| 1 | `git status --porcelain` / `git rev-parse HEAD` / `git branch --show-current` | root | baseline record | `00-initial-git-status.txt`, `00-head.txt` |
| 2 | `$PY -m pytest -q --durations=10` | root | full Python suite | `logs/01-pytest-full.log` |
| 3 | `$PY -m pytest -m docker -v` | root | real-Docker sandbox tests only | `logs/02-pytest-docker-marked.log` |
| 4 | `cd ui && npx vitest run` | `ui/` | UI component tests (as documented) | `logs/03-ui-vitest.log` |
| 5 | `cd ui && npx vitest run --reporter=verbose` | `ui/` | retry of #4 after an infrastructure timeout | `logs/03-ui-vitest-retry.log` |
| 6 | `$PY -m vulnguard.main doctor` | root | live provider + Docker preflight | `logs/04-doctor.log` |
| 7 | `$PY evaluation/.../procedure/run_case.py --case-id C01 ...` | root | live Red→Blue→Judge run, case C01 | `cases/C01.json` |
| 8 | `bash evaluation/.../procedure/run_cases.sh` | root | live runs C02–C06, sequential | `logs/05-cases-runner.log`, `logs/05-cases.log` |
| 9 | `$PY evaluation/.../procedure/ml_eval.py --out <dir>` | root | ML triage, latency, selection ratios | `logs/06-ml-eval.log`, `ml_eval.json` |
| 10 | `$PY evaluation/.../procedure/patch_probe.py --cases ... --out ...` | root | patch syntax + real `apply_patch` attempt | `logs/10-patch-probe.log`, `patch_probe.json` |
| 11 | inline `$PY` probe of `DockerRunner.run_tests` on the fixture repo | root | does the Judge's test step actually run tests? | `logs/11-regression-capability-probe.log` |
| 12 | `$PY evaluation/.../procedure/aggregate.py --dir <dir>` | root | metric aggregation | `logs/12-aggregate.log`, `metrics.json`, `cases.csv` |
| 13 | `$PY -m vulnguard.main usage` | root | provider-side token/cost summary | `logs/13-usage-cli.log` |
| 14 | `cd ui && npx oxlint` ; `npx tsc -b && npx vite build` | `ui/` | lint / typecheck+build | `logs/08-ui-lint.log`, `logs/09-ui-build.log` |

Commands #7, #8, #9 (latency), #10 and #11 use small **evaluation-side driver scripts** kept under
`evaluation/run-2026-10-28T-baseline/procedure/`. They are read-only with respect to the
application: they import the application's own public entry points
(`vulnguard.agents.graph.run_pipeline`, `vulnguard.models.risk_scorer.RiskScorer`,
`vulnguard.sandbox.patcher.apply_patch`, `vulnguard.data.parser.validate_syntax`) and write only
inside the evidence directory (and, for the patch probe, a temp directory that is deleted). No
application file, test file or fixture was created or modified.

---

## 7. Tests actually executed and their outcomes

### 7.1 Python suite (baseline application code)

`$PY -m pytest -q` → **179 passed, 0 failed, 0 skipped, 0 errors, 0 xfail**, exit code 0,
65.44 s (`logs/01-pytest-full.log`).

12 test modules: `test_agents.py`, `test_ui_server.py`, `test_docker_runner.py`,
`test_context_gatherer.py`, `test_feature_extractor.py`, `test_context_extractor.py`,
`test_retriever.py`, `test_risk_scorer.py`, `test_llm_runtime.py`, `test_parser.py`,
`test_model_routing.py`, `test_benchmark_runner.py`. (The modules contain 171 `def test_*`
definitions; the collected total is 179 because of parametrisation.) These exercise the agent nodes against
mocked LLMs, the FastAPI server, the SQLite store, the parser/feature extractor, the retriever, and
the Docker runner.

### 7.2 Docker-marked sandbox tests (real containers)

`$PY -m pytest -m docker -v` → **4 passed**, 0 skipped (i.e. Docker *was* available), 17.46 s:

- `test_sandbox_executes_as_unprivileged_user` — asserts `id -u == 65534` inside the container.
- `test_python_exploit_imports_single_file_target`
- `test_c_exploit_links_target_with_existing_main`
- `test_c_buffer_overflow_is_detected_at_runtime`

Evidence: `logs/02-pytest-docker-marked.log`.

### 7.3 Frontend tests

- First run: `cd ui && npx vitest run` → **1 infrastructure error, 0 tests executed**, exit 1,
  60.07 s: `[vitest-pool-runner]: Timeout waiting for worker to respond`
  (`logs/03-ui-vitest.log`). Reported as a failure, not a pass.
- Immediate retry, same configuration, verbose reporter → **12 passed / 12, exit 0**, 63.98 s
  (`logs/03-ui-vitest-retry.log`). Test file: `ui/src/components/AgentFeed.test.tsx`.

The first-attempt worker timeout is an infrastructure flake on this host, not a test failure: the
identical command passed on retry with no change to any file.

### 7.4 Lint, typecheck, build

`npx oxlint` → 0 warnings, 0 errors (13 files). `npx tsc -b && npx vite build` → exit 0, bundle
`index-*.js` 373.72 kB. Evidence: `logs/08-ui-lint.log`, `logs/09-ui-build.log`.

### 7.5 Live preflight

`$PY -m vulnguard.main doctor` → all seven checks `[OK]` (Python 3.12.6, scikit-learn 1.8.0,
xgboost 3.3.0, Gemini key configured, Gemini routes, **Gemini live request**, Docker sandbox image),
exit 0, 43.6 s. The live request cost was $0.00115 / 100 tokens and is **excluded** from the
per-case cost figures below.

---

## 8. Implementation capability verification (Phase 1 table)

| Capability | Verified implementation | Evidence location | Measurable now? |
|---|---|---|---|
| Candidate patch generation | **Verified** — `blue_agent_node` produces `patched_code` + `patch_diff`; never raises, sets `BLUE_ERROR`/`PATCH_GENERATION_FAILED` on failure | `vulnguard/agents/blue_agent.py`; 5/5 detected cases have `patched_code` in `cases/*.json` | Yes — M12 |
| Temporary patch application | **Partial** — the *Judge* applies patches only **in memory** by byte-splicing the target function into a virtual copy of the file (`judge_agent._get_full_file_code`); no file is written. The repository-apply primitive `patcher.apply_patch` **crashes** (missing `import time`) | `vulnguard/agents/judge_agent.py:130-165`; `vulnguard/sandbox/patcher.py:69`; `patch_probe.json` | Yes — M4; repository-level application is a failure |
| Compilation or syntax checks | **Verified** — `validate_syntax(full_code, language)` in the Judge before any sandbox work; PASS requires it. C/C++ patches are additionally compiled with `-fsanitize=address -fstack-protector-all` inside the container | `vulnguard/agents/judge_agent.py:200-215`; `vulnguard/sandbox/docker_runner.py::run_exploit` | Yes — M13 |
| Baseline exploit execution | **Verified** — Judge step 3a runs the harness against the *unpatched* code and requires the sandbox marker `VULNGUARD_EXECUTION_STARTED` plus either an ASan/crash signature (memory defects) or the `expected_stdout_regex` match | `judge_agent._validate` steps 3a, `_exploit_succeeded`, `_execution_started` | Yes, but only 1 of 6 cases reached it (M2) |
| Patched exploit execution | **Verified** — Judge step 3b re-runs the harness against the patched source, then repeats it a second time (deterministic double-run) | `judge_agent._validate` steps 3b + 4 | Yes (n=1) |
| Existing regression tests | **Partial / structurally absent** — `_run_tests` executes `pytest -x` *only when* `repo_root` is set, and maps "no tests ran" (exit 5) to a pass. The suite is never run on the baseline, so no baseline-vs-patched comparison exists anywhere | `judge_agent._run_tests`; capability probe: `pytest` collects **0 tests**, exit 5 → reported as "skipped" (`logs/11-regression-capability-probe.log`) | **No** — M3 unavailable |
| Retry tracking | **Verified but unused in this run** — `attempt_history` (append-only ledger with `attempt_number`, `patched_code`, `error_logs`, `failure_reason`), `RETRYABLE_VERDICTS` vs `TERMINAL_FAILURE_VERDICTS`, `MAX_RETRIES_EXHAUSTED` | `vulnguard/agents/judge_agent.py:70-100, 400-455`; 0 retries in `cases/*.json`; 0 rows with `attempt_history` in the historic DB | Partially — 0 retried cases (M6 unavailable) |
| Token usage | **Verified** — per-call `input_tokens`, `output_tokens`, `reasoning_tokens`, `total_tokens`, `latency_ms` appended to `data/llm_usage.jsonl`; **not linked to a scan id** and **not persisted in the scan store** | `vulnguard/llm_runtime.py::_record_usage`; `logs/13-usage-cli.log` | Yes, via log-offset attribution (M8) |
| Monetary cost | **Verified (estimated)** — LiteLLM local price map → `estimated_cost_usd` per call | same | Yes — M8 (estimate, not an invoice) |
| Repair latency | **Verified** — `timestamps.pipeline_start/red_end/blue_end/judge_end/pipeline_end` (epoch floats) | `vulnguard/agents/*.py`; every `cases/*.json` | Yes — M7 |
| ML risk scoring | **Verified** — XGBoost artifact loads; `RiskScorer.score()` → 0–100 + `bypass_reason`; language routing, template dampening, mega-function slicing, static-signal floor | `vulnguard/models/risk_scorer.py`; `ml_eval.json` | Yes — M16–M18 |
| Ground-truth ML labels | **Partial** — 6 labeled positives only; **no labeled negatives**, no held-out split | `vulnguard/evaluation.py::KNOWN_VULN_FUNCTIONS` | Positives only; precision/AUC/calibration **unavailable** |
| Original repository preservation | **Verified** — the pipeline never writes to the target file (splicing is in-memory; sandbox receives copies inside a read-only-mounted `/tmp/workspace`); fixture mtimes unchanged (2026-09-16), no `.bak`/backup dirs created, `git status` unchanged | `judge_agent._get_full_file_code`, `docker_runner._run_container` (`mode: ro`, `read_only: True`), §17 | Yes — verified |

---

## 9. Per-case results (raw observations)

All six cases: live Gemini `gemini-3.1-pro-preview`, real `vulnguard-sandbox:latest` container,
`max_attempts=3`, one attempt each, executed sequentially 15:36–15:51 local time on 2026-10-28.
Source of every cell: `cases/C0*.json` → `final_state`, and `patch_probe.json`.

| ID | Fixture : function | Lang | Triage score | Detected | Reported type / CWE | Harness | Patch | Patch syntax | Patch applied | Judge verdict | Attempts | Wall time | Tokens | Cost (USD) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| C01 | `vuln_sqli.py:get_user` | py | 92.2 (`STATIC_SIGNAL:DYNAMIC_SQL`) | yes | SQL_INJECTION / CWE-89 | **invalid** — no `expected_stdout_regex` | yes | valid | **no** (NameError) | `EXPLOIT_INVALID` | 1 | 116.8 s | 10,689 | 0.084498 |
| C02 | `vuln_cmdi.py:ping_host` | py | 80.7 (`SHELL_EXECUTION`) | yes | COMMAND_INJECTION / CWE-78 | **none returned** | yes | valid | **no** (NameError) | `EXPLOIT_INVALID` | 1 | 163.5 s | 18,055 | 0.155800 |
| C03 | `vuln_buffer.c:process_data` | c | 71.3 (`UNBOUNDED_C_API`) | yes | BUFFER_OVERFLOW / CWE-121 | **valid** (`POC_SUCCESS_MARKER`) | yes | valid | **no** (NameError) | **`PASS`** | 1 | 138.6 s | 15,646 | 0.138582 |
| C04 | `vuln_format.c:log_message` | c | 30.0 (`NON_LITERAL_FORMAT_STRING`, floor) | yes | FORMAT_STRING / CWE-134 | **none returned** | yes | valid | **no** (NameError) | `EXPLOIT_INVALID` | 1 | 83.9 s | 8,626 | 0.069742 |
| C05 | `vuln_race.c:write_secure_log` | c | 30.0 (`TOCTOU_FILE_ACCESS`, floor) | yes | TOCTOU / CWE-367 | **none returned** | yes | valid | **no** (NameError) | `EXPLOIT_INVALID` | 1 | 111.4 s | 15,661 | 0.128772 |
| C06 | `vuln_taint_flow/input_handler.py:handle_request` | py | 42.2 (no static signal) | **no** | — | none | none | n/a | n/a | *(none — `RED_COMPLETE`, clean negative)* | 1 | 63.2 s | 6,160 | 0.052620 |

**Totals:** 6 cases, 6 attempts, **0 retries**, 5 detections, 5 patches, 5 syntactically valid
patches, **0 applied**, 1 `PASS`, 4 `EXPLOIT_INVALID`, 1 clean negative.
**35 provider calls, 74,837 tokens, $0.630014**, 677.3 s of pipeline wall time in total.

### 9.1 Case narratives (what actually happened)

- **C03 is the only fully validated repair.** Red produced a C harness that installs
  `SIGSEGV`/`SIGABRT` handlers printing `POC_SUCCESS_MARKER` and passes a 256-byte payload to
  `process_data`; the Judge's baseline pass saw the marker/crash, the patched pass did not, and the
  deterministic double-run agreed. Blue's patch replaces `strcpy(buffer, input)` with
  `strncpy(buffer, input, sizeof(buffer) - 1)` plus explicit NUL termination. This is a genuine
  security-correct outcome, but it is **not** a strict PSR success under this report's definition
  because the patch was never applied to a workspace (§11 M1a).
- **C01** was detected with the correct CWE and a correct, idiomatic parameterised-query patch, but
  the harness produced by the second (harness) model call had no `expected_stdout_regex`; the single
  corrective re-prompt failed identically, so the run terminated as `EXPLOIT_INVALID`. No sandbox
  exploit was ever executed for this case, so its patch was never tested.
- **C02, C04, C05** were detected correctly but the harness call returned **no harness at all**
  ("the model did not provide an exploit harness"). Their patches were therefore never executed.
- **C06 is a false negative** on the cross-file taint-flow cohort: the Red Agent returned no defect
  for `handle_request`, and the pipeline correctly ended as a clean negative
  (`pipeline_status=RED_COMPLETE`, `vulnerability_found=False`, no `judge_verdict`). The dashboard
  path normalises this to `COMPLETE`; it is a *miss*, not a validated negative.

---

## 10. Metric table

Definitions, numerators, denominators and evidence. Machine-readable copy: `metrics.json`;
Markdown copy: `metrics.md`; per-case table: `cases.csv`.

| ID | Metric | Numerator / denominator | Result | Status | Evidence |
|---|---|---|---|---|---|
| **M1a** | Patch Success Rate, strict security-correct, **PSR@1** | 0 / 6 | **0.00 %** | measured | Strict acceptance requires (i) valid baseline exploit, (ii) patch applied to the workspace, (iii) syntax/compile checks, (iv) pre-existing functional tests, (v) exploit neutralised. No case satisfies (ii): `patch_probe.json.applications_succeeded = 0` |
| **M1b** | Patch Success Rate, strict, **PSR@3** | 0 / 6 | **0.00 %** | measured | Identical to M1a because `retry_scheduled = 0` in every case — the retry budget was never exercised |
| **M1c** | Judge-accepted repair rate (weaker, system-reported) | 1 / 6 | **16.67 %** | measured | `cases/C03.json` `judge_verdict = PASS`. Reported separately and **not** relabelled as PSR |
| **M2** | Exploit Blocking Rate, EBR | 1 / 1 | **100 %** (n = 1) | **provisional** | Only C03 produced a valid baseline exploit (`exploit_status=AVAILABLE`, harness + regex present); it was blocked on the patched run. C01/C02/C04/C05 are *ineligible* (no usable harness), C06 had no finding. Inconclusive/infrastructure cases are excluded from the denominator, not counted as blocked |
| **M3** | Regression Rate, RR | 0 / **0** | **unavailable** | unavailable | The Judge never runs the baseline test suite; `pytest -x` on the fixture repo collects 0 tests (exit 5) and is converted to "regression step skipped" (`logs/11-regression-capability-probe.log`). There is no case with a baseline-vs-patched test comparison, so the denominator is genuinely zero |
| **M4** | Application Success Rate, repo-level, ASR | 0 / 5 | **0.00 %** | measured | `patch_probe.json`: all five `apply_patch` calls raise `NameError: name 'time' is not defined` at `vulnguard/sandbox/patcher.py:69`. Application failure is mechanical, not a malformed patch |
| **M5** | Malformed Patch Rate | 0 / 5 | **0.00 %** | measured | Independent `validate_syntax()` on the spliced patched sources: 5/5 pass. No `BUILD_FAILED` verdict was produced |
| **M6** | Retry Recovery Rate | 0 / **0** | **unavailable** | unavailable | 5 first-attempt failures occurred, **0** were retried. Four were terminal evidence verdicts (`EXPLOIT_INVALID`), one was a clean negative; `judge_agent` routes both to END, not back to Blue |
| **M7** | Time-to-Remediation, TTR | — / 6 | median **114.1 s**, mean **112.9 s**, min 63.2 s, max 163.5 s | measured | `cases/*.json` `elapsed_seconds`. Boundary: `pipeline_start` → `pipeline_end`; **excludes** repository ingestion, file parsing and ML triage, **includes** all LLM inference, container execution and the (unused) retry loop |
| **M8a** | Token cost per **Judge-accepted** fix | $0.630014 / 1 | **$0.630014** (74,837 tokens, 35 calls, 6 cases) | measured | Sum of per-case `estimated_cost_usd`; LiteLLM local price map, `gemini-3.1-pro-preview` list price. Includes the cost of the 5 failed/unvalidated attempts |
| **M8b** | Token cost per **strict** security-correct fix | $0.630014 / 0 | **undefined** | unavailable | Denominator is zero |
| **M9** | Vulnerability detection rate (Red Agent) | 5 / 6 | **83.33 %** | measured | `vulnerability_found`; miss = C06 |
| **M10** | Vulnerability category (CWE) accuracy | 5 / 5 | **100 %** | measured | Expected CWE-89/78/121/134/367 from the fixtures' own `VULNERABILITY:` comments; all five reported CWEs match exactly |
| **M11** | Judge acceptance rate (of cases that reached the Judge) | 1 / 5 | **20.00 %** | measured | C06 produced no verdict |
| **M12** | Patch generation rate | 5 / 5 | **100 %** | measured | one patch per detected case |
| **M13** | Syntax/compilation success rate for candidate patches | 5 / 5 | **100 %** | measured | `patch_probe.json` `syntax_valid` |
| **M14** | First-attempt success rate | 1 / 6 | **16.67 %** | measured | `attempt_number = 0` (i.e. attempt 1) in every case |
| **M15** | Unresolved-case rate | 5 / 6 | **83.33 %** | measured | no `PASS` |
| **M16** | ML triage detection on the labeled cohort | 6 / 6 | **100 %** | measured | `ml_eval.json`. Caveat: only **3/6** are above the model's own probability threshold (0.49373); `log_message` (p=0.2543) and `write_secure_log` (p=0.1339) are flagged **only** by the static-signal floor, which equals the deployed threshold of 30 (`ml_raw_probability.json`) |
| **M17** | ML triage selection ratio, unlabeled workload `vulnguard/` | 186 / 249 | **74.70 %** | measured | A *selection* ratio, **not** accuracy — the repository is unlabeled |
| **M18** | Functions prioritized for LLM analysis (fixture cohort) | 11 / 14 | **78.57 %** | measured | `ml_eval.json` `fixture_selection`; the three C `main` functions score 27.0 each and are the three not flagged |

### 10.1 Additional metrics requested by the brief

| Metric | Result | Status |
|---|---|---|
| Vulnerability localization success | `affected_lines` reported for all 5 detections (C01 [8,10], C02 [4,8], C03 [6], C04 [6], C05 [5,15]); each includes the true defect line. **Not** scored as a rate because the fixtures have no machine-readable defect-line annotation | partially measured |
| Vulnerability category / CWE distribution | BUFFER_OVERFLOW 1, FORMAT_STRING 1, TOCTOU 1, SQL_INJECTION 1, COMMAND_INJECTION 1 (5 detected) | measured |
| Retry / unresolved rates | retries 0/6; unresolved 5/6 | measured |
| Repository scan duration | not measured — a directory scan would issue paid LLM calls per flagged function and was out of budget | unavailable |
| ML inference latency per function | steady-state median **2.12–2.77 ms** (three fresh-process runs, 150 samples each); first process run (cold caches) median 5.82 ms; median of run medians 3.25 ms | measured (`ml_latency_summary.json`) |
| Total LLM calls / tokens per repository | 35 calls, 74,837 tokens for the 6-case cohort | measured |
| Cost per attempted repair | $0.630014 / 6 = **$0.105003** | measured |
| Cost per strict fix | undefined (0 strict fixes) | unavailable |
| ML precision / recall / F1 / confusion matrix / ROC-AUC / PR-AUC | **Not measurable** — 6 positives, **0 labeled negatives**, no held-out split, and no stored test partition behind the artifact | unavailable |
| Brier score / ECE | **Not measurable** — needs labeled positives *and* negatives; also the deployed score is `max(model, static floor)` and template-damped, so it is not a calibrated probability | unavailable |
| Top-k vulnerability recall at a review budget | **Not measurable** — 6 positives give no meaningful ranking budget; would be a degenerate 100 % at k ≥ 6 | unavailable |

---

## 11. Retry-level and case-level outcomes

| Case | Attempt 1 outcome | Retry scheduled? | Attempt 2 | Final |
|---|---|---|---|---|
| C01 | `EXPLOIT_INVALID` (harness had no success regex; 1 corrective re-prompt also failed) | **no** — terminal evidence verdict | — | `FAILED` / `EXPLOIT_INVALID` |
| C02 | `EXPLOIT_INVALID` (no harness returned) | no | — | `FAILED` / `EXPLOIT_INVALID` |
| C03 | `PASS` | no (success) | — | `COMPLETE` / `PASS` |
| C04 | `EXPLOIT_INVALID` (no harness returned) | no | — | `FAILED` / `EXPLOIT_INVALID` |
| C05 | `EXPLOIT_INVALID` (no harness returned) | no | — | `FAILED` / `EXPLOIT_INVALID` |
| C06 | clean negative (no defect reported) | no | — | `RED_COMPLETE` / no verdict |

`attempt_history` was empty in all six records, consistent with `pipeline_status` never being
`RETRY`. The three-attempt budget therefore never materialised in this evaluation, and any
PSR@3 / Retry-Recovery claim would be unsupported.

---

## 12. Historic operational records (reported separately, excluded from all metrics)

`data/vulnguard.db` holds 92 scan rows written by earlier dashboard sessions between
2026-10-25T06:42Z and 2026-10-26T11:00Z — i.e. **before** the current working-tree state and with no
ground-truth labels or per-attempt ledger.

| `pipeline_status` | `judge_verdict` | `vulnerability_found` | rows |
|---|---|---|---|
| `ERROR` | *(empty)* | 0 | 45 |
| `COMPLETE` | *(empty — triage-skipped low-risk)* | 0 | 28 |
| `RED_PARSE_ERROR` | *(empty)* | 0 | 8 |
| `COMPLETE` | `PASS` | 1 | **5** |
| `DISCONNECTED` | *(empty)* | 0 | 3 |
| `TRIAGE` | *(empty)* | 0 | 1 |
| `FAILED` | `EXPLOIT_NOT_REPRODUCED` | 1 | 1 |
| `COMPLETE` | `SANDBOX_UNAVAILABLE` | 1 | 1 |

Additional observations from the same table (`historical-db-crosstab.txt`): **0** rows contain an
`attempt_history`; **0** rows contain any token/cost field; timestamp keys are partial
(`red_end` 25, `blue_end` 7, `judge_end` 7, never `pipeline_start`), so historical TTR is not
reconstructable; 25 rows carry a `red_report`, 7 carry a `patched_code`.

These five historic `PASS` rows are **not** evidence about the code evaluated here: they predate the
current uncommitted changes, are not attributable to a specific attempt, and cannot be re-verified.
They are presented only as an observation about the system's operational history.

---

## 13. Defects and anomalies observed (documented, not repaired)

1. **`vulnguard/sandbox/patcher.py` cannot apply any patch.** `apply_patch` calls
   `time.time()` at line 69 but the module imports only `logging` and `pathlib`. Every call raises
   `NameError: name 'time' is not defined` before writing anything (`logs/10-patch-probe.log`).
   Consequences for research claims: repository-level ASR is 0 %; the evaluation writeback path
   (`vulnguard/evaluation.py::run_writeback_pass`) can never succeed; strict PSR is 0 % for a reason
   unrelated to repair quality. `apply_patch` also has a duplicated docstring block; the function
   works only up to the first `time.time()` call.
2. **The Judge's build/test step is vacuous for these fixtures.** `_detect_build_command` returns
   `echo 'No build system detected — skipping build'`; `_detect_test_command` returns
   `python3 -m pytest -x`, which collects 0 tests and exits 5, and `_run_tests` converts that into a
   passing "skipped" signal (`logs/11-regression-capability-probe.log`). For C03 the recorded
   `test_success=True` therefore means *"no tests existed"*, not *"tests passed"*. For C01/C02/C04/C05
   `build_success`/`test_success` are `True` only because the Judge returned before those steps ran —
   they are not measurements.
3. **The Red Agent's harness step is the dominant failure mode in this run.** 4 of 5 detections
   ended with no usable proof of concept (3 × "model did not provide an exploit harness", 1 × missing
   `expected_stdout_regex` that survived the single corrective re-prompt). Because the Judge treats
   these as terminal evidence verdicts, no Blue retry was attempted and the patches were never
   executed.
4. **ML triage "detection" on 2 of 6 positives is driven by a heuristic, not the model.** The
   static-signal floor is `max(score, cfg.triage.risk_threshold)` and the deployed
   `VULNGUARD_RISK_THRESHOLD` is 30, so any static-signal match is auto-flagged at exactly 30.0
   (C04 p=0.2543, C05 p=0.1339). Any claim that the classifier detects these two cases would be
   wrong.
5. **Token/cost is not attributable per scan in the product.** Usage is written to a global
   append-only JSONL with no scan id, and the scan store has no token/cost columns. This evaluation
   attributed usage by log offsets around each run; that mechanism is evaluation-side, not
   application-side.

---

## 14. Execution failures, limitations and missing evidence

| Item | Status | Detail |
|---|---|---|
| UI test run #1 | **failed** | Vitest worker timeout, 0 tests executed, exit 1 (`logs/03-ui-vitest.log`); passed on retry (`logs/03-ui-vitest-retry.log`) |
| Labeled **negatives** | **absent** | No safe/fixed functions with labels exist; precision, F1, AUC, calibration and top-k recall are therefore not measurable |
| Held-out ML test split | **absent** | The artifact ships alone; no train/validation/test partition or the dataset behind it is in the repository |
| Functional regression comparison | **absent by design** | The Judge never runs the baseline suite; see §13.2 |
| Retries | **not exercised** | 0 retries in 6 cases and 0 in the historic DB; PSR@3 and Retry-Recovery are unproven |
| Repository-level patch integration | **not possible** | `apply_patch` raises `NameError`; the pipeline's in-memory splice was exercised, the writeback path was not (running it would have mutated `data/test_vulns`) |
| Repository scan duration / end-to-end repo workload | **not run** | Deliberate budget decision: each flagged function costs a paid LLM round-trip; `vulnguard/` alone yields 186 flagged functions |
| Per-case repeated runs | **not run** | One attempt per case; provider non-determinism means the observed 1/6 PASS is not a stable estimate |
| Sample size | **n = 6** | All from one repository's fixture cohort; no confidence intervals are meaningful |
| Live-provider behaviour | provider warnings present | Gemini emitted `temperature`/`top_p` deprecation warnings and `finish_reason=length` truncations were observed and handled by the escalation code (`max_tokens 1024→2048`) |
| Timing precision | ±clock granularity | Timestamps come from `time.time()` on one host; Docker start-up and container teardown are inside the measured window |

---

## 15. Measured vs calculated vs unavailable

**Directly measured (raw observation in the evidence directory)**
test outcomes (179/4/12, lint, build), per-case verdicts, patches, harness presence, per-case token
counts and cost, per-case wall time, per-function ML scores and latencies, patch syntax validity,
`apply_patch` exceptions, sandbox test outcomes, fixture mtimes.

**Calculated (arithmetic over the above)**
every percentage in §10, total tokens/cost, mean/median TTR, selection ratios, cost per attempted
repair, cost per Judge-accepted fix.

**Unavailable (not measured, not estimated)**
strict PSR numerator > 0; RR; Retry Recovery; precision/recall/F1/AUC/PR-AUC/Brier/ECE/top-k recall for
the ML layer; cost per strict fix; repository-level patch integration; repository scan duration;
historical TTR.

---

## 16. Reproduction instructions

```bash
# 0. Preconditions: repository at the state recorded in 00-head.txt / 00-initial-git-status.txt,
#    .venv (Python 3.12), Docker daemon running with vulnguard-sandbox:latest, GEMINI_API_KEY in .env.
cd "<repo root>"
PY=.venv/Scripts/python.exe

# 1. Baseline record
git rev-parse HEAD; git status --porcelain

# 2. Existing test suites
$PY -m pytest -q --durations=10                 # expect 179 passed
$PY -m pytest -m docker -v                      # expect 4 passed (skipped if Docker is absent)
cd ui && npx vitest run && npx oxlint && npx tsc -b && npx vite build && cd ..

# 3. Live preflight
$PY -m vulnguard.main doctor                    # all checks must print [OK]

# 4. Six live cases (~$0.63 total, ~11 minutes, 35 provider calls)
OUT=evaluation/run-2026-10-28T-baseline
$PY $OUT/procedure/run_case.py --case-id C01 --rel-path data/test_vulns/vuln_sqli.py \
    --function get_user --out $OUT/cases
bash $OUT/procedure/run_cases.sh                # C02..C06, sequential

# 5. Measurements and aggregation
$PY $OUT/procedure/ml_eval.py --out $OUT
$PY $OUT/procedure/patch_probe.py --cases $OUT/cases --out $OUT
$PY $OUT/procedure/aggregate.py --dir $OUT
$PY -m vulnguard.main usage

# 6. Integrity check
git status --porcelain | grep -v node_modules   # must match 00-initial-git-status.txt
```

Notes for a replicator:
- Run the six cases **sequentially**: `data/llm_usage.jsonl` is one append-only file, so concurrent
  runs make per-case cost attribution ambiguous.
- `run_case.py` snapshots the usage-log line count before and after each run and copies only the new
  records into the case evidence; that is how per-case tokens/cost in §9 were obtained.
- Do **not** call `vulnguard.evaluation.run_and_save_evaluation` / `run_labeled_evaluation`: they run
  `run_writeback_pass`, which writes to `data/test_vulns`. This evaluation deliberately avoided them.
- Provider cost figures are LiteLLM's local price-map estimates, not billing statements.

---

## 17. Integrity statement — the evaluation did not change the application

**Verified.** Comparing `git status --porcelain` before and after the evaluation
(`00-initial-git-status.txt` vs the final run, §17.1) shows **no difference in tracked application
files**: the same 19 `M`, 2 `D`, 5,093 `D `, 11 `R`, 1 `RM` entries and the same 11 pre-existing
untracked files are all exactly as they were (the only new untracked paths are the evaluation
directory, this report, and the appended `context.md` section). All of those changes **pre-date this
evaluation** and were preserved, not reverted.

Additional checks:

| Check | Result |
|---|---|
| Tracked application files changed by evaluation | **none** |
| Dependency manifests / lockfiles changed | **none** (`requirements.txt`, `ui/package.json`, `ui/package-lock.json` unchanged; no package installed or upgraded) |
| Configuration / `.env` changed | **none** |
| Datasets / fixtures / model artifact changed | **none** — `data/test_vulns/*` mtimes still 2026-09-16; `vulnguard/models/artifacts/vulnguard_classifier.joblib` untouched; no `.bak` or `.vuln*_backups` created |
| Application data appended by normal operation | `data/llm_usage.jsonl` grew 87 → 123 records and `data/vulnguard.db` may gain rows **only if** the dashboard is used (it was not; row count stayed 92). The usage log is the application's own telemetry, appended by the app itself on every provider call — not an evaluation artifact and not a modification of source, dataset, config or model |
| Generated build artifacts | `ui/dist/`, `ui/tsconfig.tsbuildinfo` — both git-ignored build outputs of the documented `npm run build`; no tracked file affected |
| New files created | only under `evaluation/run-2026-10-28T-baseline/`, plus this `test.md` and the appended section in `context.md` |

No unexpected working-tree change occurred; nothing was reset, cleaned, checked out, stashed, or
committed.

---

## 18. What the observed results do and do not support

**Supported by these measurements (scoped to this fixture cohort and this configuration)**
1. On the six functions the project itself labels vulnerable, the ML triage layer flags **6/6** at
   the deployed threshold of 30 — but only **3/6** on the model's own probability, the other two
   purely through the static-signal floor. ML triage latency is ~2–3 ms/function at steady state.
2. The Red Agent detects **5/6** with **5/5 correct CWE** classification, and the Blue Agent
   generates a syntactically valid patch for **5/5** of the detected cases.
3. Only **1/6** cases reaches a `PASS` verdict; the single `PASS` (C03, buffer overflow) is backed by
   a valid baseline exploit and a patched run that no longer triggers it.
4. Exploit-blocking is **1/1** where a valid baseline exploit existed — a real but single-case
   observation.
5. End-to-end cost is **$0.105** per attempted repair and **$0.630** per Judge-accepted repair, with
   a median 114.1 s per case, 35 provider calls and 74,837 tokens for six cases.
6. The sandbox is real and constrains execution: the 4 Docker-marked tests pass against a live
   daemon, including the unprivileged-user check (`uid 65534`), and the exploit/patched runs happen
   in containers with `network_mode=none`, `read_only=True`, `cap_drop=[ALL]`, `pids_limit=64`,
   `mem_limit=512m`, non-root user, and a read-only bind mount of the host repository.
7. The original target files are never modified by the pipeline: patches are spliced in memory and
   only copies enter the container.
8. The application's own test suite is green (179 Python tests, 12 UI tests) and the UI builds.

**Not supported / must not be claimed**
- Any **strict** patch-success rate above zero, or any PSR@3 / retry-recovery claim: retries never
  ran, and repository-level patch application is broken (`NameError`).
- Any **regression** claim: no baseline test suite is executed for these cases and the Judge
  converts "no tests" into a pass.
- Any **ML accuracy, precision, recall, F1, ROC/PR-AUC, calibration (Brier/ECE) or top-k recall**
  claim: there are no labeled negatives and no held-out data.
- Any claim that the classifier itself detects format-string or TOCTOU defects: those two are flagged
  by the heuristic floor.
- Any claim of **comparative superiority** over SAST or single-LLM baselines: no baseline tool was
  run in this evaluation.
- Any generalisation beyond six functions in one repository with one model: **n = 6, one attempt
  each, no repeated seeds, no confidence intervals**.

**Classification of this evidence (choose the honest label):**
This is a **local functional verification plus an exploratory pilot evaluation** on a small labeled
cohort. It is **not** a labeled benchmark evaluation of a dataset (no dataset, no negatives, no
held-out split) and **not** a comparative research experiment (no baselines, no cross-system
comparison).

---

## 19. Evidence index

| File | Contents |
|---|---|
| `00-head.txt`, `00-initial-git-status.txt` | commit, branch, pre-evaluation working-tree state |
| `logs/00-env.txt` | interpreter and pip versions |
| `logs/01-pytest-full.log` | 179-test run with slowest-10 durations |
| `logs/02-pytest-docker-marked.log` | 4 real-Docker sandbox tests, verbose |
| `logs/03-ui-vitest.log`, `logs/03-ui-vitest-retry.log` | UI test run #1 (worker timeout) and retry (12 passed) |
| `logs/04-doctor.log` | live provider + Docker preflight |
| `cases/C01..C06.json` | full per-case record: final state, red/blue/judge outputs, harness, patch, timestamps, per-run LLM usage records |
| `logs/05-cases.log`, `logs/05-cases-runner.log` | case-runner console transcript |
| `ml_eval.json`, `logs/06-ml-eval.log` | labeled-cohort scores, latency, fixture and repo selection ratios |
| `ml_raw_probability.json`, `logs/07-ml-raw-probability.log` | model probability before the static-signal floor |
| `ml_latency_summary.json`, `logs/06b-ml-latency-run{1,2,3}.log` | three independent latency runs |
| `patch_probe.json`, `logs/10-patch-probe.log` | per-patch syntax validity and real `apply_patch` attempts |
| `logs/11-regression-capability-probe.log` | detected build/test commands and 0-tests-collected result |
| `logs/08-ui-lint.log`, `logs/09-ui-build.log` | lint / typecheck+build |
| `logs/12-aggregate.log`, `metrics.json`, `metrics.md`, `cases.csv` | aggregation and machine-readable metrics |
| `logs/13-usage-cli.log` | `vulnguard usage` provider-side summary |
| `historical-db-summary.json`, `historical-db-crosstab.txt` | 92 historic scan rows (§12) |
| `procedure/run_case.py`, `run_cases.sh`, `ml_eval.py`, `patch_probe.py`, `aggregate.py` | the exact evaluation-side procedures used |

No secrets, API keys, `.env` values or personal paths beyond the project root appear in any artifact.
