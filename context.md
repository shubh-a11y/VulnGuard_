# VulnGuard — Project Context

Project root: `C:/Users/singh/OneDrive/Desktop/AI Projects/VulnGuard`
Language/runtime: Python 3.12, Node.js (npm), React + Vite + TypeScript UI, LangGraph (LangChain) agent graph, FastAPI backend, SQLite store, RQ background worker, Docker sandbox for exploit validation, Gemini LLM for agents, matplotlib for paper figures.
Docs: `README.md`, `project_description.md`. `skills-lock.json`, `.agrules`, `promptfooconfig.yaml` are tooling artifacts.

---

## 1. Layout (top level)

| Path | Purpose |
|---|---|
| `vulnguard/` | Python package: agents, sandbox, models, data, benchmarks, API, config, main entry |
| `vulnguard/ui/` | FastAPI backend (`server.py`, `app.py`, `store.py`, `__init__.py`) + React/TypeScript dashboard (`src/`) + build config (`vite.config.ts`, `package.json`) |
| `ui/src/` | Dashboard React app: `App.tsx`, `components/`, `lib/utils.ts`, `index.css`, `vite-env.d.ts` |
| `data/` | Labeled test vulns (`test_vulns/`), uploads (`uploads/`), SQLite DB (`vulnguard.db*`), LLM usage log (`llm_usage.jsonl`), benchmark artifacts (`benchmarks/`) |
| `samples/` | Sample vulnerable/non-vulnerable targets + test patch/vuln files |
| `scripts/` | Debug and helper scripts (`train_classifier.py` etc.) |
| `tests/` | pytest suite (137 tests): server, agents, benchmarks, data, models, LLM runtime |
| `requirements.txt`, `requirements-dev.txt` (implied) | Python deps; `package.json` in `ui/` for the frontend |

---

## 2. Python package: `vulnguard/`

### 2.1 Entry & CLI: `main.py`
- `python -m vulnguard.main <command>` with subcommands: `doctor` (prereq check), `scan` (single file/repo), `benchmark` (SAST vs single-LLM vs VulnGuard, `--output-dir`, default `data/benchmarks`), `dashboard` (Streamlit or FastAPI backend), `usage` (LLM token/cost summary), `worker` (RQ worker).
- `scan` internal path: reads target file(s) → `_function_payloads` → per-function `run_pipeline` (uses `run_pipeline` from `vulnguard.agents.graph`) → saves result into SQLite store → POSTs progress/partial results over a channel to the worker.
- `benchmark` calls `vulnguard.benchmarks.runner.benchmark_repository` (SAST `static_analyzer`, single LLM `single_llm`, and the full VulnGuard pipeline), writes JSON summary + labeled PNG figures into `data/benchmarks`.

### 2.2 Config: `config.py`
- `TriageConfig` (model names, thresholds), `LLMConfig` (Gemini provider, usage tracking), `ModelRoutingConfig`, `AgentConfig` (max retries), `SandboxConfig` (Docker image, paths). Defaults + env overrides in `.env` (see `.env.example`).
- `LLMConfig` knobs: `VULNGUARD_LLM_TEMPERATURE` (default 0.0 for determinism), `VULNGUARD_LLM_MAX_TOKENS` (base budget 4096), `VULNGUARD_LLM_MAX_TOKEN_CEILING` (escalation cap, 16384), `VULNGUARD_LLM_TIMEOUT` (120s per request), `VULNGUARD_LLM_MAX_RETRIES` (3 total provider calls per generation step), `VULNGUARD_LLM_RETRY_DELAY` (2s base backoff).
- Gemini 3 notes: reasoning-aware models can exhaust the output budget before JSON completes (finish_reason=length). The Red Agent therefore generates the diagnosis and the proof of concept in separate calls, so a long harness can no longer consume the diagnosis budget.

### 2.3 State & agents graph: `agents/`
- `state.py` — `VulnGuardState` (TypedDict) with keys `function_id`, `code`, `language`, `risk_score`, `context_bundle`, `file_path`, `repo_root`, `start_byte`, `end_byte`, `max_attempts`, `attempt_number`, `scan_id`, `timestamps`, `red_report`, `blue_report`, `judge_report`, `patch`, `executed_patch`, `vulnerability_found`, `judge_verdict`, `pipeline_status`, `error_logs`, `rich_output`, `metrics`, `feature_vector`, `embedding`, `retriever_top_k`, `retriever_scores`, `local_context`, `final_report`, etc.
- `red_agent.py` — `red_agent_node`: two bounded model calls. (1) `RedAgentDiagnosis` (compact JSON: type/CWE/severity/short explanation); (2) `RedAgentHarness` (minimal PoC) only when a defect is diagnosed. Both merge into `RedAgentReport` (the single shape consumed downstream). A failed/truncated harness preserves the diagnosis and sets `exploit_status=INVALID|UNAVAILABLE` with `exploit_error`. Never raises: all failures become `RED_ERROR` state.
- `blue_agent.py` — parse/retry with `BLUE_ERROR` + `PATCH_GENERATION_FAILED` on exhaustion; never raises.
- `llm_parsing.py` — shared response handling: `strip_code_fences`, `parse_agent_json(raw, schema)` (returns `(instance, failure_reason)`, never a default negative), `unwrap_schema_payload`, `is_truncated_response`/`finish_reason`, `raw_response_preview` (log-safe 400-char previews).
- `llm_calls.py` — shared bounded invocation (`call_llm_json`) used by Red and Blue: doubles `max_tokens` on truncation up to `cfg.llm.max_token_ceiling` and stops immediately at the ceiling, retries only transient provider errors (rate limit/timeout/connection) with capped backoff, fails fast on permanent errors, and raises typed `LLMTruncationError` / `LLMProviderError` carrying `attempts_used`, `finish_reason`, `partial_response`.
- `blue_agent.py` — `blue_agent_node`: hardening/analysis pass.
- `judge_agent.py` — `judge_node`: decides PASS/FAIL, aggregates reports.
- `graph.py` — `build_graph()` (LangGraph StateGraph around red→blue→judge conditional edges), `compile_graph`, `run_pipeline(function_id, code, language, risk_score, context_bundle, file_path, repo_root, start_byte, end_byte, max_attempts, checkpointer)` — **the single reusable runner** (see notes on the duplicate that was removed). Returns a plain dict of the final state.
- `decisions.py` — decision helpers used by the agents.

### 2.4 Sandbox: `sandbox/`
- `docker_runner.py` — builds/prepares a Docker image per run, runs exploit/verification commands inside a container, reports output + exit codes; `readiness.py`-like logic for image readiness on Windows.
- `patcher.py` — `apply_patch(file_path, start_byte, end_byte, new_code, backup_dir)` writes a timestamped backup and returns `(target, backup)`; `restore_backup(backup, file_path)`; `apply_patch_with_validation(...)` applies then re-runs the sandbox exploit check to validate the patch.

### 2.5 Models
- `risk_scorer.py` — gradient-boosted RF classifier over AST/humanoid features; `predict(features)` returns risk probabilities and `risk_score`.
- `retriever.py` — FAISS/Chroma vector store of labeled vuln examples, `retrieve(query)` returns top-k context with scores (`retriever_top_k`, `retriever_scores`).
- `train_classifier.py` — training script for the triage classifier (needs labeled data).

### 2.6 Data pipeline
- `data/parser.py` — parses uploaded sources into function payloads (`_function_payloads`): AST-level extraction, language-aware (Python/C/JS).
- `data/feature_extractor.py` — AST/humanoid feature vectors for the classifier & embeddings.
- `data/context_gatherer.py` / `context_extractor.py` — gathers labeled curation data and serializes context bundles.
- `data/fetch_dataset.py` — pulls/constructs the labeled dataset into `data/test_vulns/` (6 labeled functions in `KNOWN_VULN_FUNCTIONS` in `evaluation.py`).
- `data/__init__.py` / `parser.py` etc. as modules.

### 2.7 Benchmarks
- `benchmarks/__init__.py`, `evaluator.py` (metric classes `ApproachMetrics`, `BenchmarkReport`, `create_empty_report`), `static_analyzer.py` (`run_all_sast`), `single_llm.py` (pure LLM approach), `runner.py` (`benchmark_repository`).
- Both `evaluation.py` and `benchmarks/evaluator.py` write artifacts into `data/benchmarks/`: `evaluation.json`, `evaluation_summary.md`, and labeled PNGs (`evaluation_verdict_distribution.png`, `evaluation_pipeline_funnel.png`, `evaluation_risk_distribution.png`, `model_health_summary.png`, `llm_usage_summary.png`) via `render_figures_from_metrics` / `_render_*`.

### 2.8 Eval harness: `evaluation.py`
- `LabelResult`, `EvaluationMetrics` dataclasses; `KNOWN_VULN_FUNCTIONS` (6); `run_labeled_evaluation()` (full pipeline per labeled function), `run_labeled_evaluation_heap()` (heap-based run order), `run_writeback_pass()` (applies Judge-PASS patches back to `data/test_vulns` with patcher backup/restore + post-write syntax check), `run_and_save_evaluation()` → writes JSON+summary, computes `_compute_verdict_distribution`, `model_health_metrics_from_store()` (reads `EVALUATION_JSON` for recall/precision/patch_success_rate), `render_figures_from_metrics`, `_render_*` (matplotlib helpers), `write_evaluation_json`, `write_evaluation_summary`.
- NOTE: `import vulnguard.evaluation` works; no pytest coverage for this module (add tests).

### 2.9 API server: `ui/server.py`
- `create_app()` factory builds the FastAPI app (`app = create_app()`), mounts `CORSMiddleware`, mounts the SQLite `ScanStore`.
- Routes (no duplicates, no deletions):
  - `GET /api/health` — `{"status": "ok", "timestamp"}`
  - `GET /api/scan/status` — `{"scans": {...}}`
  - `GET /api/scan/verdict-distribution` — judge verdict counts
  - `GET /api/scan/successful-fixes?limit=20` — recent `pipeline_status=COMPLETE AND judge_verdict=PASS` scans (validated only) with patch preview; `limit` must be 1-100 (422 otherwise); unreadable legacy `result_json` rows are logged and skipped; real store failures return 500 with the traceback in the server log
  - `GET /api/results/{scan_id}`, `GET /api/metrics` (total_scans, vulnerabilities_found, patches_validated, patch_rate)
  - `POST /upload` — multipart file upload → `_save_upload` → returns `{upload_id, repository, files_scanned, functions[]}`
  - `POST /upload/folder` — ZIP upload with paths
  - `GET /api/evaluation/model-health` — `{"recall","precision","patch_success_rate"}` (0.0 until evaluation.json exists)
  - `GET /api/evaluation/health` — `evaluation_json_exists`, `evaluation_summary_exists`, `figures_dir` (= `<repo>/data/benchmarks`), `figures[]`, `figures_count`, `model_health`, optional `metrics`/`verdict_distribution`/`metrics_error`
  - `POST /api/evaluation/run` — runs `run_and_save_evaluation()` end to end
  - `GET /api/evaluation/figures/{filename}` — serves PNGs
- Uses `run_pipeline` from `vulnguard.agents.graph`, and `vulnguard.sandbox.patcher` via the evaluation harness.

### 2.10 Store: `ui/store.py`
- `ScanStore(db_path)` — SQLite; `save(scan_id, result)`, `get`, `list`, `metrics()`, `verdict_distribution()`, `successful_fixes(limit)`. `successful_fixes` filters to validated PASS scans, clamps the limit, and tolerates legacy rows (`sqlite3.Row` has no `.pop()` — that bug caused the historical 500). DB at `data/vulnguard.db*` (gitignored).

### 2.11 Background jobs: `queue.py` + `worker.py`
- `queue.py` (`enqueue_job`) writes JSON job files into `data/uploads/` and POSTs to an RQ/fit queue; `worker.py` runs `run_scan_job(**kwargs)` which calls `run_pipeline(**kwargs)` and serializes a summary. (Task queue plumbing may vary by environment; check live behavior.)

### 2.12 Dashboard UI (frontend)
- `ui/src/App.tsx` — mounts `<Dashboard/>`.
- `ui/src/components/Dashboard.tsx` — main page:
  - Left column: file upload, detected-function list with single/batch scan, recent-scan history.
  - Right column: **Live Agent Stream** (`AgentFeed`) over WebSocket `ws://localhost:8000/ws/scan`; progress/colour/cancel.
  - Bottom analytics section: 4 metric cards (`total_scans`, `vulnerabilities_found`, `patches_validated`, patch success %), 3 model-health cards, verdict chips, recent validated-fix list, figures grid + "Re-run evaluation" button.
  - Fetches REST endpoints from `http://localhost:8000` (hardcoded base; see reachability note in 2.13).
- `ui/src/components/AgentFeed.tsx` — renders the event stream items with typing for `batch_function`, `update`, `patch`, `executed_patch`, `complete`, `error`, `skip`.
- `ui/src/components/dashboard/MetricCards.tsx` — styled `MetricCard` + `ModelHealthCard` (with lucide icons per color).
- `ui/src/lib/utils.ts` — `cn()` class merger; `index.css` — custom CSS variables (gradients, glassmorphism classes) + Tailwind-like utilities.
- `ui/vite.config.ts` — Vite 8 (-oxc), proxy for `/api` and `ws://` to the backend, `react-refresh`. Dev server on port 5173 (implied).

---

## 3. End-to-end flows

1. **Upload + scan**: `POST /upload` (or `/upload/folder`) → `vulnguard.agents.graph.run_pipeline` per function → `ScanStore.save` → results appear in `/api/metrics`, `/api/scan/status`, dashboard live stream via WebSocket.
2. **Agent walk**: Red agent runs LLM+retriever → patch → sandbox exploit run; Blue agent pass; Judge verdicts PASS/FAIL; patch validated in sandbox; PATCHED source file updated with backup on failure (patcher).
3. **Evaluation**: `POST /api/evaluation/run` → `run_and_save_evaluation` → JSON+summary+5 PNGs into `data/benchmarks/`; `GET /api/evaluation/health` then reports `evaluation_json_exists: true` and model-health numbers.
4. **Benchmarks**: `vulnguard benchmark --output-dir data/benchmarks` → per-approach JSON + labeled figures.

---

## 4. Key config values that matter
- `cfg.agent.max_retry_attempts`, `cfg.sandbox.image`, `cfg.llm.provider` (Gemini), `cfg.triage.*` (model names/thresholds), `cfg.backend.dashboard` (streamlit vs fastapi), `cfg.queue.*`.
- Python env via `requirements.txt`; frontend via `ui/package.json` (React 18, Vite 8, framer-motion, lucide-react, tailwind).
- `data/benchmarks` is the shared output dir for CLI benchmarks AND evaluation figures (both `vulnguard/evaluation.py` and `vulnguard/ui/server.py` use `Path(__file__).resolve().parents[2] / "data" / "benchmarks"`).

---

## 5. Where to look for anything
- New feature start: `vulnguard/evaluation.py` (analytics) or `vulnguard/ui/server.py` (API), `ui/src/components/Dashboard.tsx` (UI). For bugs: `tests/test_ui_server.py` (API regressions), `vulnguard/agents/` (pipeline), `vulnguard/sandbox/` (docker/patcher).
- Anything about agents: `vulnguard/agents/{red,blue,judge}_agent.py`, `state.py`, `graph.py`.
- Anything about scan persistence: `vulnguard/ui/store.py` + SQLite schema in `vulnguard/ui/server.py` `_save_upload`/schema setup.
- Anything about LLM/usage: `vulnguard/llm_runtime.py` + `usage` CLI + `data/llm_usage.jsonl`.
- Anything about security testing: `data/test_vulns/*`, `vulnguard/benchmarks/static_analyzer.py`.

---

## 6. Conventions / notes
- Python code style: double quotes in strings in most files, `from __future__ import annotations` where needed, TypedDict state, `logger = logging.getLogger(__name__)` everywhere, `create_app()` factory for the app, `main.py` as the unified entry.
- UI: Tailwind CSS + custom CSS classes (`glassmorphism`, `text-white/*`, `bg-white/*`), framer-motion animations, lucide react icons; components are functional with hooks; API base `http://localhost:8000` hardcoded in `Dashboard.tsx` fetch URLs (known limitation — must run backend on 8000 with `--backend fastapi`).
- The previous session added `vulnguard/evaluation.py`, `ui/src/components/dashboard/MetricCards.tsx`, changed `vulnguard/agents/graph.py` (run_pipeline), `vulnguard/sandbox/patcher.py` (backup/restore), `vulnguard/ui/server.py` (analytics endpoints), `vulnguard/ui/store.py` (successful_fixes query), `ui/src/components/Dashboard.tsx` (analytics), `README.md` (sample path), `.gitignore` (new Python/UI/secret sections). All local-only, uncommitted.
- Bench/out-of-tree work generates `data/benchmarks/` and `data/uploads/`; both gitignored.

---

## 7. Repair session notes (October 2026) — verified changes

### Root causes & fixes (all verified by tests)

1. **Agent live stream auto-scrolled on every event** (Bug A).
   - Cause: `ui/src/components/AgentFeed.tsx` ran `bottomRef.current?.scrollIntoView(...)` in a `useEffect` keyed on `[events]`.
   - Fix: effect + bottom sentinel ref removed entirely; scrolling is now purely user-controlled.

2. **Truncated Red Agent JSON became "No Exploit Found"** (Bug B).
   - Cause: `red_agent_node` parsed the model response exactly once; on `JSONDecodeError` it returned `vulnerability_found=False` (with `RED_PARSE_ERROR`), which the graph used to route END — indistinguishable from a confirmed negative. `_call_llm` also parsed fences via brittle `.split("```")` and never looked at `finish_reason`.
   - Fix: shared `vulnguard/agents/llm_parsing.py`; bounded parse-retry loop (max `cfg.llm.max_retries` attempts, corrective re-prompt between attempts); on exhaustion node returns `pipeline_status="RED_ERROR"`, `judge_verdict="RED_AGENT_ERROR"`, with a 400-char raw preview + parse_error kept in `red_report`. Graph `_after_red` routes RED_ERROR to END without the "no vulnerability found" path; `ui/server.py` maps RED_ERROR → `FAILED`/`RED_AGENT_ERROR` in the store. `_call_llm` detects `finish_reason ∈ {length, max_tokens}` and escalates `max_tokens ×2` per retry (tested: 100→200→400).

3. **Blue Agent parse failure handling** (Bug C).
   - Same bounded parse-retry loop; exhaustion now returns `pipeline_status="BLUE_ERROR"`, `judge_verdict="PATCH_GENERATION_FAILED"` (new `JudgeVerdict` member).
   - `judge_agent_node` recognizes a pre-existing `BLUE_ERROR` status first (verdict PATCH_GENERATION_FAILED, uses blue's error_logs as retry feedback). The judge's enum conversion now uses try/except instead of a `__members__` name check that silently mislabeled `NEW_DEPENDENCIES_REJECTED` as BUILD_FAILED.

4. **Frontend status separation** (Bug E).
   - `AgentFeed.tsx` renders: Red response-error card (explicitly "not a confirmed absence of vulnerabilities") vs red "No Vulnerability Detected" vs "Attack Payload (awaiting sandbox validation)"; Blue "PATCH_GENERATED — awaiting sandbox validation" card plus a Blue generation-error card;
   - Judge card shows "Retry Scheduled — retry N/M in progress" when `pipeline_status=RETRY`.

5. **Config**: `VULNGUARD_LLM_TEMPERATURE` env override added (kept default 0.0 for EC-7.5 determinism; Gemini 3 recommends 1.0 — documented, not silently changed).

### State/status values added
- `pipeline_status`: `RED_ERROR` (Red parse/generation failure → server maps to FAILED), `BLUE_ERROR` (Blue parse/generation failure → judge schedules bounded retry).
- `judge_verdict`: `RED_AGENT_ERROR`, `PATCH_GENERATION_FAILED`.
- Same event payload shape as before (`agent_update`/`complete`/`error`); new fields are additive (`state.red_report.parse_error`, `attempt_number`/`max_attempts` in judge updates).

### Frontend test stack (new)
- `ui` now has `vitest`, `jsdom`, `@testing-library/react`, `@testing-library/jest-dom` (devDeps); script `npm run test`. Config lives in `ui/vite.config.ts` (`test:` block, jsdom, setup `ui/src/test-setup.ts`). Tests: `ui/src/components/AgentFeed.test.tsx` (9 tests: no auto-scroll on new events, no window.scrollTo, message order preserved, RED_ERROR vs negative detection vs attack-payload cards, Blue patch/error cards, judge retry progress).

### Tests executed (results)
- `.venv/Scripts/python.exe -m pytest tests/test_agents.py -q` → 54 passed (20 new truncation/parse/retry/routing tests).
- `.venv/Scripts/python.exe -m pytest -q` → 156 passed.
- `cd ui && npx vitest run` → 9 passed; `npm run lint` → 0 errors; `npm run build` → OK.
- Mock-LLM end-to-end `run_pipeline` smoke run → RED(vuln found) → BLUE(patch) → FAILJudge(EXPLOIT_NOT_REPRODUCED, harness redefined target) → status FAILED — honest verdict.

### Remaining limitations / unverified
- Live Gemini truncation behavior (Gemini 3 reasoning exhausting the budget) could not be reproduced without API credentials; the fix detects it via `finish_reason` and escalates, but the original observed 80-char failure was not re-run against the real provider.
- Docker sandbox validation (build/test/exploit dual pass) still requires Docker Desktop; only the static no-Docker path was exercised here.
- Browser-level manual verification of scroll behavior: covered by component tests, not by a real browser session.

---

## 8. Reliability repair session 2 (October 2026) — verified

### Root causes found this session

1. **Red Agent crash on persistent truncation.** `_call_llm` raised `ValueError`
   after the retry budget, and `red_agent_node` had no `except`; LangGraph
   re-raised into `ws_scan`. The merged prompt asked for diagnosis *and* a full
   harness, so reasoning tokens could exhaust `max_tokens` before the JSON
   closed; the last retry also re-raised instead of producing state.
2. **Wrong escalation evidence.** The retry log announced a larger budget on
   attempts where no further call would be made, and escalation was not capped,
   so identical requests could repeat indefinitely at the same limit.
3. **`/api/scan/successful-fixes` 500.** `ScanStore.successful_fixes` called
   `row.pop("result_json")` on a `sqlite3.Row` (`AttributeError: 'sqlite3.Row'
   object has no attribute 'pop'`), so every non-empty response failed.
4. **Judge could PASS unvalidated patches.** When `exploit_harness` was missing,
   `_validate` skipped the exploit pass and returned `PASS`. It also reported any
   non-reproducing/failed-to-run harness as `EXPLOIT_NOT_REPRODUCED`, and asked
   Blue to re-patch for those cases.
5. **ML triage looked broken.** Any pipeline `error` event rendered a "Pipeline
   Error" card next to the triage card with no stage label, implying triage
   failed; `Dashboard.loadDashboardData` silently ignored a non-OK
   successful-fixes response.

### Behavior now

- Red node: diagnosis call → harness call only if a defect is found. Harness
  failure keeps `red_report` (type/CWE/severity/explanation) and records
  `exploit_status` (`NONE|AVAILABLE|UNAVAILABLE|INVALID|ERROR`) + `exploit_error`.
  On exhausted diagnosis retries: `pipeline_status=RED_ERROR`,
  `judge_verdict=RED_AGENT_ERROR`, `red_report.parse_error`, `error_logs`;
  the node never raises. Truncated full diagnosis is retried once in compact mode.
- `llm_calls.call_llm_json`: total provider calls bounded by
  `cfg.llm.max_retries` per generation step; `max_tokens` doubles only on
  truncation up to `max_token_ceiling`, then `LLMTruncationError` immediately;
  permanent errors fail fast; transient errors back off (capped 30s); per-call
  `timeout=cfg.llm.request_timeout_seconds`. Parse repair is 1 extra call
  (`_PARSE_ATTEMPTS = 2` per node); LangGraph adds no retry policy, so the two
  layers do not multiply.
- Judge verdicts: `EXPLOIT_NOT_REPRODUCED` (harness ran, defect not shown),
  `EXPLOIT_INVALID` (harness malformed/unsafe), `EXPLOIT_UNAVAILABLE` (no PoC,
  patch not proven secure), `EXPLOIT_EXECUTION_ERROR` (harness/target never ran,
  e.g. import/compile failure), `EXPLOIT_NOT_BLOCKED` (valid exploit still fires
  on the patch), `BUILD_FAILED` (patched source no longer runs), plus existing
  guardrail verdicts and `PATCH_GENERATION_FAILED`.
- Retry routing: `RETRYABLE_VERDICTS` (build/tests/exploit-not-blocked/guardrail/
  patch-generation failures) go back to Blue with the real evidence until
  `max_attempts` (then `MAX_RETRIES_EXHAUSTED`); `TERMINAL_FAILURE_VERDICTS`
  (unproven/invalid/unavailable/execution-error) end as `FAILED` with their own
  verdict and no pointless re-patching. `PASS` requires a valid harness that
  triggered on the original code and did not trigger on the patched code.
- Dashboard transport: `_safe_send` converts a closed client into
  `WebSocketDisconnect` (scan persisted as `DISCONNECTED`, stage recorded);
  unexpected errors persist `pipeline_status=ERROR`, `failed_stage`, concise
  `error_logs`, and send `{type:"error", stage, function_id, message}` (full
  traceback stays in the server log). A stream that ends without a terminal
  verdict is persisted as `FAILED`/`PIPELINE_INCOMPLETE`. `complete` now carries
  `pipeline_status` and `judge_verdict`. Scans ending in `RED_ERROR` persist
  `FAILED`/`RED_AGENT_ERROR`, never a clean negative.
- Frontend: triage card is preserved; errors are labelled "Agent Pipeline Error"
  with a stage chip and an explicit note that triage remains valid when a triage
  result exists. Red cards distinguish response error / diagnosis-without-exploit
  / attack-payload / no-vulnerability. `complete` renders the final status and
  verdict. Dashboard surfaces successful-fixes load failures and tolerates
  malformed WS events. CLI (`main.py::_print_scan_result`) no longer prints
  "No vulnerability found" for `RED_ERROR`.
- `successful_fixes(limit)`: clamps to 1..100, returns only validated PASS rows,
  skips unreadable/incomplete legacy payloads with a warning, and never leaks
  `result_json`; genuine DB errors propagate to a logged 500.

### Tests (commands and results)

- `.venv/Scripts/python.exe -m pytest -q` → **179 passed** (69 in
  `tests/test_agents.py`, 11 in `tests/test_ui_server.py`).
  New coverage: truncation at the ceiling, non-retryable provider errors,
  diagnosis preserved when the harness truncates, invalid harness never becoming
  an exploit, judge verdict distinctions (`EXPLOIT_UNAVAILABLE/INVALID/
  EXECUTION_ERROR/NOT_REPRODUCED/PASS`), retry routing per category, WS graph
  failure event/stage/persistence, RED_ERROR not a clean scan, next scan after a
  failure, successful-fixes populated/empty/legacy/limit/DB-error.
- `cd ui && npx vitest run` → **12 passed** (auto-scroll, triage preserved on
  failure, stage-labelled error, diagnosis-without-exploit, final status,
  retry progress, patch cards). `ui/vite.config.ts` sets `test.pool: 'threads'`
  (forked workers time out on this Windows setup).
- `cd ui && npm run lint` → 0 warnings/errors; `npm run build` → OK.
- Mock end-to-end (`VULNGUARD_MOCK_LLM=true python -c "run_pipeline(...)"`):
  diagnosis preserved, harness invalid → `FAILED`/`EXPLOIT_INVALID`, no crash.
- Not verified: live Gemini calls (no credentials in this session) and Docker
  sandbox execution. Live providers may still truncate; the ceiling now fails
  explicitly instead of crashing, and the compact diagnosis path reduces risk.

### Remaining limitations

- No live-provider verification of Gemini 3 thinking-token behaviour; if
  diagnoses still truncate at 16k, raise `VULNGUARD_LLM_MAX_TOKEN_CEILING` or set
  `VULNGUARD_LLM_TEMPERATURE=1.0` per Gemini guidance.
- Docker dual-pass validation is covered only by mocked runners here.

---

## 9. Empirical evaluation session (2026-10-28) — run `run-2026-10-28T-baseline`

Documentation-only session. Full report: `test.md`. Raw evidence:
`evaluation/run-2026-10-28T-baseline/`. No application source, config, dependency, dataset, model
artifact or fixture was modified.

### 9.1 Verified architecture (as it exists in the working tree)

- `vulnguard/agents/graph.py` — LangGraph `red_agent → blue_agent → judge_agent` with
  `_after_red` (END when no defect or `RED_ERROR`) and `_after_judge` (END on COMPLETE/FAILED,
  back to Blue on RETRY). `run_pipeline(...)` is the single public runner used by the CLI, the
  FastAPI `ws_scan` handler and the evaluation harness.
- `vulnguard/agents/red_agent.py` — two bounded calls: compact `RedAgentDiagnosis`, then
  `RedAgentHarness` only when a defect is diagnosed. Sets `exploit_status`
  (`NONE|AVAILABLE|UNAVAILABLE|INVALID|ERROR`) and never raises.
- `vulnguard/agents/blue_agent.py` — patch generation + guardrails (`INTERFACE_VIOLATION`,
  `NEW_DEPENDENCIES_REJECTED`, `DESTRUCTIVE_PATCH_REJECTED` via `cfg.agent.min_ast_ratio = 0.4`).
- `vulnguard/agents/judge_agent.py` — acceptance sequence: syntax check → exploit-evidence gate →
  (repo mode only) build → tests → exploit on unpatched → exploit on patched → deterministic
  double-run. `PASS` requires a valid harness that fired on the original code and not on the patch.
  `RETRYABLE_VERDICTS` vs `TERMINAL_FAILURE_VERDICTS` split the retry loop.
- `vulnguard/sandbox/docker_runner.py` — per-run container with `network_mode="none"`,
  `read_only=True`, `tmpfs=/tmp`, `user=65534:65534`, `cap_drop=["ALL"]`, `pids_limit=64`,
  `mem_limit` from config (512m), repository bind-mounted **read-only** at `/host_workspace` and
  copied to `/tmp/workspace` inside the container.
- Patch application: the Judge splices the patched function into an in-memory copy
  (`_get_full_file_code`); **no host file is written**. The only repository-write path is
  `vulnguard/sandbox/patcher.py::apply_patch`, used solely by `vulnguard/evaluation.py` writeback.
- `vulnguard/evaluation.py` — labeled cohort (`KNOWN_VULN_FUNCTIONS`, 6 functions),
  `run_labeled_evaluation(...)` (writes JSON/summary/PNGs to `data/benchmarks`) and
  `run_writeback_pass(...)` (**mutates `data/test_vulns`** — deliberately not executed here).

### 9.2 Fixtures and datasets available

`data/test_vulns/` (6 files, 14 parsed functions, 6 labeled-vulnerable targets):
`vuln_buffer.c`, `vuln_cmdi.py`, `vuln_format.c`, `vuln_race.c`, `vuln_sqli.py`,
`vuln_taint_flow/{input_handler,database,processor}.py`. Model artifact:
`vulnguard/models/artifacts/vulnguard_classifier.joblib`. **No labeled negatives, no local training
dataset, no held-out split.** `data/benchmarks/` is empty (no prior evaluation output exists).

### 9.3 Tests run (this session)

- `$PY -m pytest -q` → 179 passed, 0 failed, 0 skipped (65.4 s).
- `$PY -m pytest -m docker -v` → 4 passed against the live daemon (unprivileged user, Python and C
  exploit linking, real buffer-overflow detection).
- `cd ui && npx vitest run` → first attempt: vitest worker timeout, 0 tests, exit 1; retry:
  **12 passed**.
- `cd ui && npx oxlint` → 0/0; `npx tsc -b && npx vite build` → OK.
- `$PY -m vulnguard.main doctor` → all `[OK]` including a live Gemini request.

### 9.4 Live evaluation of the six labeled cases (real Gemini + real Docker)

| Metric | Num/Den | Result |
|---|---|---|
| ML triage flags labeled positives (@ threshold 30) | 6/6 | 100 % (only 3/6 on model probability alone) |
| Red Agent detection | 5/6 | 83.3 % |
| Reported CWE correct | 5/5 | 100 % |
| Patch generated | 5/5 | 100 % |
| Patch syntactically valid | 5/5 | 100 % |
| Patch applied to a workspace | 0/5 | 0 % (`NameError` in `patcher.py`) |
| Judge `PASS` | 1/6 | 16.7 % (C03 buffer overflow) |
| Exploit blocked, where a valid baseline exploit existed | 1/1 | 100 % (n=1, provisional) |
| Strict PSR@1 / PSR@3 | 0/6 | 0 % |
| First-attempt success | 1/6 | 16.7 % |
| Unresolved | 5/6 | 83.3 % |
| TTR | n=6 | median 114.1 s, mean 112.9 s |
| Cost | 35 calls, 74,837 tokens | $0.630014 total; $0.105 per attempt; $0.630 per Judge-accepted fix |
| ML inference latency | 150 samples/run | steady-state median 2.12–2.77 ms/function |

Unavailable metrics (and why): strict PSR denominator unmet (patch application broken);
Regression Rate (the Judge never runs the baseline suite and converts "no tests" to a pass);
Retry Recovery (0 retries — every failure was a terminal evidence verdict); ML precision/recall/F1/
AUC/Brier/ECE/top-k (no labeled negatives, no held-out data); cost per strict fix (0 strict fixes);
repository scan duration (out of budget).

### 9.5 Defects found and deliberately not repaired

1. `vulnguard/sandbox/patcher.py::apply_patch` raises `NameError: name 'time' is not defined`
   (module imports only `logging`, `pathlib`) — repository-level patch writeback is non-functional.
2. Judge build/test step is vacuous for the fixtures: build auto-detects as
   `echo 'No build system detected'`; `pytest -x` collects 0 tests (exit 5) and is treated as a
   skipped pass, so `test_success=True` does **not** mean tests passed.
3. Red Agent harness generation is the dominant failure: 4/5 detections ended with no usable proof
   of concept (`EXPLOIT_INVALID`), so those patches were never executed.
4. Two of six ML "detections" come from the static-signal floor (which equals the deployed
   threshold of 30), not from the classifier.

### 9.6 Repository state

Initial and final `git status --porcelain` are identical for all pre-existing entries
(`evaluation/run-2026-10-28T-baseline/00-initial-git-status.txt`): HEAD `7474c6d`, branch `main`,
19 `M`, 2 `D`, 5,093 staged `node_modules/` deletions, 11 `R`, 1 `RM`, 11 untracked files — all
pre-existing. The evaluation added only: `evaluation/run-2026-10-28T-baseline/**`, `test.md`, and
this section of `context.md`. Fixture mtimes are unchanged (2026-09-16) and no patch backups were
created. `data/llm_usage.jsonl` grew 87 → 123 records because the application logs its own provider
usage — expected runtime telemetry, not a source/config/dataset change.
