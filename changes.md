# VulnGuard AI — Changes (2026-11-06)

## 1. Red Agent Reliability

**Root causes found**

- The harness call asked for a complete program as a JSON string but started at the generic
  4096-token budget, so reasoning tokens could exhaust the completion before the JSON closed
  (`finish_reason=length`).
- The corrective retry was a single call at the *same* base budget. A truncated harness therefore
  could never recover ("corrected harness unavailable: … after 1 attempts").
- A model refusal/prose and a generated-but-statically-rejected harness both became
  `exploit_status=INVALID` → Judge `EXPLOIT_INVALID`, conflating "no exploit could be generated"
  with "an exploit ran and disproved the finding".
- Callee extraction matched names as substrings and never pulled signatures from imported local
  modules, so task packets could report `0 callees` and `19 context tokens` even when the target
  called another module.

**Prompt / schema changes**

- Diagnosis now also carries `location` and `attack_strategy`; the harness response carries
  `execution_instructions`, `expected_vulnerable_behavior` and `expected_patched_behavior` alongside
  `exploit_code_harness` and `expected_stdout_regex`. All new fields are optional, so the LangGraph
  state and downstream agents stay compatible.

**Harness generation and validation**

- Harness generation starts at `VULNGUARD_LLM_HARNESS_MAX_TOKENS` (default 8192, capped by the
  configured ceiling).
- On truncation, missing fields, unparseable JSON, or a statically invalid harness, one *smaller*
  regeneration is requested with a larger output budget (never an identical repeat). Harness
  generation is bounded to two calls.
- Validation stayed strict: target-language markers, no foreign language, `int main` for C/C++,
  import/link the real target without redefining it, required success regex, marker not embedded in
  attacker input, no "success on any exception". Prose/refusal detection was extended.

**Failure classification**

- New `exploit_failure_kind`: `EXPLOIT_GENERATION_FAILED` (refusal, truncation, empty/unparseable
  response) vs `HARNESS_INVALID` (code produced, rejected before execution).
- New Judge verdicts `EXPLOIT_GENERATION_FAILED` and `HARNESS_INVALID`; both are terminal and can
  never be `PASS`.
- The Judge also records `exploit_confirmed` (valid harness fired on the original code) and
  `security_validated` (Judge `PASS`) separately. `PASS` still requires build/tests where they run,
  the exploit firing on the original code, and not firing on the patched code.
- Diagnosis and the Blue patch are preserved when the exploit is missing; the run ends FAILED with
  an explicit inconclusive verdict instead of claiming security validation.

**Context assembly**

- `gather_context` merges the tree-sitter imports/callees already present in the upload payload,
  resolves callee signatures from imported local modules, and includes the enclosing class header
  and `__init__` signature (`class_context`). Token budget and function-level scoping unchanged.

## 2. Agent Live Stream

- New `ui/src/lib/functionStreams.ts`: one keyed record per function (`scanId::functionId`) with pure
  `applyStreamEvent` / `applyEventToStreams` / `upsertStream` helpers. An event updates exactly one
  record; duplicate events are ignored; cards keep their order.
- `AgentFeed.tsx` now renders every function as a card: header (name, path, risk, classification,
  status, verdict), independent Red / Blue / Judge sections, sandbox/log detail, event log. The list
  scrolls vertically; new events never force a scroll, an "N new updates" button appears instead.
- `Dashboard.tsx`: replaced the single `events` array and selected-function view with the stream
  collection. Each function has its own WebSocket (the previous socket is no longer closed when a
  new scan starts), batch scans pre-create a card for every function and run with concurrency 3, and
  a Clear action empties the stream.
- Backend `/ws/scan` now tags every event with `function_id`; `complete` also reports
  `exploit_status`, `exploit_confirmed` and `security_validated`.

## 3. Dashboard Cleanup

- Removed the "Recent validated fixes" panel, its `SuccessfulFix` type, `fixes` state, the
  `/api/scan/successful-fixes` request, and the error state used only by that panel.
- The endpoint, `ScanStore.successful_fixes`, the `scans` table and all persisted patch/validation
  records are untouched, so evaluation and research history remain available.

## 4. Testing

| Check | Result |
|---|---|
| `.venv/Scripts/python.exe -m pytest -q` | **197 passed** |
| `cd ui && npx vitest run` | **25 passed** (13 AgentFeed, 8 functionStreams, 4 scanOutputStore) |
| `cd ui && npx tsc -b` | pass |
| `cd ui && npm run lint` (oxlint) | 0 warnings, 0 errors |
| `cd ui && npx vite build` | pass |

New tests: `tests/test_harness_reliability.py` (budget, truncation recovery, refusal vs invalid
harness, terminal verdicts, validation flags), `tests/test_context_assembly.py` (imports/callees/
enclosing class), `ui/src/lib/functionStreams.test.ts` (5 concurrent functions, isolation, duplicate
events, verdict mapping), rewritten `ui/src/components/AgentFeed.test.tsx` (5 cards, independent
sections, verdict on the correct card, no auto-scroll, triage preserved on failure).

**Not verified here:** a live Gemini run and a real Docker dual-pass exploitation. The UI was
validated by component tests, not by a browser session.

## 5. Files Modified

| File | Why |
|---|---|
| `vulnguard/agents/red_agent.py` | Extended schemas/prompts, harness budget + recovery, failure classification |
| `vulnguard/agents/judge_agent.py` | New generation/invalid verdicts, honest validation flags, failure-kind gate |
| `vulnguard/agents/state.py` | `exploit_failure_kind`, `exploit_confirmed`, `security_validated` |
| `vulnguard/agents/llm_parsing.py` | Recover a balanced JSON object wrapped in prose (never code) |
| `vulnguard/config.py` | `VULNGUARD_LLM_HARNESS_MAX_TOKENS` (default 8192) |
| `vulnguard/data/context_gatherer.py` | Merge parser imports/callees, resolve callee signatures, enclosing class |
| `vulnguard/ui/server.py` | `function_id` on every WS event, richer context, validation flags on `complete` |
| `ui/src/lib/functionStreams.ts` (new) | Per-function stream state and event reducer |
| `ui/src/components/AgentFeed.tsx` | Multi-function cards, Red/Blue/Judge sections, scroll indicator |
| `ui/src/components/Dashboard.tsx` | Per-function sockets, concurrent batch, Clear, fixes panel removed |
| `ui/src/lib/functionStreams.test.ts` (new) | Stream reducer tests |
| `ui/src/components/AgentFeed.test.tsx` | Rewritten for the multi-function stream |
| `tests/test_agents.py` | Truncation now expects `UNAVAILABLE` + generation-failure kind |
| `tests/test_harness_reliability.py`, `tests/test_context_assembly.py` (new) | New coverage |
| `context.md`, `changes.md` | Persistent context and this change log |

## 6. Generalization — repository-independent Red Agent

**Architecture**

- New `vulnguard/agents/harness/` package. Vulnerability reasoning stays in the Red Agent; language
  mechanics moved into adapters: `python_adapter.py`, `c_adapter.py` (+ `CppAdapter`),
  `javascript_adapter.py`, `java_adapter.py`, `generic_adapter.py`. Each owns its markers, program
  shape, target-loading instruction, prerequisite notes, entry-point/load validation, sandbox
  command and an honest `runtime_status`.
- `__init__.py` provides an alias registry (`py`, `python3`, `c++`, `cc`, `node`, `ts`, …), a support
  matrix and `get_adapter()`; unknown languages get the unsupported fallback instead of silently
  passing validation.
- `red_agent.py` now delegates: language markers, `_harness_shape`, workspace-target instruction and
  the language-specific validation branch. The generic guardrails (prose/refusal, required success
  regex, wrong language, dangerous payloads) still run for every adapter.
- `base.target_symbol()` accepts pipeline `function_id` and upload `id`/`name`, so the adapters work
  from the dashboard, CLI and evaluation harness without a conversion layer.

**Repository environment probe** (`harness/environment.py`)

- Bounded walk (depth 3, 400 files, skips VCS/virtualenv/node_modules/build output) detects the
  target module, import roots, manifests, declared Python dependencies and which are missing, test
  infrastructure, database artifacts/signals, and the language runtime status.
- Findings are cached, injected into the harness prompt, persisted as
  `red_report["harness_environment"]`, and appended to generation failure messages as explicit
  limitations. Nothing is assumed available when it could not be resolved.

**Vulnerability strategies** (`harness/strategies.py`)

- 15 reusable class-level strategies selected by CWE then vulnerability type (SQLi, command
  injection, buffer overflow, format string, path traversal, TOCTOU, XSS, code injection,
  deserialization, SSRF, XXE, open redirect, LDAP injection, generic). Each describes prerequisites,
  observable proof and approach — no function names or canned payloads.
- Harness prompts now include the execution adapter, repository environment and selected strategy,
  in addition to the pinned language and shape.

**Dataset separation**

- Production code contains no `test_vulns` filenames, fixture function names or payloads; this is
  enforced by `test_production_agent_code_contains_no_dataset_fixtures` over `red_agent.py` and every
  adapter module.
- `data/test_vulns` remains purely the regression/evaluation corpus.

**ML triage payload**

- `/ws/scan` `triage_result` now also reports the contributing `features` and the high-confidence
  `static_signal` that bypassed the model. Zero-valued features are omitted, and an unavailable
  model is reported as such rather than faked.

## 7. Agent Live Stream — vertical layout

- Removed the three-column Red/Blue/Judge grid. Each function card is now a single vertical
  sequence: function header → **ML Triage** → **Red Agent** → **Blue Agent** → **Judge Agent**.
- Added a real ML Triage section (score, high-risk/below-threshold, threshold, extracted features,
  static signal) instead of a one-line strip in the header.
- Every section is `w-full min-w-0`; code/diff/log blocks scroll internally; the stream panel now
  occupies its own full-width dashboard row (`lg:col-span-12`).
- All previous multi-function behaviour is unchanged: one card per scanned function, independent
  state, three concurrent scans, completed cards retained, vertical scrolling with no forced scroll.

## 8. Responsive behaviour

- Cards and sections are full-width on mobile; the triage block stacks vertically below `sm` and
  becomes a score/features split above it; feature lists use one column on mobile and two on larger
  screens; fixed-width label columns were reduced on small screens.
- Long error messages use `whitespace-pre-wrap break-words`; code blocks keep an internal
  horizontal scroller, so the dashboard itself never needs horizontal scrolling.

## 9. Test results

| Suite | Kind | Result |
|---|---|---|
| `tests/test_harness_adapters.py` | adapter registry and strategy contract tests | pass |
| `tests/test_generalization.py` — independent repos | Python package (`svc/billing/invoices.py`), C (`src/telemetry.c`), JavaScript (`lib/report.js`), all with unfamiliar names/layouts | pass |
| `tests/test_generalization.py` — regression dataset | all six `data/test_vulns` scenarios (C01–C06) still produce a valid harness | pass |
| `.venv/Scripts/python.exe -m pytest -q` | whole backend suite | **231 passed** |
| `cd ui && npx vitest run` | frontend suite | **28 passed** (16 AgentFeed, 8 functionStreams, 4 scanOutputStore) |
| `cd ui && npx tsc -b` | typecheck | pass |
| `cd ui && npm run lint` | oxlint | 0 warnings, 0 errors |
| `cd ui && npx vite build` | production build | pass |

New frontend assertions: sections appear in the required vertical order, no three-column grid
remains, each section is full width, ML features/static signal render, and the full sequence exists
for queued functions.

**Not verified here:** live Gemini generation and real Docker dual-pass execution. LLM responses
were stubbed in every new test; JavaScript/Java sandbox runtimes and third-party dependency
installation were not exercised.

## 10. Files added/modified in this round

| File | Change |
|---|---|
| `vulnguard/agents/harness/base.py` (new) | Adapter contract + target symbol resolution |
| `vulnguard/agents/harness/python_adapter.py` (new) | Python module/class resolution, import + AST validation |
| `vulnguard/agents/harness/c_adapter.py` (new) | C/C++ entry point, prototype/link validation, sanitizer command |
| `vulnguard/agents/harness/javascript_adapter.py` (new) | Node module loading + output validation |
| `vulnguard/agents/harness/java_adapter.py` (new) | Java class/main/target validation |
| `vulnguard/agents/harness/generic_adapter.py` (new) | Explicit unsupported fallback |
| `vulnguard/agents/harness/environment.py` (new) | Repository layout/dependency/test/database probe |
| `vulnguard/agents/harness/strategies.py` (new) | Reusable vulnerability-class guidance |
| `vulnguard/agents/harness/__init__.py` (new) | Alias registry + support matrix |
| `vulnguard/agents/red_agent.py` | Delegates language mechanics; prompt includes adapter/environment/strategy; persists environment |
| `vulnguard/ui/server.py` | Triage event carries features + static signal |
| `ui/src/lib/functionStreams.ts` | Triage features/static signal in stream state |
| `ui/src/components/AgentFeed.tsx` | Vertical layout, ML Triage section, full-width sections, test ids |
| `ui/src/components/Dashboard.tsx` | Live stream occupies a full-width row |
| `ui/src/components/AgentFeed.test.tsx` | Vertical order/full-width/triage assertions |
| `tests/test_harness_adapters.py` (new) | Adapter and strategy contracts |
| `tests/test_generalization.py` (new) | Independent repos + six-scenario regression + dataset-purity guard |
| `context.md` | §12 generalization, adapter layer, vertical stream, support matrix, limits |

## 11. Remaining limitations

- Live-provider harness quality for complex classes (races, SSRF, template injection) is still
  unproven; those runs end `EXPLOIT_UNAVAILABLE`/`EXPLOIT_GENERATION_FAILED` instead of a false PASS.
- Docker dual-pass and sandbox image contents (Node, JDK, third-party packages) were not run here.
- JavaScript and Java are generated and statically validated but remain **experimental** runtimes.
- Go, Rust, Ruby, PHP and other languages have no adapter; their results are never marked validated.
- ML triage itself only scores Python, C and C++; other languages are routed with an explicit
  `LANGUAGE_UNSUPPORTED` signal.
- A repository that needs external services (a real database server, a network service) will be
  rejected by harness validation rather than silently "proven" — by design, but it limits coverage.
- Pre-existing: the Judge's build/test steps are vacuous without a build system or collected tests
  (§9.5), and `patcher.py::apply_patch` still raises `NameError` (§9.5).
