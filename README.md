# VulnGuard AI

VulnGuard triages functions, analyzes high-risk code with Red and Blue agents,
and validates proposed patches with a Judge agent. Source discovery supports
Python, C, C++, Java, and JavaScript repositories.

## Prerequisites

- Python 3.12
- Node.js 20 or newer
- Docker Desktop for sandbox validation
- An API key for the configured LLM provider

## Setup

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

Set `GEMINI_API_KEY` in `.env`. The stable profile routes both risk tiers to
`gemini-3.1-pro-preview` because agent scans require reliable structured output.

Run the preflight once. It makes a small live Gemini request, connects to Docker,
and builds the isolated multi-language sandbox image when it is missing:

```powershell
python -m vulnguard.main doctor --build-sandbox
```

Do not start the backend until every doctor check says `[OK]`. Run it again after
Docker Desktop upgrades or restarts; the backend recovers when Docker becomes
available without needing its own restart.

## Run the dashboard

Start the API from the project root:

```powershell
python -m vulnguard.main dashboard --backend fastapi --port 8000
```

Start the React UI in a second terminal:

```powershell
cd ui
npm install
npm run dev
```

Open `http://localhost:5173`, upload a supported source file or a ZIP repository, and
select a discovered function or scan all discovered functions as a batch.
Repository uploads enable cross-file context and project build/test validation.
Scans can be cancelled, recent history is shown in the dashboard, and results are retained in
`data/vulnguard.db`, and generated patch diffs can be downloaded from the live
agent feed.

Useful API endpoints:

- `GET /api/metrics`
- `GET /api/scan/status`
- `GET /api/results/{scan_id}`

## Run a CLI scan

```powershell
python -m vulnguard.main scan samples/vulnerable_app.py --no-docker
```

Remove `--no-docker` when Docker Desktop is running and sandbox verification is
required.

Without Docker, the Judge performs syntax and patch guardrail checks and reports
`SANDBOX_UNAVAILABLE`. Install Docker for build, test, and exploit validation;
static-only results are not counted as validated patches.

## Run a repository benchmark

```powershell
python -m vulnguard.main benchmark . --max-files 100 --output-dir data/benchmarks
```

The command writes JSON and Markdown comparisons for VulnGuard triage and any
installed SAST tools. Precision and recall are reported only for labeled data.

## Compare LLM usage

VulnGuard records provider, model, token counts, and LiteLLM's estimated cost in
`data/llm_usage.jsonl`. Prompts, source code, responses, and API keys are not logged.

```powershell
python -m vulnguard.main usage
python -m vulnguard.main usage --json
```

## Test

```powershell
python -m pytest -q
cd ui
npm run test
npm run lint
npm run build
```
