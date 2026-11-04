# VulnGuard AI — Autonomous Vulnerability Detection and Remediation System

## 1. Project Overview
VulnGuard AI is an advanced, multi-agent AI system designed to automatically detect, exploit, and patch software vulnerabilities in source code. By combining lightweight Machine Learning (ML) for rapid triage with Large Language Models (LLMs) for complex reasoning, VulnGuard acts as an autonomous security engineering team. 

Unlike traditional static analysis tools (SAST) that simply flag potential issues and produce high false-positive rates, VulnGuard actively proves the existence of a vulnerability by writing a Proof-of-Concept (PoC) exploit, generates a patch, and securely verifies that the patch fixes the issue without breaking existing functionality.

## 2. Core Architecture
The system is built on a highly modular architecture consisting of five main pillars:

### A. ML Triage & Context Extraction (The Pre-processor)
To minimize expensive LLM token usage and reduce latency, the system does not send all code to the agents.
* **Tree-Sitter Parser:** Statically analyzes the repository across multiple languages (Python, C/C++, Java, JavaScript) to extract individual functions, classes, cross-file imports, and callee signatures into a localized "Context Bundle."
* **ML Risk Scorer:** A fast classifier trained on historical vulnerability data (e.g., CVEFixes). It scores the extracted code chunks. If a function's risk score is below an optimal threshold, it is bypassed. Only high-risk code is sent to the LLM pipeline.

### B. The LangGraph Multi-Agent Pipeline
The core reasoning engine uses a cyclic graph (via LangGraph) to orchestrate three distinct AI personas:
1. **The Red Agent (Attacker):** Analyzes the high-risk code and context to identify vulnerabilities (e.g., Command Injection, SQLi, Buffer Overflows). If a defect is found, it generates a sandboxed PoC exploit script designed to explicitly trigger the vulnerability.
2. **The Blue Agent (Defender):** Receives the Red Agent's report and the original code. Its job is to generate a secure, surgically precise patch that remediates the vulnerability without altering the function's signature or breaking backward compatibility.
3. **The Judge Agent (Evaluator):** Acts as the objective referee. It takes the Blue Agent's patch and the Red Agent's exploit and coordinates the verification process in an isolated environment. If a patch fails validation, it provides the error logs back to the Blue Agent and initiates a retry loop (up to 3 attempts).

### C. Secure Docker Sandbox Verification
A critical innovation of VulnGuard is its deterministic verification engine. The Judge Agent executes all untrusted code in a highly restricted Docker container (`docker_runner.py`). 
* **Validation Sequence:**
  1. **Build Check:** Verifies the Blue Agent's patch compiles successfully (auto-detects CMake, Maven, npm, etc.).
  2. **Regression Check:** Runs the repository's existing test suite to ensure the patch didn't break core functionality.
  3. **Dual-Pass Exploit Check:** Runs the Red Agent's exploit against the *original* code (asserting it succeeds and triggers the defect) and then against the *patched* code (asserting the exploit is now blocked).
* **Security:** The sandbox operates with dropped privileges (running as the `nobody` user), disabled networking, and memory-backed `tmpfs` mounts to safely execute potentially malicious Red Agent exploits.

### D. Multi-File & Cross-File Resolution
Real-world vulnerabilities rarely exist in a vacuum. VulnGuard traces import statements and cross-file dependencies to build a comprehensive context window. The sandbox mounts the entire workspace so that cross-file vulnerabilities (e.g., untrusted input accepted in `main.py` but executed in `utils.py`) can be successfully compiled and exploited during the Judge Agent's validation phase.

### E. Real-Time Dashboard (FastAPI + React)
A modern, dynamic web interface provides real-time observability into the pipeline.
* **Live Agent Feed:** Streams WebSocket events showing exactly what the Red, Blue, and Judge agents are thinking and doing.
* **Scan Metrics:** Tracks total scans, vulnerability discovery rates, and patch success rates.
* **Interactive UI:** Allows users to drag-and-drop files for immediate analysis.

## 3. Technology Stack
* **AI/LLM Orchestration:** LangGraph, LiteLLM (supporting Groq, OpenAI, Anthropic models).
* **Machine Learning:** Scikit-learn, Joblib (Random Forest/XGBoost for triage).
* **Static Analysis:** Tree-sitter (Multi-language AST parsing).
* **Backend:** Python, FastAPI, WebSockets.
* **Frontend:** React, Vite, Tailwind CSS, Framer Motion.
* **Execution Environment:** Docker SDK for Python.

## 4. Why This Approach Matters (Academic Value)
1. **Zero False Positives:** By requiring a functional PoC exploit that successfully executes in a sandbox, VulnGuard guarantees that the vulnerabilities it flags are real and exploitable.
2. **Closed-Loop Remediation:** It doesn't just alert the developer; it provides a mathematically/programmatically verified patch.
3. **Cost Efficiency:** The ML Triage layer prevents expensive LLMs from wasting compute on mundane, safe code, creating a pipeline that is both highly accurate and economically viable at scale.
