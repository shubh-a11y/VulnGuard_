"""JavaScript / Node.js harness adapter (experimental sandbox runtime)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Sequence

from vulnguard.agents.harness.base import HarnessAdapter, target_symbol


class JavaScriptAdapter(HarnessAdapter):
    language = "javascript"
    display_name = "JavaScript"
    aliases = ("js", "node", "nodejs", "jsx", "ts", "typescript", "mjs", "cjs")
    markers = (
        r"\b(?:const|let|var|function|class)\b",
        r"\brequire\s*\(",
        r"\bconsole\.log\s*\(",
    )
    foreign_markers = (
        r"#include\s*[<\"]",
        r"^\s*def\s+\w+\s*\(",
        r"^\s*(?:import|from)\s+[\w.]+(?:\s+import\s|$)",
        r"\bpublic\s+(?:static\s+)?class\b",
        r"\bSystem\.out\.print",
    )
    runtime_status = "experimental"
    runtime_note = (
        "The sandbox runs the harness with `node`; the sandbox image must provide "
        "Node.js. Until that is confirmed for a deployment, JavaScript harnesses "
        "are generated and validated but not reported as security-validated."
    )

    def shape(self) -> str:
        return (
            "const target = require('./<workspace_module>');\n\n"
            "const result = target.<target>(<malicious input>);\n"
            "if (<observable condition>) {\n"
            "  console.log('VULNGUARD_POC_SUCCESS');\n"
            "}"
        )

    def workspace_target_instruction(self, state: Mapping[str, Any]) -> str:
        file_path = str(state.get("file_path") or "")
        module = Path(file_path).stem if file_path else "<workspace_module>"
        target = target_symbol(state) or "<target>"
        return (
            f"`require()` (or `import`) the workspace module `{module}` and invoke "
            f"the real export `{target}`; never re-implement the target."
        )

    def prerequisite_notes(self, vulnerability_type: str) -> tuple[str, ...]:
        return (
            "Use only Node.js built-ins (`fs`, `os`, `path`, `child_process`, "
            "`http`) and modules that already exist in the workspace.",
            "Create temporary artifacts under `os.tmpdir()`; the sandbox has no "
            "network access and a read-only root filesystem.",
        )

    def execution_command(self, exploit_path: str) -> str:
        return f"echo VULNGUARD_EXECUTION_STARTED && node {exploit_path}"

    def validation_error(self, report: Any, state: Mapping[str, Any]) -> str | None:
        import re

        harness = getattr(report, "exploit_code_harness", None) or ""
        if not re.search(r"\brequire\s*\(|\bimport\s+", harness):
            return "the JavaScript harness does not require/import the workspace module"
        if not re.search(r"\bconsole\.log\s*\(|\bprocess\.stdout\.write\s*\(", harness):
            return "the JavaScript harness has no observable output call"

        file_path = str(state.get("file_path") or "")
        module = Path(file_path).stem if file_path else ""
        if module and module not in harness and not re.search(
            r"\brequire\s*\(\s*['\"]\./", harness
        ):
            return f"the harness does not load workspace module '{module}'"

        target = target_symbol(state)
        if target and not re.search(rf"\b{re.escape(target)}\b", harness):
            return f"the harness does not invoke target '{target}'"
        return None
