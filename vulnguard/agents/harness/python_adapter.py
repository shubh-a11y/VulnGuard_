"""Python harness adapter: import the real module, call the real symbol."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any, Mapping

from vulnguard.agents.harness.base import HarnessAdapter, target_symbol


class PythonAdapter(HarnessAdapter):
    language = "python"
    display_name = "Python"
    aliases = ("py", "python3", "pythonw")
    markers = (
        r"^\s*(?:import\s+\w|from\s+[\w.]+\s+import\s)",
        r"^\s*def\s+\w+\s*\(",
        r"\bprint\s*\(",
    )
    foreign_markers = (
        r"#include\s*[<\"]",
        r"\bint\s+main\s*\(",
        r"\bpublic\s+class\b",
        r"\bconsole\.log\s*\(",
    )
    runtime_status = "verified"
    runtime_note = (
        "The sandbox copies the workspace to /tmp/workspace and runs the harness "
        "with `python3`, so the harness must import the module from the workspace, "
        "not restate it."
    )

    # ── Target resolution ────────────────────────────────────────────

    def module_and_owner(self, state: Mapping[str, Any]) -> tuple[str, str, str]:
        """Return ``(importable_module, owner, target)`` for this target.

        The module is derived from the target file's path relative to the
        repository root the sandbox mounts, so nested packages, ``src`` layouts
        and arbitrary file names all resolve without a project-specific map.
        """
        file_path = str(state.get("file_path") or "")
        target = target_symbol(state)
        module_name = Path(file_path).stem if file_path else "target_module"
        repo_root = str(state.get("repo_root") or "")

        if file_path and repo_root:
            try:
                relative = Path(file_path).resolve().relative_to(Path(repo_root).resolve())
                module_name = ".".join(relative.with_suffix("").parts)
                if module_name.endswith(".__init__"):
                    module_name = module_name.removesuffix(".__init__")
            except (ValueError, OSError):
                pass
        elif file_path:
            # Single-file upload without a repository: import by bare module name.
            module_name = Path(file_path).stem

        owner = target
        try:
            source = Path(file_path).read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source)
            for node in tree.body:
                if isinstance(node, ast.ClassDef) and any(
                    isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and child.name == target
                    for child in node.body
                ):
                    owner = node.name
                    break
        except (OSError, SyntaxError):
            pass

        return module_name, owner, target

    def shape(self) -> str:
        return (
            "import os\n"
            "from <workspace_module> import <target>\n\n"
            "# Call the target exactly as the application would.\n"
            "<target>(<malicious input>)\n\n"
            "if <observable side effect, e.g. os.path.exists('/tmp/vulnguard_probe')>:\n"
            "    print(\"VULNGUARD_POC_SUCCESS\")"
        )

    def workspace_target_instruction(self, state: Mapping[str, Any]) -> str:
        module_name, owner, target = self.module_and_owner(state)
        if owner == target:
            return f"Use `from {module_name} import {target}` and invoke `{target}`."
        return (
            f"Use `from {module_name} import {owner}`, instantiate `{owner}`, "
            f"and invoke its `{target}` method."
        )

    def prerequisite_notes(self, vulnerability_type: str) -> tuple[str, ...]:
        return (
            "Import only the standard library plus modules already present in the "
            "workspace; a third-party package that is not installed fails before the "
            "exploit runs.",
            "If the target opens a database or file by a fixed path, create that "
            "prerequisite at that path inside the harness instead of editing the target.",
        )

    def execution_command(self, exploit_path: str) -> str:
        return f"python3 {exploit_path}"

    # ── Validation ───────────────────────────────────────────────────

    def validation_error(self, report: Any, state: Mapping[str, Any]) -> str | None:
        harness = getattr(report, "exploit_code_harness", None) or ""
        try:
            tree = ast.parse(harness)
        except SyntaxError:
            return "the Python exploit harness is not valid syntax"

        module_name, owner, target = self.module_and_owner(state)

        if target and any(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == target
            for node in ast.walk(tree)
        ):
            return f"the harness redefines target '{target}' instead of importing it"

        imports_target = any(
            isinstance(node, ast.ImportFrom)
            and node.module == module_name
            and any(alias.name in {owner, "*"} for alias in node.names)
            for node in ast.walk(tree)
        ) or any(
            isinstance(node, ast.Import)
            and any(alias.name == module_name for alias in node.names)
            for node in ast.walk(tree)
        )
        if not imports_target:
            return f"the harness must import '{owner}' from workspace module '{module_name}'"

        expected = getattr(report, "expected_stdout_regex", None)
        if expected:
            if re.fullmatch(r"[A-Za-z0-9_ -]+", expected):
                embedded_marker = any(
                    expected in node.value and node.value.strip() != expected
                    for node in ast.walk(tree)
                    if isinstance(node, ast.Constant) and isinstance(node.value, str)
                )
                if embedded_marker:
                    return (
                        "the success marker is embedded in exploit input, causing "
                        "false positives"
                    )

            for handler in (
                node for node in ast.walk(tree) if isinstance(node, ast.ExceptHandler)
            ):
                catches_any = handler.type is None or (
                    isinstance(handler.type, ast.Name)
                    and handler.type.id in {"Exception", "BaseException"}
                )
                if not catches_any:
                    continue
                strings = (
                    node.value
                    for statement in handler.body
                    for node in ast.walk(statement)
                    if isinstance(node, ast.Constant) and isinstance(node.value, str)
                )
                try:
                    if any(re.search(expected, value) for value in strings):
                        return (
                            "the harness reports success for any exception, causing "
                            "false positives"
                        )
                except re.error:
                    return "expected_stdout_regex is not a valid regular expression"

        return None
