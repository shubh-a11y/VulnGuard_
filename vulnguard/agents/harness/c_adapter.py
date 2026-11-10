"""C and C++ harness adapters.

The sandbox compiles the workspace target separately (renaming ``main``) with
AddressSanitizer and links it with the harness, so the harness declares the
target prototype and never includes or restates the target source.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Mapping

from vulnguard.agents.harness.base import HarnessAdapter, target_symbol


class CAdapter(HarnessAdapter):
    language = "c"
    display_name = "C"
    aliases = ("h", "c99", "gnu-c")
    markers = (r"#include\s*[<\"]", r"\bint\s+main\s*\(")
    foreign_markers = (
        r"^\s*(?:import|from)\s+\w",
        r"^\s*def\s+\w+\s*\(",
        r"\bconsole\.log\s*\(",
        r"\bpublic\s+class\b",
    )
    runtime_status = "verified"
    runtime_note = (
        "The sandbox compiles the workspace target with gcc and AddressSanitizer, "
        "renames its main, links it with the harness, and runs the binary."
    )
    requires_entry_point = True

    def __init__(self, *, language: str | None = None, compiler: str = "gcc") -> None:
        if language:
            self.language = language
            self.display_name = {"cpp": "C++"}.get(language, language.upper())
        self.compiler = compiler

    def shape(self) -> str:
        marker = (
            '    std::cout << "VULNGUARD_POC_SUCCESS" << std::endl;'
            if self.language == "cpp"
            else '    printf("VULNGUARD_POC_SUCCESS\\n");'
        )
        includes = (
            "#include <iostream>\n#include <string>"
            if self.language == "cpp"
            else "#include <stdio.h>\n#include <string.h>"
        )
        return (
            f"{includes}\n\n"
            "/* Prototype of the target as defined in the workspace file. */\n"
            "<return_type> <target>(<parameters>);\n\n"
            "int main(void) {\n"
            "    <payload setup>\n"
            "    <target>(<malicious input>);\n"
            f"{marker}\n"
            "    return 0;\n"
            "}"
        )

    def workspace_target_instruction(self, state: Mapping[str, Any]) -> str:
        target = target_symbol(state) or "<target>"
        return (
            f"Declare the real prototype `{target}(...)` exactly as it appears in "
            "the workspace source and call it from `main`. Do not `#include` the "
            "target `.c` file and do not copy its body."
        )

    def prerequisite_notes(self, vulnerability_type: str) -> tuple[str, ...]:
        notes = [
            "No third-party libraries: the sandbox links only the target object and "
            "the C standard library.",
            "A crash is the proof for memory defects; do not catch signals, and do "
            "not print the marker after a normal return that did not traverse the "
            "defect.",
        ]
        if self.language == "cpp":
            notes.append("Compile as C++ and use only the C++ standard library.")
        return tuple(notes)

    def execution_command(self, exploit_path: str) -> str:
        return (
            f"{self.compiler} {exploit_path} -o exploit_bin && echo "
            "VULNGUARD_EXECUTION_STARTED && ./exploit_bin"
        )

    def validation_error(self, report: Any, state: Mapping[str, Any]) -> str | None:
        harness = getattr(report, "exploit_code_harness", None) or ""
        if not re.search(r"\bint\s+main\s*\(", harness):
            return f"the {self.display_name} harness has no int main() entry point"

        target = target_symbol(state)
        if target:
            file_name = Path(str(state.get("file_path") or "")).name
            if file_name and re.search(
                rf'#include\s*"{re.escape(file_name)}"', harness
            ):
                return (
                    f"the harness includes target source '{file_name}' instead of "
                    "linking the workspace object"
                )
            if not re.search(rf"\b{re.escape(target)}\s*\(", harness):
                return f"the harness does not invoke target '{target}'"
        return None


class CppAdapter(CAdapter):
    language = "cpp"
    display_name = "C++"
    aliases = ("c++", "cc", "cxx", "hpp", "hxx")

    def __init__(self) -> None:
        super().__init__(compiler="g++")

