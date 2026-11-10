"""Java harness adapter (experimental sandbox runtime)."""

from __future__ import annotations

from typing import Any, Mapping

from vulnguard.agents.harness.base import HarnessAdapter, target_symbol


class JavaAdapter(HarnessAdapter):
    language = "java"
    display_name = "Java"
    aliases = ("jvm",)
    markers = (
        r"\bpublic\s+(?:final\s+)?class\b",
        r"\bpublic\s+static\s+void\s+main\s*\(",
    )
    foreign_markers = (
        r"#include\s*[<\"]",
        r"^\s*def\s+\w+\s*\(",
        r"\bconsole\.log\s*\(",
        r"\brequire\s*\(",
    )
    runtime_status = "experimental"
    runtime_note = (
        "The sandbox compiles with `javac` and runs `java`; the image must provide "
        "a JDK. Until that is confirmed, Java harnesses are generated and validated "
        "but not reported as security-validated."
    )
    requires_entry_point = True

    def shape(self) -> str:
        return (
            "public class Exploit {\n"
            "    public static void main(String[] args) throws Exception {\n"
            "        <TargetClass> target = new <TargetClass>();\n"
            "        target.<target>(<malicious input>);\n"
            "        System.out.println(\"VULNGUARD_POC_SUCCESS\");\n"
            "    }\n"
            "}"
        )

    def workspace_target_instruction(self, state: Mapping[str, Any]) -> str:
        target = target_symbol(state) or "<target>"
        return (
            "Compile the harness on the classpath of the uploaded sources and call "
            f"`{target}` on the real class that owns it. Do not copy the target body."
        )

    def prerequisite_notes(self, vulnerability_type: str) -> tuple[str, ...]:
        return (
            "Use only the JDK standard library; add no Maven/Gradle dependencies.",
            "The class must be named `Exploit` in a file the sandbox compiles.",
        )

    def execution_command(self, exploit_path: str) -> str:
        return (
            f"javac {exploit_path} && echo VULNGUARD_EXECUTION_STARTED && "
            "java -cp . Exploit"
        )

    def validation_error(self, report: Any, state: Mapping[str, Any]) -> str | None:
        import re

        harness = getattr(report, "exploit_code_harness", None) or ""
        if not re.search(r"\bclass\s+\w+", harness):
            return "the Java harness declares no class"
        if not re.search(r"\bstatic\s+void\s+main\s*\(", harness):
            return "the Java harness has no `static void main` entry point"
        target = target_symbol(state)
        if target and not re.search(rf"\b{re.escape(target)}\b", harness):
            return f"the harness does not invoke target '{target}'"
        return None
