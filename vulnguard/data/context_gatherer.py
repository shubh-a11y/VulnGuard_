"""
Context gatherer & dependency slicer.

Extracts imports, custom type definitions, caller/callee signatures,
global variables, and macro definitions to build a context bundle for
agent prompts.

Guardrails: circular import protection (EC-6.1), dynamic import
detection (EC-6.2), FFI detection (EC-6.3), token budget enforcement (EC-6.4).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from vulnguard.config import cfg

logger = logging.getLogger(__name__)

# ── Regex patterns for dependency detection ───────────────────────────────

# C/C++ includes
_C_INCLUDE = re.compile(r'^\s*#\s*include\s*[<"](.+?)[>"]', re.MULTILINE)

# Python imports
_PY_IMPORT = re.compile(
    r"^\s*(?:from\s+([\w.]+)\s+import\s+(.+)|import\s+([\w., ]+))",
    re.MULTILINE,
)

# Java imports
_JAVA_IMPORT = re.compile(r"^\s*import\s+([\w.*]+)\s*;", re.MULTILINE)

# JavaScript require/import
_JS_IMPORT = re.compile(
    r"""(?:^\s*import\s+.+?\s+from\s+['"](.+?)['"]|"""
    r"""(?:require|import)\s*\(\s*['"](.+?)['"]\s*\))""",
    re.MULTILINE,
)

# Dynamic import detection (EC-6.2)
_DYNAMIC_IMPORT = re.compile(
    r"(?:importlib\.import_module|__import__|Class\.forName|"
    r"require\s*\(\s*[^'\"\s]|eval\s*\()",
    re.MULTILINE,
)

# FFI detection (EC-6.3)
_FFI_PATTERNS = re.compile(
    r"(?:ctypes\.(?:CDLL|cdll|windll)|cffi\.FFI|"
    r"JNI_OnLoad|napi_|PyObject\s*\*|Py_Initialize)",
    re.MULTILINE,
)

# C/C++ macros
_MACRO_DEF = re.compile(r"^\s*#\s*define\s+(\w+)(?:\(.*?\))?\s*(.*?)$", re.MULTILINE)

# Struct/class/typedef/enum definitions
_TYPE_DEF = re.compile(
    r"(?:(?:typedef\s+)?(?:struct|class|enum|union)\s+(\w+)\s*\{)",
    re.MULTILINE,
)

# Function signatures (simplified — C-style and Python def)
_FUNC_SIG = re.compile(
    r"(?:(?:[\w*&]+\s+)+(\w+)\s*\([^)]*\)\s*\{|"  # C/C++ function definition
    r"def\s+(\w+)\s*\([^)]*\)\s*(?:->.*?)?:)",  # Python function definition
    re.MULTILINE,
)

# Approximate token counting (1 token ≈ 4 chars for English/code)
_CHARS_PER_TOKEN = 4


@dataclass
class ContextBundle:
    """Extracted dependency context for a function."""

    imports: list[str] = field(default_factory=list)
    type_definitions: list[str] = field(default_factory=list)
    caller_signatures: list[str] = field(default_factory=list)
    callee_signatures: list[str] = field(default_factory=list)
    global_variables: list[str] = field(default_factory=list)
    macro_definitions: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    token_count: int = 0
    truncated: bool = False

    def to_prompt_text(self) -> str:
        """Render context as text for inclusion in LLM prompts."""
        sections: list[str] = []

        if self.imports:
            sections.append("=== IMPORTS ===\n" + "\n".join(self.imports))
        if self.type_definitions:
            sections.append("=== TYPE DEFINITIONS ===\n" + "\n".join(self.type_definitions))
        if self.caller_signatures:
            sections.append("=== CALLERS ===\n" + "\n".join(self.caller_signatures))
        if self.callee_signatures:
            sections.append("=== CALLEES ===\n" + "\n".join(self.callee_signatures))
        if self.macro_definitions:
            sections.append("=== MACROS ===\n" + "\n".join(self.macro_definitions))
        if self.global_variables:
            sections.append("=== GLOBALS ===\n" + "\n".join(self.global_variables))
        if self.warnings:
            sections.append("=== WARNINGS ===\n" + "\n".join(self.warnings))
        if self.truncated:
            sections.append("[CONTEXT TRUNCATED — token budget exceeded]")

        text = "\n\n".join(sections)
        self.token_count = len(text) // _CHARS_PER_TOKEN
        return text

    def to_dict(self) -> dict:
        """Serialize for LangGraph state."""
        return {
            "imports": self.imports,
            "type_definitions": self.type_definitions,
            "caller_signatures": self.caller_signatures,
            "callee_signatures": self.callee_signatures,
            "global_variables": self.global_variables,
            "macro_definitions": self.macro_definitions,
            "warnings": self.warnings,
            "token_count": self.token_count,
            "truncated": self.truncated,
        }


# ── Extraction engine ─────────────────────────────────────────────────────

def gather_context(
    func_code: str,
    file_path: Optional[Path] = None,
    repo_root: Optional[Path] = None,
    language: str = "c",
    token_budget: Optional[int] = None,
) -> ContextBundle:
    """Extract dependency context for a target function.

    Args:
        func_code: Source code of the target function.
        file_path: Path to the file containing the function (for cross-file scanning).
        repo_root: Repository root (for traversing imports).
        language: Programming language.
        token_budget: Max tokens for the context bundle. Defaults to config.

    Returns:
        ContextBundle with all gathered dependencies and warnings.
    """
    budget = token_budget or cfg.agent.context_token_budget
    ctx = ContextBundle()
    visited: set[str] = set()  # EC-6.1: circular import protection

    # ── 1. Extract imports from function's file ───────────
    file_content = ""
    if file_path and file_path.exists():
        try:
            file_content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            ctx.warnings.append(f"Could not read file: {exc}")

    ctx.imports = _extract_imports(file_content or func_code, language)

    # ── 2. Dynamic import detection (EC-6.2) ──────────────
    if _DYNAMIC_IMPORT.search(func_code):
        ctx.warnings.append(
            "DYNAMIC_IMPORT_DETECTED: This function uses dynamic imports. "
            "The following context may be incomplete."
        )

    # ── 3. FFI detection (EC-6.3) ─────────────────────────
    if _FFI_PATTERNS.search(func_code):
        ctx.warnings.append(
            "FFI_CONTEXT_DETECTED: This function uses foreign function interface (FFI) calls. "
            "Native code context may be missing."
        )

    # ── 4. Extract type definitions ───────────────────────
    ctx.type_definitions = _extract_type_defs(file_content or func_code)

    # ── 5. Extract macro definitions ──────────────────────
    ctx.macro_definitions = _extract_macros(file_content or func_code)

    # ── 6. Extract function signatures (callers/callees) ──
    if file_content:
        all_func_names = _extract_function_names(file_content)
        # Callees: functions referenced in func_code
        ctx.callee_signatures = [
            sig for name, sig in all_func_names if name in func_code and sig not in func_code[:50]
        ]

    # ── 7. Cross-file import resolution (limited depth) ───
    if repo_root and file_path:
        _resolve_imports(
            ctx, repo_root, file_path, language, visited, depth=0, max_depth=3
        )

    # ── 8. Token budget enforcement (EC-6.4) ──────────────
    _enforce_token_budget(ctx, budget)

    return ctx


# ── Helpers ───────────────────────────────────────────────────────────────

def _extract_imports(code: str, language: str) -> list[str]:
    """Extract import statements based on language."""
    if language in ("c", "cpp"):
        return [f"#include <{m.group(1)}>" for m in _C_INCLUDE.finditer(code)]
    elif language == "python":
        results = []
        for m in _PY_IMPORT.finditer(code):
            if m.group(1):
                results.append(f"from {m.group(1)} import {m.group(2)}")
            elif m.group(3):
                results.append(f"import {m.group(3)}")
        return results
    elif language == "java":
        return [f"import {m.group(1)};" for m in _JAVA_IMPORT.finditer(code)]
    elif language in ("javascript", "typescript"):
        results = []
        for m in _JS_IMPORT.finditer(code):
            path = m.group(1) or m.group(2)
            results.append(f"import ... from '{path}'")
        return results
    return []


def _extract_type_defs(code: str) -> list[str]:
    """Extract struct/class/enum/typedef definitions."""
    results = []
    for m in _TYPE_DEF.finditer(code):
        name = m.group(1)
        # Grab the definition (up to closing brace, capped at 20 lines)
        start = m.start()
        depth = 0
        end = start
        for i, ch in enumerate(code[start:], start):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        snippet = code[start : min(end + 1, start + 2000)]
        lines = snippet.splitlines()
        if len(lines) > 20:
            lines = lines[:20] + ["  // ... truncated"]
        results.append("\n".join(lines))
    return results


def _extract_macros(code: str) -> list[str]:
    """Extract #define macro definitions."""
    return [m.group(0).strip() for m in _MACRO_DEF.finditer(code)]


def _extract_function_names(code: str) -> list[tuple[str, str]]:
    """Extract (name, signature_line) tuples from code."""
    results = []
    for m in _FUNC_SIG.finditer(code):
        name = m.group(1) or m.group(2)
        if name:
            results.append((name, m.group(0).strip()))
    return results


def _resolve_imports(
    ctx: ContextBundle,
    repo_root: Path,
    file_path: Path,
    language: str,
    visited: set[str],
    depth: int,
    max_depth: int,
) -> None:
    """Recursively resolve imported files up to max_depth (EC-6.1)."""
    if depth >= max_depth:
        return

    file_key = str(file_path.resolve())
    if file_key in visited:
        ctx.warnings.append(f"CIRCULAR_IMPORT: {file_path.name} (depth {depth})")
        return
    visited.add(file_key)

    for imp in ctx.imports:
        resolved = _resolve_import_path(imp, file_path, repo_root, language)
        if resolved and resolved.exists() and str(resolved.resolve()) not in visited:
            try:
                content = resolved.read_text(encoding="utf-8", errors="replace")
                # Extract type definitions from imported file
                imported_types = _extract_type_defs(content)
                ctx.type_definitions.extend(imported_types[:5])  # Cap per file
            except Exception:
                pass


def _resolve_import_path(
    import_str: str, source_file: Path, repo_root: Path, language: str
) -> Optional[Path]:
    """Attempt to resolve an import statement to a file path."""
    if language in ("c", "cpp"):
        # Extract path from #include <foo.h> or #include "foo.h"
        m = re.search(r'[<"](.+?)[>"]', import_str)
        if m:
            rel = m.group(1)
            # Check relative to source file first, then repo root
            for base in [source_file.parent, repo_root]:
                candidate = base / rel
                if candidate.exists():
                    return candidate
    elif language == "python":
        # Convert dotted module to path
        m = re.match(r"(?:from\s+|import\s+)([\w.]+)", import_str)
        if m:
            parts = m.group(1).replace(".", "/")
            for suffix in [".py", "/__init__.py"]:
                candidate = repo_root / (parts + suffix)
                if candidate.exists():
                    return candidate
    return None


def _enforce_token_budget(ctx: ContextBundle, budget: int) -> None:
    """Truncate context to fit within token budget (EC-6.4).

    Priority: imports > type_defs > callees > macros > globals > callers
    """
    text = ctx.to_prompt_text()
    current_tokens = len(text) // _CHARS_PER_TOKEN

    if current_tokens <= budget:
        ctx.token_count = current_tokens
        return

    # Truncate lowest-priority sections first
    priority_fields = [
        "caller_signatures",
        "global_variables",
        "macro_definitions",
        "callee_signatures",
        "type_definitions",
    ]

    for field_name in priority_fields:
        items = getattr(ctx, field_name)
        while items:
            items.pop()
            text = ctx.to_prompt_text()
            current_tokens = len(text) // _CHARS_PER_TOKEN
            if current_tokens <= budget:
                ctx.truncated = True
                ctx.token_count = current_tokens
                return

    ctx.truncated = True
    ctx.token_count = current_tokens
