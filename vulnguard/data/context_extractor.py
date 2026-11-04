"""
eWASH Context Extractor — Cross-file syntax hierarchy extraction.

Based on InferFix's "extended Widened Abstract Syntax Hierarchy" (eWASH),
this module extracts structured cross-file context to give LLM agents
the necessary multi-file awareness to fix vulnerabilities that span
across multiple files (e.g., taint flows from input_handler → processor → database).

Key capabilities:
  - Extracts class/module-level fields and method signatures from peer files
  - Follows import chains to resolve cross-file dependencies
  - Injects <START_BUG> / <END_BUG> markers around flagged lines
  - Enforces a token budget to prevent overflowing the LLM context window
"""

from __future__ import annotations

import ast
import logging
import re
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from vulnguard.config import cfg

logger = logging.getLogger(__name__)

# Approximate token counting (1 token ≈ 4 chars for code)
_CHARS_PER_TOKEN = 4


@dataclass
class CrossFileContext:
    """Structured cross-file context for a single vulnerability."""

    # The buggy function source with <START_BUG> / <END_BUG> markers injected
    marked_source: str = ""
    # Peer method signatures from the same file/class
    peer_signatures: list[str] = field(default_factory=list)
    # Class-level fields and __init__ context from the same class
    class_fields: list[str] = field(default_factory=list)
    # Cross-file dependency skeletons (import target → their signatures)
    cross_file_skeletons: dict[str, list[str]] = field(default_factory=dict)
    # Import statements relevant to the buggy function
    relevant_imports: list[str] = field(default_factory=list)
    # Warnings (e.g., unresolved imports, circular deps)
    warnings: list[str] = field(default_factory=list)
    # Estimated token count
    token_count: int = 0
    truncated: bool = False

    def to_prompt_text(self) -> str:
        """Render the eWASH context as a structured prompt section."""
        sections: list[str] = []

        if self.relevant_imports:
            sections.append(
                "=== RELEVANT IMPORTS ===\n" + "\n".join(self.relevant_imports)
            )
        if self.class_fields:
            sections.append(
                "=== CLASS FIELDS / CONSTRUCTOR ===\n"
                + "\n".join(self.class_fields)
            )
        if self.peer_signatures:
            sections.append(
                "=== PEER METHOD SIGNATURES (same file) ===\n"
                + "\n".join(self.peer_signatures)
            )
        if self.cross_file_skeletons:
            skeleton_parts = []
            for filepath, sigs in self.cross_file_skeletons.items():
                skeleton_parts.append(
                    f"--- {filepath} ---\n" + "\n".join(sigs)
                )
            sections.append(
                "=== CROSS-FILE DEPENDENCIES ===\n"
                + "\n\n".join(skeleton_parts)
            )
        if self.warnings:
            sections.append(
                "=== CONTEXT WARNINGS ===\n" + "\n".join(self.warnings)
            )
        if self.truncated:
            sections.append("[CROSS-FILE CONTEXT TRUNCATED — token budget exceeded]")

        text = "\n\n".join(sections)
        self.token_count = len(text) // _CHARS_PER_TOKEN
        return text


# ── Bug marker injection ──────────────────────────────────────────────────

def inject_bug_markers(
    code: str,
    affected_lines: list[int] | None = None,
) -> str:
    """Wrap affected lines with <START_BUG> and <END_BUG> markers.

    If affected_lines is None or empty, returns the code unchanged.

    Args:
        code: The original function source code.
        affected_lines: 1-indexed line numbers flagged by the Red Agent.

    Returns:
        Source code with bug markers injected around affected lines.
    """
    if not affected_lines:
        return code

    lines = code.splitlines()
    # Convert to 0-indexed set
    flagged = set(l - 1 for l in affected_lines if 1 <= l <= len(lines))

    if not flagged:
        return code

    result: list[str] = []
    in_bug_block = False

    for i, line in enumerate(lines):
        if i in flagged and not in_bug_block:
            result.append("// <START_BUG>")
            in_bug_block = True
        elif i not in flagged and in_bug_block:
            result.append("// <END_BUG>")
            in_bug_block = False
        result.append(line)

    # Close any trailing block
    if in_bug_block:
        result.append("// <END_BUG>")

    return "\n".join(result)


# ── Python skeleton extractor ─────────────────────────────────────────────

def _extract_python_skeleton(source: str) -> list[str]:
    """Extract a Python file's skeleton: class names, method signatures,
    module-level function signatures, and class-level field assignments.

    Returns a list of signature strings.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    signatures: list[str] = []

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.ClassDef):
            signatures.append(f"class {node.name}:")
            for item in node.body:
                if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef):
                    args = _format_args(item.args)
                    ret = ""
                    if item.returns:
                        try:
                            ret = f" -> {ast.unparse(item.returns)}"
                        except Exception:
                            pass
                    signatures.append(f"    def {item.name}({args}){ret}: ...")
                elif isinstance(item, ast.Assign):
                    for target in item.targets:
                        try:
                            signatures.append(f"    {ast.unparse(target)} = ...")
                        except Exception:
                            pass

        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            args = _format_args(node.args)
            ret = ""
            if node.returns:
                try:
                    ret = f" -> {ast.unparse(node.returns)}"
                except Exception:
                    pass
            signatures.append(f"def {node.name}({args}){ret}: ...")

    return signatures


def _format_args(args: ast.arguments) -> str:
    """Format an ast.arguments node into a parameter string."""
    parts: list[str] = []
    for arg in args.args:
        annotation = ""
        if arg.annotation:
            try:
                annotation = f": {ast.unparse(arg.annotation)}"
            except Exception:
                pass
        parts.append(f"{arg.arg}{annotation}")
    return ", ".join(parts)


def _extract_python_class_context(
    source: str, target_func_name: str
) -> tuple[list[str], list[str]]:
    """Extract class fields and peer method signatures for a function.

    If target_func_name is defined inside a class, returns:
      - class_fields: __init__ body lines and class-level assignments
      - peer_sigs: signatures of other methods in that class

    Returns (class_fields, peer_signatures).
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return [], []

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.ClassDef):
            method_names = [
                item.name
                for item in node.body
                if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef)
            ]
            if target_func_name in method_names:
                # Found the class containing our target function
                class_fields: list[str] = []
                peer_sigs: list[str] = []

                for item in node.body:
                    if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef):
                        if item.name != target_func_name:
                            args = _format_args(item.args)
                            peer_sigs.append(
                                f"def {item.name}({args}): ..."
                            )
                        if item.name == "__init__":
                            # Extract self.x = ... assignments from __init__
                            for stmt in ast.walk(item):
                                if isinstance(stmt, ast.Assign):
                                    for t in stmt.targets:
                                        if isinstance(t, ast.Attribute) and isinstance(
                                            t.value, ast.Name
                                        ) and t.value.id == "self":
                                            try:
                                                class_fields.append(
                                                    f"self.{t.attr} = {ast.unparse(stmt.value)}"
                                                )
                                            except Exception:
                                                class_fields.append(
                                                    f"self.{t.attr} = ..."
                                                )
                    elif isinstance(item, ast.Assign):
                        for t in item.targets:
                            try:
                                class_fields.append(f"{ast.unparse(t)} = ...")
                            except Exception:
                                pass

                return class_fields, peer_sigs

    return [], []


# ── Cross-file import resolution ──────────────────────────────────────────

_PY_IMPORT_RE = re.compile(
    r"^\s*(?:from\s+([\w.]+)\s+import\s+(.+)|import\s+([\w., ]+))",
    re.MULTILINE,
)


def _resolve_python_import(
    import_str: str, source_file: Path, repo_root: Path
) -> Optional[Path]:
    """Resolve a Python import string to a file path."""
    m = re.match(r"(?:from\s+|import\s+)([\w.]+)", import_str)
    if not m:
        return None
    parts = m.group(1).replace(".", "/")
    for suffix in [".py", "/__init__.py"]:
        candidate = repo_root / (parts + suffix)
        if candidate.exists():
            return candidate
    # Try relative to source file's directory
    for suffix in [".py", "/__init__.py"]:
        candidate = source_file.parent / (parts + suffix)
        if candidate.exists():
            return candidate
    return None


# ── Main extraction entry point ───────────────────────────────────────────

def extract_cross_file_context(
    func_code: str,
    func_name: str,
    file_path: Path,
    repo_root: Path,
    language: str = "python",
    affected_lines: list[int] | None = None,
    token_budget: int | None = None,
) -> CrossFileContext:
    """Extract eWASH cross-file context for a target function.

    This is the main entry point. It:
      1. Injects <START_BUG> / <END_BUG> markers on affected lines.
      2. Extracts peer method signatures and class fields from the same file.
      3. Follows imports to extract "skeletons" (signatures only) from dependency files.
      4. Enforces a token budget.

    Args:
        func_code: Source code of the target function.
        func_name: Name of the target function (for class context extraction).
        file_path: Absolute path to the source file.
        repo_root: Repository root path.
        language: Programming language (currently supports "python").
        affected_lines: 1-indexed line numbers flagged by the Red Agent.
        token_budget: Max tokens for cross-file context. Defaults to config.

    Returns:
        CrossFileContext with all gathered cross-file dependencies.
    """
    budget = token_budget or cfg.agent.context_token_budget
    ctx = CrossFileContext()

    # 1. Inject bug markers
    ctx.marked_source = inject_bug_markers(func_code, affected_lines)

    if language != "python":
        ctx.warnings.append(
            f"eWASH cross-file extraction not yet supported for {language}. "
            "Falling back to single-file context."
        )
        return ctx

    # 2. Read the full source file
    try:
        file_content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        ctx.warnings.append(f"Could not read source file: {exc}")
        return ctx

    # 3. Extract imports
    for m in _PY_IMPORT_RE.finditer(file_content):
        if m.group(1):
            ctx.relevant_imports.append(f"from {m.group(1)} import {m.group(2)}")
        elif m.group(3):
            ctx.relevant_imports.append(f"import {m.group(3)}")

    # 4. Extract class fields and peer signatures
    ctx.class_fields, ctx.peer_signatures = _extract_python_class_context(
        file_content, func_name
    )

    # 5. Follow imports and extract skeletons from dependency files
    visited: set[str] = {str(file_path.resolve())}
    for imp_str in ctx.relevant_imports:
        resolved = _resolve_python_import(imp_str, file_path, repo_root)
        if resolved and str(resolved.resolve()) not in visited:
            visited.add(str(resolved.resolve()))
            try:
                dep_content = resolved.read_text(encoding="utf-8", errors="replace")
                skeleton = _extract_python_skeleton(dep_content)
                if skeleton:
                    # Use relative path for readability
                    try:
                        rel = resolved.relative_to(repo_root)
                    except ValueError:
                        rel = resolved.name
                    ctx.cross_file_skeletons[str(rel)] = skeleton
            except Exception as exc:
                ctx.warnings.append(f"Could not read dependency {resolved.name}: {exc}")

    # 6. Enforce token budget
    _enforce_budget(ctx, budget)

    return ctx


def _enforce_budget(ctx: CrossFileContext, budget: int) -> None:
    """Truncate cross-file context to fit within token budget.

    Priority (highest to lowest):
      relevant_imports > class_fields > peer_signatures > cross_file_skeletons
    """
    text = ctx.to_prompt_text()
    current = len(text) // _CHARS_PER_TOKEN

    if current <= budget:
        ctx.token_count = current
        return

    # Truncate lowest priority first: cross-file skeletons
    skeleton_keys = list(ctx.cross_file_skeletons.keys())
    for key in reversed(skeleton_keys):
        sigs = ctx.cross_file_skeletons[key]
        while sigs:
            sigs.pop()
            text = ctx.to_prompt_text()
            current = len(text) // _CHARS_PER_TOKEN
            if current <= budget:
                ctx.truncated = True
                ctx.token_count = current
                return
        del ctx.cross_file_skeletons[key]

    # Then peer signatures
    while ctx.peer_signatures:
        ctx.peer_signatures.pop()
        text = ctx.to_prompt_text()
        current = len(text) // _CHARS_PER_TOKEN
        if current <= budget:
            ctx.truncated = True
            ctx.token_count = current
            return

    # Then class fields
    while ctx.class_fields:
        ctx.class_fields.pop()
        text = ctx.to_prompt_text()
        current = len(text) // _CHARS_PER_TOKEN
        if current <= budget:
            ctx.truncated = True
            ctx.token_count = current
            return

    ctx.truncated = True
    ctx.token_count = current
