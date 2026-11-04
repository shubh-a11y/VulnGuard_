"""
Static feature extractor for code vulnerability triage.

Extracts 7 features per function using lizard, tree-sitter, and radon.
All parser calls are wrapped in try-except with timeout fallbacks (EC-5.3).
"""

from __future__ import annotations

import logging
import re
import signal
import sys
import textwrap
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

from vulnguard.config import cfg

logger = logging.getLogger(__name__)

# Feature names in consistent order for ML pipeline
FEATURE_NAMES = [
    "loc",
    "cyclomatic_complexity",
    "ast_max_depth",
    "parameter_count",
    "maintainability_index",
    "nested_block_depth",
    "is_template",
    # Security-specific keyword features
    "unsafe_func_count",
    "memory_op_count",
    "input_func_count",
    "pointer_arith_count",
    "unchecked_return_count",
    "string_op_count",
]

# Defaults when parsing fails
_DEFAULTS = {
    "loc": 0,
    "cyclomatic_complexity": 1,
    "ast_max_depth": 0,
    "parameter_count": 0,
    "maintainability_index": 50.0,
    "nested_block_depth": 0,
    "is_template": 0,
    "unsafe_func_count": 0,
    "memory_op_count": 0,
    "input_func_count": 0,
    "pointer_arith_count": 0,
    "unchecked_return_count": 0,
    "string_op_count": 0,
}

# ── Security keyword patterns — C/C++ ─────────────────────────────────────

# Unsafe C/C++ functions known to cause buffer overflows, format strings, etc.
_UNSAFE_FUNCS = re.compile(
    r"\b(?:strcpy|strcat|sprintf|vsprintf|gets|scanf|sscanf|fscanf|"
    r"realpath|getwd|strtok|mktemp|tmpnam)\s*\("
)

# Memory allocation/deallocation (potential use-after-free, double-free)
_MEMORY_OPS = re.compile(
    r"\b(?:malloc|calloc|realloc|free|alloca|mmap|munmap|"
    r"new\s+|delete\s+|delete\[\])\s*[\(;]"
)

# Input/external data functions (taint sources)
_INPUT_FUNCS = re.compile(
    r"\b(?:fgets|fread|recv|recvfrom|read|getenv|getchar|"
    r"fgetc|getline|accept|listen|input\s*\()\s*\("
)

# Pointer arithmetic (potential out-of-bounds)
_POINTER_ARITH = re.compile(
    r"(?:\*\s*\(.*?[+\-]|\[.*?[+\-].*?\]|\+\+\s*\*|\*.*?\+\+)"
)

# String manipulation without bounds (potential overflow)
_STRING_OPS = re.compile(
    r"\b(?:strncpy|strncat|snprintf|memcpy|memmove|memset|bcopy|bzero)\s*\("
)


# ── Security keyword patterns — Python ────────────────────────────────────

# Dangerous eval/exec/deserialization (code injection, RCE)
_PY_UNSAFE_FUNCS = re.compile(
    r"\b(?:eval|exec|compile|execfile|__import__)\s*\("
)

# Unsafe deserialization (arbitrary code execution)
_PY_DESERIALIZATION = re.compile(
    r"\b(?:pickle\.loads?|cPickle\.loads?|shelve\.open|"
    r"yaml\.load|yaml\.unsafe_load|marshal\.loads?|"
    r"jsonpickle\.decode)\s*\("
)

# Command/OS injection vectors
_PY_INJECTION = re.compile(
    r"\b(?:os\.system|os\.popen|subprocess\.call|subprocess\.Popen|"
    r"subprocess\.run|subprocess\.check_output|"
    r"commands\.getoutput|commands\.getstatusoutput)\s*\("
)

# Taint sources — user/external input
_PY_TAINT_SOURCES = re.compile(
    r"\b(?:request\.form|request\.args|request\.values|request\.json|"
    r"request\.data|request\.get_json|"
    r"os\.environ|sys\.argv|input)\s*[\.\[\(]"
)

# SQL injection patterns (string formatting in queries)
_PY_SQL_INJECTION = re.compile(
    r"(?:execute|executemany|raw|cursor\.execute)\s*\(|"
    r"(?:SELECT|INSERT|UPDATE|DELETE).*(?:%s|\{.*?\}|%\s*\()"
)

# Insecure file/path handling
_PY_FILE_OPS = re.compile(
    r"\b(?:open\s*\(|tempfile\.mktemp|os\.chmod|os\.makedirs)\s*\("
)


@dataclass
class FeatureResult:
    """Extraction result for a single function."""

    features: dict[str, float] = field(default_factory=lambda: dict(_DEFAULTS))
    parse_errors: list[str] = field(default_factory=list)

    @property
    def vector(self) -> np.ndarray:
        """Feature vector in canonical order."""
        return np.array([self.features[k] for k in FEATURE_NAMES], dtype=np.float32)


# ── Timeout helper (Unix-only; Windows falls back to no timeout) ──────────

class _ParseTimeout(Exception):
    pass


def _timeout_handler(signum, frame):
    raise _ParseTimeout("Parser timed out")


def _with_timeout(func, *args, timeout_sec: int = 5):
    """Run *func* with a timeout. Returns None on timeout (caller uses default)."""
    if sys.platform == "win32":
        # signal.alarm not available on Windows — run without timeout
        return func(*args)
    old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
    signal.alarm(timeout_sec)
    try:
        return func(*args)
    except _ParseTimeout:
        return None
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


# ── Macro stripping (Section 4.1) ────────────────────────────────────────

_MACRO_RE = re.compile(
    r"^\s*#\s*(define|ifdef|ifndef|endif|if|elif|else|undef|pragma|include)\b.*$",
    re.MULTILINE,
)


def strip_macros(code: str) -> str:
    """Remove C/C++ preprocessor directives for cleaner parsing."""
    return _MACRO_RE.sub("", code)


_TEMPLATE_RE = re.compile(r"\btemplate\s*<")


# ── Individual extractors ─────────────────────────────────────────────────

def _extract_lizard(code: str) -> dict:
    """LOC, cyclomatic complexity, parameter count via lizard."""
    import lizard

    analysis = lizard.analyze_file.analyze_source_code("input.c", code)
    if not analysis.function_list:
        # Treat entire code as one function
        return {
            "loc": max(len(code.splitlines()), 1),
            "cyclomatic_complexity": 1,
            "parameter_count": 0,
        }
    fn = analysis.function_list[0]
    return {
        "loc": fn.nloc,
        "cyclomatic_complexity": fn.cyclomatic_complexity,
        "parameter_count": len(fn.parameters),
    }


def _extract_tree_sitter_depth(code: str) -> dict:
    """AST max depth and nested block depth via tree-sitter."""
    import tree_sitter_c as tsc
    from tree_sitter import Language, Parser

    parser = Parser(Language(tsc.language()))
    tree = parser.parse(code.encode("utf-8"))

    max_depth = 0
    max_block_depth = 0
    block_types = frozenset({
        "compound_statement",
        "if_statement",
        "for_statement",
        "while_statement",
        "switch_statement",
        "case_statement",
    })

    def walk(node, depth=0, block_depth=0):
        nonlocal max_depth, max_block_depth
        max_depth = max(max_depth, depth)
        is_block = node.type in block_types
        bd = block_depth + (1 if is_block else 0)
        max_block_depth = max(max_block_depth, bd)
        for child in node.children:
            walk(child, depth + 1, bd)

    walk(tree.root_node)
    return {"ast_max_depth": max_depth, "nested_block_depth": max_block_depth}


def _extract_maintainability(code: str) -> dict:
    """Maintainability Index approximation.

    Uses Halstead-based formula:
        MI = max(0, (171 - 5.2*ln(V) - 0.23*CC - 16.2*ln(LOC)) * 100/171)
    Falls back to a simple heuristic when full Halstead volume isn't available.
    """
    import math

    lines = code.splitlines()
    loc = max(len(lines), 1)
    # Rough Halstead volume proxy: total operator+operand tokens
    tokens = code.split()
    volume = max(len(tokens), 1)
    # Cyclomatic complexity proxy
    cc = code.count("if") + code.count("for") + code.count("while") + code.count("case") + 1

    try:
        mi = max(0.0, (171 - 5.2 * math.log(volume) - 0.23 * cc - 16.2 * math.log(loc)) * 100 / 171)
    except ValueError:
        mi = 50.0
    return {"maintainability_index": round(mi, 2)}


# ── Security keyword feature extraction ───────────────────────────────────

def _extract_security_keywords(code: str, language: str = "c") -> dict:
    """Count security-relevant patterns in source code.

    These features give the ML model semantic signal about vulnerability-prone
    patterns that structural features (LOC, complexity) completely miss.

    Dispatches to Python-specific or C/C++-specific regex sets based on language.
    """
    if language in ("python",):
        return _extract_security_keywords_python(code)
    else:
        return _extract_security_keywords_c(code)


def _extract_security_keywords_c(code: str) -> dict:
    """C/C++ security keyword extraction."""
    return {
        "unsafe_func_count": len(_UNSAFE_FUNCS.findall(code)),
        "memory_op_count": len(_MEMORY_OPS.findall(code)),
        "input_func_count": len(_INPUT_FUNCS.findall(code)),
        "pointer_arith_count": len(_POINTER_ARITH.findall(code)),
        "unchecked_return_count": _count_unchecked_returns(code),
        "string_op_count": len(_STRING_OPS.findall(code)),
    }


def _extract_security_keywords_python(code: str) -> dict:
    """Python security keyword extraction.

    Maps Python-specific patterns to the same 6 feature slots used by C/C++,
    so the downstream ML model consumes the same feature vector shape.
    """
    return {
        # eval/exec/compile → maps to unsafe_func_count
        "unsafe_func_count": len(_PY_UNSAFE_FUNCS.findall(code)),
        # pickle/yaml/marshal deserialization → maps to memory_op_count
        "memory_op_count": len(_PY_DESERIALIZATION.findall(code)),
        # request.form, os.environ, input() → maps to input_func_count
        "input_func_count": len(_PY_TAINT_SOURCES.findall(code)),
        # os.system, subprocess → maps to pointer_arith_count (reused slot)
        "pointer_arith_count": len(_PY_INJECTION.findall(code)),
        # SQL injection patterns → maps to unchecked_return_count (reused slot)
        "unchecked_return_count": len(_PY_SQL_INJECTION.findall(code)),
        # open(), tempfile.mktemp → maps to string_op_count (reused slot)
        "string_op_count": len(_PY_FILE_OPS.findall(code)),
    }


def _count_unchecked_returns(code: str) -> int:
    """Count calls to functions whose return values are not checked.

    Heuristic: lines with malloc/calloc/realloc NOT preceded by 'if' or '='.
    """
    count = 0
    lines = code.splitlines()
    alloc_pattern = re.compile(r"\b(?:malloc|calloc|realloc)\s*\(")
    for i, line in enumerate(lines):
        if alloc_pattern.search(line):
            stripped = line.strip()
            # If the line doesn't assign the result or check it, it's unchecked
            if not any(op in stripped for op in ["=", "if", "assert", "return"]):
                count += 1
    return count


# ── Public API ────────────────────────────────────────────────────────────

def extract_features(code: str, language: str = "c") -> FeatureResult:
    """Extract all 13 features from a code snippet.

    Features:
        7 structural: LOC, cyclomatic complexity, AST max depth, parameter count,
                      maintainability index, nested block depth, is_template
        6 security:   unsafe_func_count, memory_op_count, input_func_count,
                      pointer_arith_count, unchecked_return_count, string_op_count

    Args:
        code: Source code string (single function or file).
        language: Programming language hint ("c", "cpp", "python", etc.).

    Returns:
        FeatureResult with feature dict and any parse errors.
    """
    result = FeatureResult()
    timeout = cfg.triage.parse_timeout_seconds

    # Template detection (EC-5.5)
    result.features["is_template"] = int(bool(_TEMPLATE_RE.search(code)))

    # Strip macros for C/C++ before parsing
    clean_code = strip_macros(code) if language in ("c", "cpp") else code

    # ── lizard ────────────────────────────────────────────
    try:
        lizard_feats = _with_timeout(_extract_lizard, clean_code, timeout_sec=timeout)
        if lizard_feats:
            result.features.update(lizard_feats)
        else:
            result.parse_errors.append("lizard: timeout")
    except Exception as exc:
        result.parse_errors.append(f"lizard: {exc}")
        # Fallback LOC
        result.features["loc"] = len(code.splitlines())

    # ── tree-sitter (C/C++ only) ──────────────────────────
    if language in ("c", "cpp"):
        try:
            ts_feats = _with_timeout(_extract_tree_sitter_depth, clean_code, timeout_sec=timeout)
            if ts_feats:
                result.features.update(ts_feats)
            else:
                result.parse_errors.append("tree-sitter: timeout")
        except Exception as exc:
            result.parse_errors.append(f"tree-sitter: {exc}")

    # ── maintainability ───────────────────────────────────
    try:
        mi_feats = _extract_maintainability(clean_code)
        result.features.update(mi_feats)
    except Exception as exc:
        result.parse_errors.append(f"maintainability: {exc}")

    # ── security keyword features ─────────────────────────
    try:
        sec_feats = _extract_security_keywords(code, language=language)  # Use original code (with macros)
        result.features.update(sec_feats)
    except Exception as exc:
        result.parse_errors.append(f"security_keywords: {exc}")

    return result


def extract_features_batch(
    code_list: list[str],
    language: str = "c",
    show_progress: bool = True,
) -> list[FeatureResult]:
    """Extract features for a batch of code snippets."""
    from tqdm import tqdm

    iterator = tqdm(code_list, desc="Extracting features", disable=not show_progress)
    return [extract_features(code, language) for code in iterator]
