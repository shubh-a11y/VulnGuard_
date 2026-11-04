"""Tree-sitter function extraction for VulnGuard-supported languages."""

from __future__ import annotations

import importlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

from tree_sitter import Language, Node, Parser


@dataclass
class CodeUnit:
    """A function or method extracted from a source file."""

    file_path: str
    function_name: str
    class_name: Optional[str]
    start_byte: int
    end_byte: int
    start_line: int
    end_line: int
    raw_source: str
    language: str
    imports: list[str] = field(default_factory=list)
    callees: list[str] = field(default_factory=list)


_EXTENSIONS = {
    ".py": "python",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".java": "java",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
}

_MODULES = {
    "python": "tree_sitter_python",
    "c": "tree_sitter_c",
    "cpp": "tree_sitter_cpp",
    "java": "tree_sitter_java",
    "javascript": "tree_sitter_javascript",
}

_IGNORED_DIRECTORIES = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
}

_FUNCTION_NODES = {
    "python": {"function_definition"},
    "c": {"function_definition"},
    "cpp": {"function_definition"},
    "java": {"method_declaration", "constructor_declaration"},
    "javascript": {
        "function_declaration",
        "generator_function_declaration",
        "method_definition",
        "variable_declarator",
    },
}

_IMPORT_NODES = {
    "python": {"import_statement", "import_from_statement"},
    "c": {"preproc_include"},
    "cpp": {"preproc_include"},
    "java": {"import_declaration"},
    "javascript": {"import_statement"},
}

_CLASS_NODES = {
    "python": {"class_definition"},
    "cpp": {"class_specifier", "struct_specifier"},
    "java": {"class_declaration", "interface_declaration", "enum_declaration"},
    "javascript": {"class_declaration"},
}


def supported_extensions() -> tuple[str, ...]:
    return tuple(_EXTENSIONS)


def detect_language(file_path: str | Path) -> str | None:
    return _EXTENSIONS.get(Path(file_path).suffix.lower())


def read_source_file(file_path: str | Path) -> str:
    """Decode source bytes without normalizing line endings used by byte offsets."""
    return Path(file_path).read_bytes().decode("utf-8", errors="replace")


def iter_source_files(root: str | Path) -> Iterator[Path]:
    """Yield supported source files while pruning generated/vendor directories."""
    root_path = Path(root)
    if root_path.is_file():
        if detect_language(root_path):
            yield root_path
        return
    for directory, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [name for name in dirnames if name not in _IGNORED_DIRECTORIES]
        for filename in filenames:
            path = Path(directory) / filename
            if detect_language(path):
                yield path


def _walk(node: Node) -> Iterator[Node]:
    yield node
    for child in node.children:
        yield from _walk(child)


def _text(node: Node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _parser_for(language: str) -> Parser:
    module_name = _MODULES.get(language)
    if not module_name:
        raise ValueError(f"Unsupported language: {language}")
    module = importlib.import_module(module_name)
    return Parser(Language(module.language()))


def validate_syntax(source_code: str, language: str) -> tuple[bool, str]:
    """Validate complete source text with the configured Tree-sitter grammar."""
    source = source_code.encode("utf-8")
    root = _parser_for(language).parse(source).root_node
    if not root.has_error:
        return True, ""
    invalid = next(
        (node for node in _walk(root) if node.is_error or node.is_missing),
        root,
    )
    line, column = invalid.start_point
    return False, f"Syntax error near line {line + 1}, column {column + 1}"


def _identifier(node: Node | None, source: bytes) -> str | None:
    if node is None:
        return None
    preferred = {
        "identifier",
        "field_identifier",
        "property_identifier",
        "type_identifier",
        "operator_name",
        "destructor_name",
    }
    if node.type in preferred:
        return _text(node, source)
    for child in node.children:
        found = _identifier(child, source)
        if found:
            return found
    return None


def _function_name(node: Node, source: bytes, language: str) -> str | None:
    name = node.child_by_field_name("name")
    if name is not None:
        return _text(name, source)
    if language in {"c", "cpp"}:
        return _identifier(node.child_by_field_name("declarator"), source)
    if language == "javascript" and node.type == "variable_declarator":
        value = node.child_by_field_name("value")
        if value is None or value.type not in {"arrow_function", "function_expression"}:
            return None
        return _identifier(node.child_by_field_name("name"), source)
    return None


def _class_name(node: Node, source: bytes, language: str) -> str | None:
    class_types = _CLASS_NODES.get(language, set())
    parent = node.parent
    while parent:
        if parent.type in class_types:
            return _identifier(parent.child_by_field_name("name"), source)
        parent = parent.parent
    return None


def _callees(node: Node, source: bytes, language: str) -> list[str]:
    result = []
    for child in _walk(node):
        target = None
        if child.type == "call":
            target = child.child_by_field_name("function")
        elif child.type == "call_expression":
            target = child.child_by_field_name("function")
        elif language == "java" and child.type == "method_invocation":
            target = child.child_by_field_name("name")
        if target is not None:
            value = _text(target, source)
            if value not in result:
                result.append(value)
    return result


def parse_file(
    file_path: str,
    source_code: str,
    language: str | None = None,
) -> list[CodeUnit]:
    """Extract functions and methods from one supported source file."""
    resolved_language = language or detect_language(file_path)
    if not resolved_language:
        raise ValueError(f"Cannot detect language for {file_path}")

    source = source_code.encode("utf-8")
    root = _parser_for(resolved_language).parse(source).root_node
    imports = [
        _text(node, source)
        for node in _walk(root)
        if node.type in _IMPORT_NODES.get(resolved_language, set())
    ]

    units = []
    for node in _walk(root):
        if node.type not in _FUNCTION_NODES[resolved_language]:
            continue
        function_name = _function_name(node, source, resolved_language)
        if not function_name:
            continue
        units.append(
            CodeUnit(
                file_path=file_path,
                function_name=function_name,
                class_name=_class_name(node, source, resolved_language),
                start_byte=node.start_byte,
                end_byte=node.end_byte,
                start_line=node.start_point[0] + 1,
                end_line=node.end_point[0] + 1,
                raw_source=_text(node, source),
                language=resolved_language,
                imports=list(dict.fromkeys(imports)),
                callees=_callees(node, source, resolved_language),
            )
        )
    return units


def parse_python_file(file_path: str, source_code: str) -> list[CodeUnit]:
    """Backward-compatible Python parser entry point."""
    return parse_file(file_path, source_code, "python")
