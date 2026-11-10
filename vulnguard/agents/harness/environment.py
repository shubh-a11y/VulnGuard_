"""Repository environment probe for harness generation.

A harness is only as good as its assumptions about the repository it runs in.
This probe inspects the *actual* uploaded repository — layout, manifests,
declared dependencies, test infrastructure, database artifacts — instead of
assuming a fixed project shape. Its findings are:

* injected into the harness prompt as hard constraints, and
* recorded as explicit limitations when something the target needs is missing.

It never fabricates availability: a dependency that cannot be resolved here is
reported as unavailable rather than silently assumed present.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from functools import lru_cache
from importlib.util import find_spec
from pathlib import Path
from typing import Iterable

from vulnguard.agents.harness import get_adapter

_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    "target",
    "coverage",
    ".next",
}
_MAX_FILES = 400
_MAX_DEPTH = 3

_MANIFESTS = (
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "requirements.txt",
    "requirements-dev.txt",
    "Pipfile",
    "poetry.lock",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "tsconfig.json",
    "go.mod",
    "Cargo.toml",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "Makefile",
    "CMakeLists.txt",
    "meson.build",
)

_TEST_MARKERS = (
    "pytest.ini",
    "tox.ini",
    "noxfile.py",
    "conftest.py",
    "jest.config.js",
    "vitest.config.ts",
    "phpunit.xml",
    "CTestTestfile.cmake",
)

_SQLITE_GLOBS = ("*.db", "*.sqlite", "*.sqlite3")

_REQUIREMENT_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*(?:[<>=!~;@ ]|$)")


@dataclass(frozen=True)
class RepositoryEnvironment:
    """What a harness may assume about the repository under analysis."""

    repo_root: str
    language: str
    target_module: str
    import_roots: tuple[str, ...]
    manifests: tuple[str, ...]
    declared_dependencies: tuple[str, ...]
    missing_dependencies: tuple[str, ...]
    test_infrastructure: tuple[str, ...]
    database_signals: tuple[str, ...]
    runtime_status: str
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "repo_root": self.repo_root,
            "language": self.language,
            "target_module": self.target_module,
            "import_roots": list(self.import_roots),
            "manifests": list(self.manifests),
            "declared_dependencies": list(self.declared_dependencies),
            "missing_dependencies": list(self.missing_dependencies),
            "test_infrastructure": list(self.test_infrastructure),
            "database_signals": list(self.database_signals),
            "runtime_status": self.runtime_status,
            "limitations": list(self.limitations),
        }

    def to_prompt_text(self) -> str:
        def line(label: str, values: Iterable[str], empty: str = "none detected") -> str:
            items = list(values)
            return f"- {label}: {', '.join(items) if items else empty}"

        return "\n".join(
            [
                line("Repository root", [self.repo_root]),
                line("Target module", [self.target_module]),
                line("Import roots", self.import_roots),
                line("Build/package manifests", self.manifests),
                line("Declared dependencies", self.declared_dependencies),
                line("Unavailable dependencies", self.missing_dependencies, "none"),
                line("Test infrastructure", self.test_infrastructure),
                line("Database artifacts", self.database_signals),
                line("Sandbox runtime", [f"{self.language} ({self.runtime_status})"]),
                line("Limitations", self.limitations, "none"),
            ]
        )

    def limitations_text(self) -> str:
        return "; ".join(self.limitations)


def _walk(repo_root: Path) -> list[Path]:
    """Bounded walk: skip dependency/build directories and cap visited files."""
    visited: list[Path] = []
    for current, dirs, files in os.walk(repo_root):
        depth = len(Path(current).relative_to(repo_root).parts)
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not d.startswith(".")]
        if depth >= _MAX_DEPTH:
            dirs[:] = []
        for name in files:
            visited.append(Path(current) / name)
            if len(visited) >= _MAX_FILES:
                return visited
    return visited


def _read(path: Path, limit: int = 200_000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


def _requirement_names(text: str) -> list[str]:
    names: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-", "git+", "http")):
            continue
        match = _REQUIREMENT_LINE.match(stripped)
        if match:
            names.append(match.group(1))
    return names


def _declared_python_dependencies(files: list[Path]) -> list[str]:
    names: dict[str, None] = {}
    for path in files:
        name = path.name
        if name.startswith("requirements") and name.endswith(".txt"):
            for dep in _requirement_names(_read(path)):
                names.setdefault(dep, None)
        elif name == "pyproject.toml":
            text = _read(path)
            for block in re.findall(r"dependencies\s*=\s*\[(.*?)\]", text, re.S):
                for dep in re.findall(r"[\"']([^\"']+)[\"']", block):
                    match = _REQUIREMENT_LINE.match(dep.strip())
                    if match:
                        names.setdefault(match.group(1), None)
            poetry = re.search(r"\[tool\.poetry\.dependencies\](.*?)(?:\n\[|\Z)", text, re.S)
            if poetry:
                for dep in re.findall(r"^\s*([A-Za-z0-9_.\-]+)\s*=", poetry.group(1), re.M):
                    names.setdefault(dep, None)
        elif name == "setup.py":
            text = _read(path)
            for block in re.findall(r"install_requires\s*=\s*\[(.*?)\]", text, re.S):
                for dep in re.findall(r"[\"']([^\"']+)[\"']", block):
                    match = _REQUIREMENT_LINE.match(dep.strip())
                    if match:
                        names.setdefault(match.group(1), None)
    return sorted(names)[:40]


def _importable(module: str) -> bool:
    top_level = module.replace("-", "_").split(".")[0]
    if not top_level:
        return True
    if top_level in getattr(sys, "stdlib_module_names", frozenset()):
        return True
    try:
        return find_spec(top_level) is not None
    except (ImportError, ValueError, AttributeError):
        return False


def _target_module(repo_root: Path, file_path: Path) -> str:
    try:
        relative = file_path.resolve().relative_to(repo_root.resolve())
        module = ".".join(relative.with_suffix("").parts)
        return module.removesuffix(".__init__")
    except (ValueError, OSError):
        return file_path.stem


def _import_roots(repo_root: Path, file_path: Path) -> tuple[str, ...]:
    roots: list[str] = [str(repo_root)]
    src = repo_root / "src"
    if src.is_dir():
        roots.append(str(src))
    for parent in [file_path.parent, *file_path.parents]:
        if parent == repo_root.parent or repo_root not in parent.parents and parent != repo_root:
            break
        if (parent / "__init__.py").is_file():
            roots.append(str(parent))
    # Deduplicate while preserving the sandbox-friendly order.
    seen: set[str] = set()
    ordered: list[str] = []
    for root in roots:
        if root not in seen:
            seen.add(root)
            ordered.append(root)
    return tuple(ordered)


def _test_infrastructure(repo_root: Path, files: list[Path]) -> tuple[str, ...]:
    found: list[str] = []
    for marker in _TEST_MARKERS:
        if (repo_root / marker).is_file():
            found.append(marker)
    for directory in ("tests", "test", "spec", "__tests__"):
        if (repo_root / directory).is_dir():
            found.append(f"{directory}/")
    names = {path.name for path in files}
    if any(name.startswith("test_") and name.endswith(".py") for name in names):
        found.append("pytest-style test modules")
    elif any(name.endswith("_test.py") or name.endswith((".test.js", ".spec.js", ".test.ts"))
             for name in names):
        found.append("test modules")
    package_json = repo_root / "package.json"
    if package_json.is_file() and re.search(r'"test"\s*:', _read(package_json)):
        found.append("npm test script")
    makefile = repo_root / "Makefile"
    if makefile.is_file() and re.search(r"^test\s*:", _read(makefile), re.M):
        found.append("make test target")
    return tuple(found)


def _database_signals(repo_root: Path, files: list[Path]) -> tuple[str, ...]:
    found: list[str] = []
    for pattern in _SQLITE_GLOBS:
        for path in list(repo_root.glob(pattern))[:3]:
            found.append(path.name)
    for path in files[:120]:
        try:
            depth = len(path.relative_to(repo_root).parts)
        except ValueError:
            continue
        if depth > 2 or path.suffix.lower() not in {".py", ".js", ".ts", ".json", ".yml", ".yaml", ".env", ".example", ".cfg", ".ini", ".toml"}:
            continue
        text = _read(path, limit=80_000)
        if not text:
            continue
        if re.search(r"DATABASE_URL|SQLALCHEMY_DATABASE_URI|\"DATABASES\"|'DATABASES'", text):
            found.append(str(path.relative_to(repo_root)))
        elif re.search(r"\bsqlite3?\b", text) and re.search(r"\b(?:connect|execute)\s*\(", text):
            found.append(str(path.relative_to(repo_root)))
        elif re.search(r"mongodb|postgres(?:ql)?|mysql|redis://", text, re.I) and "database" in text.lower():
            found.append(str(path.relative_to(repo_root)))
        if len(found) >= 6:
            break
    seen: set[str] = set()
    ordered = [item for item in found if not (item in seen or seen.add(item))]
    return tuple(ordered[:6])


@lru_cache(maxsize=32)
def _probe(repo_root: str, language: str, file_path: str) -> RepositoryEnvironment:
    root = Path(repo_root) if repo_root else Path(file_path).parent
    if not root.is_dir():
        root = Path(file_path).parent
    target = Path(file_path) if file_path else root
    adapter = get_adapter(language)

    files = _walk(root) if root.is_dir() else []
    names = [path.name for path in files]

    manifests = tuple(sorted({name for name in names if name in _MANIFESTS}))[:12]
    declared = _declared_python_dependencies(files)
    missing = tuple(dep for dep in declared if not _importable(dep))[:12]
    tests = _test_infrastructure(root, files)
    database = _database_signals(root, files)

    limitations: list[str] = []
    if missing:
        limitations.append(
            "declared dependencies not importable in the analysis environment: "
            + ", ".join(missing)
            + " (the harness must not rely on them)"
        )
    if not tests:
        limitations.append(
            "no test suite detected, so the regression-test step is skipped rather than "
            "assumed to pass"
        )
    if not manifests:
        limitations.append(
            "no build/package manifest detected; the sandbox compiles or runs the target "
            "file directly"
        )
    if language in {"c", "cpp"} and not any(
        name in {"Makefile", "CMakeLists.txt", "meson.build"} for name in manifests
    ):
        limitations.append(
            f"no C/C++ build system detected for {language}; the sandbox compiles the "
            "target translation unit directly"
        )
    if adapter.runtime_status != "verified":
        limitations.append(adapter.capability_note())

    return RepositoryEnvironment(
        repo_root=str(root),
        language=language,
        target_module=_target_module(root, target),
        import_roots=_import_roots(root, target),
        manifests=manifests,
        declared_dependencies=tuple(declared),
        missing_dependencies=missing,
        test_infrastructure=tests,
        database_signals=database,
        runtime_status=adapter.runtime_status,
        limitations=tuple(limitations),
    )


def probe_repository(
    repo_root: str | Path | None,
    language: str,
    file_path: str | Path | None = None,
) -> RepositoryEnvironment:
    """Probe a repository; results are cached per (root, language, file)."""
    return _probe(str(repo_root or ""), language or "", str(file_path or ""))
