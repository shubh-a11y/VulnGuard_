"""
Tests for the eWASH cross-file context extractor and bug marker injection.

Validates:
  - Bug marker injection on affected lines
  - Python skeleton extraction from source files
  - Cross-file dependency resolution
  - Token budget enforcement
"""

import textwrap
from pathlib import Path

import pytest


# ── Bug marker tests ──────────────────────────────────────────────────────

class TestBugMarkerInjection:
    """Test <START_BUG> / <END_BUG> marker injection."""

    def test_single_line_marker(self):
        from vulnguard.data.context_extractor import inject_bug_markers

        code = textwrap.dedent("""\
            def foo():
                x = 1
                y = eval(x)
                return y
        """)
        result = inject_bug_markers(code, [3])
        assert "// <START_BUG>" in result
        assert "// <END_BUG>" in result
        # The marker should wrap line 3 (0-indexed: line 2)
        lines = result.splitlines()
        start_idx = next(i for i, l in enumerate(lines) if "<START_BUG>" in l)
        end_idx = next(i for i, l in enumerate(lines) if "<END_BUG>" in l)
        assert start_idx < end_idx

    def test_contiguous_lines_single_block(self):
        from vulnguard.data.context_extractor import inject_bug_markers

        code = "line1\nline2\nline3\nline4\nline5"
        result = inject_bug_markers(code, [2, 3, 4])
        # Should produce a single START/END block, not three separate ones
        assert result.count("<START_BUG>") == 1
        assert result.count("<END_BUG>") == 1

    def test_no_affected_lines(self):
        from vulnguard.data.context_extractor import inject_bug_markers

        code = "def foo():\n    return 1"
        result = inject_bug_markers(code, [])
        assert result == code
        result2 = inject_bug_markers(code, None)
        assert result2 == code

    def test_out_of_range_lines_ignored(self):
        from vulnguard.data.context_extractor import inject_bug_markers

        code = "line1\nline2\nline3"
        result = inject_bug_markers(code, [99, 100])
        assert "<START_BUG>" not in result


# ── Python skeleton extraction tests ─────────────────────────────────────

class TestPythonSkeleton:
    """Test skeleton extraction from Python source files."""

    def test_extracts_class_and_methods(self):
        from vulnguard.data.context_extractor import _extract_python_skeleton

        source = textwrap.dedent("""\
            class Database:
                conn = None

                def __init__(self):
                    self.conn = sqlite3.connect(':memory:')

                def query(self, sql: str) -> list:
                    return self.conn.execute(sql).fetchall()

                def close(self):
                    self.conn.close()

            def standalone_func(x: int) -> int:
                return x + 1
        """)
        sigs = _extract_python_skeleton(source)
        assert any("class Database" in s for s in sigs)
        assert any("def __init__" in s for s in sigs)
        assert any("def query" in s for s in sigs)
        assert any("def close" in s for s in sigs)
        assert any("def standalone_func" in s for s in sigs)

    def test_handles_syntax_errors_gracefully(self):
        from vulnguard.data.context_extractor import _extract_python_skeleton

        result = _extract_python_skeleton("def broken(:\n    pass")
        assert result == []


# ── Class context extraction tests ────────────────────────────────────────

class TestClassContext:
    """Test class field and peer signature extraction."""

    def test_extracts_peer_signatures(self):
        from vulnguard.data.context_extractor import _extract_python_class_context

        source = textwrap.dedent("""\
            class Processor:
                def __init__(self):
                    self.db = Database()

                def process(self, data: str):
                    self.db.query(data)

                def validate(self, data: str) -> bool:
                    return len(data) > 0
        """)
        fields, peers = _extract_python_class_context(source, "process")
        # Should find peer method 'validate' (not 'process' itself)
        assert any("validate" in p for p in peers)
        assert not any("process" in p for p in peers)

    def test_extracts_init_fields(self):
        from vulnguard.data.context_extractor import _extract_python_class_context

        source = textwrap.dedent("""\
            class Service:
                def __init__(self):
                    self.db = Database()
                    self.cache = {}

                def run(self):
                    pass
        """)
        fields, peers = _extract_python_class_context(source, "run")
        assert any("self.db" in f for f in fields)
        assert any("self.cache" in f for f in fields)

    def test_function_not_in_class(self):
        from vulnguard.data.context_extractor import _extract_python_class_context

        source = "def standalone():\n    pass"
        fields, peers = _extract_python_class_context(source, "standalone")
        assert fields == []
        assert peers == []


# ── Cross-file context extraction tests ───────────────────────────────────

class TestCrossFileContext:
    """Test the full cross-file context extraction on the taint_flow test case."""

    def test_extracts_cross_file_context(self, tmp_path):
        """Use a synthetic multi-file project to test cross-file extraction."""
        from vulnguard.data.context_extractor import extract_cross_file_context

        # Create a synthetic multi-file project
        (tmp_path / "database.py").write_text(textwrap.dedent("""\
            import sqlite3

            class Database:
                def __init__(self):
                    self.conn = sqlite3.connect(':memory:')

                def update_user_status(self, new_status: str):
                    query = f"UPDATE users SET status = '{new_status}' WHERE id = 1"
                    self.conn.execute(query)
        """))

        (tmp_path / "processor.py").write_text(textwrap.dedent("""\
            from database import Database

            class DataProcessor:
                def __init__(self):
                    self.db = Database()

                def process(self, data: str):
                    transformed = data.strip().lower()
                    self.db.update_user_status(transformed)
        """))

        # Extract context for the 'process' function in processor.py
        func_code = textwrap.dedent("""\
            def process(self, data: str):
                transformed = data.strip().lower()
                self.db.update_user_status(transformed)
        """)

        ctx = extract_cross_file_context(
            func_code=func_code,
            func_name="process",
            file_path=tmp_path / "processor.py",
            repo_root=tmp_path,
            language="python",
            affected_lines=[3],
        )

        # Should have extracted the import
        assert any("database" in imp.lower() for imp in ctx.relevant_imports)

        # Should have cross-file skeleton from database.py
        assert len(ctx.cross_file_skeletons) > 0

        # Prompt text should be non-empty
        prompt = ctx.to_prompt_text()
        assert len(prompt) > 0

    def test_non_python_returns_warning(self, tmp_path):
        from vulnguard.data.context_extractor import extract_cross_file_context

        (tmp_path / "test.c").write_text("int main() { return 0; }")

        ctx = extract_cross_file_context(
            func_code="int main() { return 0; }",
            func_name="main",
            file_path=tmp_path / "test.c",
            repo_root=tmp_path,
            language="c",
        )
        assert any("not yet supported" in w for w in ctx.warnings)
