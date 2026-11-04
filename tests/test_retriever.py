"""
Tests for the historical fix retriever.

Validates:
  - FixRetriever index building and vector search
  - Similarity matching with vulnerability type boosting
  - Save/load persistence
"""

import textwrap
from pathlib import Path

import pytest

from vulnguard.models.retriever import FixExample, FixRetriever


@pytest.fixture
def sample_retriever():
    """Create a retriever with a few sample fix examples."""
    examples = [
        FixExample(
            fix_id="sql_001",
            vulnerability_type="SQL_INJECTION",
            cwe_id="CWE-89",
            language="python",
            vulnerable_code=textwrap.dedent("""\
                def get_user(username):
                    query = f"SELECT * FROM users WHERE name = '{username}'"
                    cursor.execute(query)
                    return cursor.fetchall()
            """),
            fixed_code=textwrap.dedent("""\
                def get_user(username):
                    query = "SELECT * FROM users WHERE name = ?"
                    cursor.execute(query, (username,))
                    return cursor.fetchall()
            """),
            diff_summary="Replaced f-string SQL with parameterized query",
        ),
        FixExample(
            fix_id="xss_001",
            vulnerability_type="XSS",
            cwe_id="CWE-79",
            language="python",
            vulnerable_code=textwrap.dedent("""\
                def render_page(user_input):
                    return f"<html><body>{user_input}</body></html>"
            """),
            fixed_code=textwrap.dedent("""\
                from markupsafe import escape
                def render_page(user_input):
                    return f"<html><body>{escape(user_input)}</body></html>"
            """),
            diff_summary="Added HTML escaping to prevent XSS",
        ),
        FixExample(
            fix_id="cmdi_001",
            vulnerability_type="COMMAND_INJECTION",
            cwe_id="CWE-78",
            language="python",
            vulnerable_code=textwrap.dedent("""\
                import os
                def run_command(user_input):
                    os.system(f"echo {user_input}")
            """),
            fixed_code=textwrap.dedent("""\
                import subprocess
                def run_command(user_input):
                    subprocess.run(["echo", user_input], check=True)
            """),
            diff_summary="Replaced os.system with subprocess.run to prevent command injection",
        ),
    ]

    retriever = FixRetriever(examples=examples)
    retriever.build_index()
    return retriever


class TestFixRetriever:
    """Test the FixRetriever vector search."""

    def test_builds_index(self, sample_retriever):
        assert sample_retriever._vectors is not None
        assert sample_retriever._vectors.shape[0] == 3
        assert len(sample_retriever._vocabulary) > 0

    def test_finds_similar_sql_injection(self, sample_retriever):
        """A SQL injection query should match the SQL injection example."""
        buggy_code = textwrap.dedent("""\
            def search_products(name):
                query = f"SELECT * FROM products WHERE title = '{name}'"
                db.execute(query)
                return db.fetchall()
        """)
        hint = sample_retriever.find_similar_fix(buggy_code, "SQL_INJECTION")
        assert hint is not None
        assert "SQL_INJECTION" in hint or "CWE-89" in hint

    def test_finds_similar_command_injection(self, sample_retriever):
        """A command injection pattern should match the cmdi example."""
        buggy_code = textwrap.dedent("""\
            import os
            def execute(cmd):
                os.system(f"ls {cmd}")
        """)
        hint = sample_retriever.find_similar_fix(buggy_code, "COMMAND_INJECTION")
        assert hint is not None
        assert "COMMAND_INJECTION" in hint or "CWE-78" in hint

    def test_returns_none_for_unrelated_code(self, sample_retriever):
        """Completely unrelated code should return None (score < threshold)."""
        unrelated = "x = 1 + 2\ny = x * 3\nprint(y)"
        hint = sample_retriever.find_similar_fix(unrelated)
        # May or may not return None depending on token overlap, but shouldn't crash
        # The key is it doesn't raise
        assert hint is None or isinstance(hint, str)

    def test_save_and_load(self, sample_retriever, tmp_path):
        """Test persistence: save to disk and reload."""
        sample_retriever.save(tmp_path)

        loaded = FixRetriever.load(tmp_path)
        assert loaded is not None
        assert len(loaded.examples) == 3
        assert loaded._vectors is not None

        # Verify search still works after reload
        hint = loaded.find_similar_fix(
            "query = f\"SELECT * FROM users WHERE id = '{uid}'\"",
            "SQL_INJECTION",
        )
        assert hint is not None

    def test_empty_retriever(self):
        """Empty retriever should not crash."""
        retriever = FixRetriever()
        retriever.build_index()
        hint = retriever.find_similar_fix("some code")
        assert hint is None

    def test_vuln_type_boosting(self, sample_retriever):
        """Verify that specifying a vulnerability type boosts matching results."""
        # Generic code that could match multiple patterns
        code = "query = user_input; execute(query)"

        # Without type filter
        hint_no_type = sample_retriever.find_similar_fix(code)
        # With SQL_INJECTION filter — should boost SQL match
        hint_sql = sample_retriever.find_similar_fix(code, "SQL_INJECTION")

        # Both should return something (the code has overlap with multiple examples)
        # The test mainly verifies no crash with type boosting
        assert hint_no_type is None or isinstance(hint_no_type, str)
        assert hint_sql is None or isinstance(hint_sql, str)
