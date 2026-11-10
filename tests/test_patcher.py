"""
Tests for vulnguard.sandbox.patcher — verifying AST span replacement,
timestamped backups, rollback behavior, and validation.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from vulnguard.sandbox.patcher import (
    _clean_patch_code,
    apply_patch,
    apply_patch_with_validation,
    restore_backup,
)


def test_clean_patch_code():
    assert _clean_patch_code("  def foo(): pass  ") == "def foo(): pass"
    markdown_wrapped = "```python\ndef foo():\n    return 42\n```"
    assert _clean_patch_code(markdown_wrapped) == "def foo():\n    return 42"


def test_apply_patch_basic(tmp_path: Path):
    target = tmp_path / "sample.py"
    original_code = "def old_func():\n    return 1\n"
    target.write_text(original_code, encoding="utf-8")

    # Replace 'return 1' (bytes 20..28) with 'return 42'
    start = original_code.index("return 1")
    end = start + len("return 1")
    new_code = "return 42"

    patched_file, backup = apply_patch(
        str(target),
        start,
        end,
        new_code,
        backup_dir=tmp_path / "backups",
    )

    assert patched_file.exists()
    assert backup is not None
    assert backup.exists()
    assert backup.read_text(encoding="utf-8") == original_code

    new_content = patched_file.read_text(encoding="utf-8")
    assert "return 42" in new_content
    assert "return 1" not in new_content


def test_apply_patch_invalid_span(tmp_path: Path):
    target = tmp_path / "sample.py"
    target.write_text("hello world", encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid byte span"):
        apply_patch(str(target), 50, 10, "foo")

    with pytest.raises(ValueError, match="Invalid byte span"):
        apply_patch(str(target), -1, 5, "foo")

    with pytest.raises(ValueError, match="Invalid byte span"):
        apply_patch(str(target), 0, 100, "foo")


def test_restore_backup(tmp_path: Path):
    target = tmp_path / "target.py"
    backup = tmp_path / "target.bak"
    target.write_text("modified", encoding="utf-8")
    backup.write_text("original", encoding="utf-8")

    restored = restore_backup(backup, str(target))
    assert restored.read_text(encoding="utf-8") == "original"


def test_apply_patch_with_validation_success(tmp_path: Path):
    target = tmp_path / "code.py"
    original = "x = 1\ny = 2\n"
    target.write_text(original, encoding="utf-8")

    start = original.index("y = 2")
    end = start + len("y = 2")
    replacement = "y = 99"

    def validator(path: str) -> tuple[bool, str]:
        content = Path(path).read_text(encoding="utf-8")
        if "y = 99" in content:
            return True, "ok"
        return False, "missing update"

    result = apply_patch_with_validation(
        str(target),
        start,
        end,
        replacement,
        validate=validator,
        backup_dir=tmp_path / "backups",
    )

    assert result["succeeded"] is True
    assert result["restored"] is False
    assert "y = 99" in target.read_text(encoding="utf-8")


def test_apply_patch_with_validation_failure_triggers_rollback(tmp_path: Path):
    target = tmp_path / "code.py"
    original = "x = 1\ny = 2\n"
    target.write_text(original, encoding="utf-8")

    start = original.index("y = 2")
    end = start + len("y = 2")
    replacement = "y = 99"

    def failing_validator(path: str) -> tuple[bool, str]:
        return False, "syntax error simulated"

    result = apply_patch_with_validation(
        str(target),
        start,
        end,
        replacement,
        validate=failing_validator,
        backup_dir=tmp_path / "backups",
    )

    assert result["succeeded"] is False
    assert result["restored"] is True
    assert result["reason"] == "syntax error simulated"
    # Target should be restored to original bytes!
    assert target.read_text(encoding="utf-8") == original

