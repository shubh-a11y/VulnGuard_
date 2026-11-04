"""
AST Span Patcher — reliably replaces function code via exact byte offsets.
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def _clean_patch_code(new_code: str) -> str:
    """Normalize LLM output so it can be spliced verbatim."""
    cleaned_code = new_code.strip()
    if cleaned_code.startswith("```"):
        lines = cleaned_code.splitlines()
        if len(lines) > 2 and lines[-1].strip() == "```":
            cleaned_code = "\n".join(lines[1:-1])
    return cleaned_code


def apply_patch(
    file_path: str,
    start_byte: int,
    end_byte: int,
    new_code: str,
    *,
    backup_dir: Path | None = None,
) -> tuple[Path, Path | None]:
    """Apply a patch using a backup/restore path.

    The original file bytes are backed up before any write, so a failed/invalid
    patch can be rolled back. The backup name is timestamped to avoid collisions.
    """
    """
    Replaces the exact byte span in a file with the new patched code.
    This avoids the flakiness of LLM-generated git-diffs.

    The original file bytes are copied to a timestamped backup next to the target
    before any write is attempted, so failed/invalid patches can be restored
    automatically.

    Args:
        file_path: The absolute or relative path to the file to modify.
        start_byte: The start byte of the original function span.
        end_byte: The end byte of the original function span.
        new_code: The raw string of the new function code.
        backup_dir: Optional directory for backups. Defaults to a sibling backup
                    folder next to the target file.

    Returns:
        (target_path, backup_path_or_None)
    """
    path = Path(file_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Cannot patch missing file: {path}")

    original_bytes = path.read_bytes()

    if start_byte < 0 or end_byte > len(original_bytes) or start_byte > end_byte:
        raise ValueError(f"Invalid byte span [{start_byte}, {end_byte}) for file of size {len(original_bytes)}")

    cleaned_code = _clean_patch_code(new_code)
    new_bytes = cleaned_code.encode("utf-8")

    backup_dir = backup_dir or path.parent / f".{path.name}.vulnguard_backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup_name = f"{path.name}.{int(time.time() * 1_000_000):016d}.bak"
    backup_path = backup_dir / backup_name

    try:
        backup_path.write_bytes(original_bytes)
    except Exception as exc:
        logger.warning("Could not write backup %s: %s", backup_path, exc)
        backup_path = None

    before = original_bytes[:start_byte]
    after = original_bytes[end_byte:]
    patched_bytes = before + new_bytes + after

    path.write_bytes(patched_bytes)
    logger.info(
        "Successfully spliced %d bytes into %s at [%d:%d] (backup=%s)",
        len(new_bytes),
        path.name,
        start_byte,
        end_byte,
        backup_path,
    )
    return path, backup_path


def restore_backup(backup_path: Path, target_path: str) -> Path:
    """Restore a target file from a previously written backup.

    This is the rollback primitive used by the post-Judge writeback path when
    post-write validation fails.
    """
    target = Path(target_path).resolve()
    original_bytes = backup_path.read_bytes()
    target.write_bytes(original_bytes)
    logger.info("Restored %s from backup %s", target.name, backup_path.name)
    return target


def apply_patch_with_validation(
    file_path: str,
    start_byte: int,
    end_byte: int,
    new_code: str,
    *,
    validate: callable,
    backup_dir: Path | None = None,
) -> dict[str, Any]:
    """Apply a patch, run a validator, and restore the backup on failure.

    This is the public writeback primitive used after the Judge agent passes.
    The validator receives the patched file path and must return (ok, reason).
    If it fails, the pre-write backup is restored automatically.
    """
    """
    Apply a patch, run a validator, and restore the backup on failure.

    This is the public writeback primitive used after the Judge agent passes.
    The validator receives the patched file path and must return (ok, reason).
    If it fails, the pre-write backup is restored automatically.

    Returns a result dict suitable for the evaluation writeback counters.
    """
    target, backup = apply_patch(file_path, start_byte, end_byte, new_code, backup_dir=backup_dir)
    ok, reason = validate(str(target))
    if not ok:
        if backup and backup.exists():
            restore_backup(backup, file_path)
            logger.warning(

                "Post-write validation failed (%s). Restored from %s",
                reason,
                backup.name,
            )
            return {
                "succeeded": False,
                "restored": True,
                "reason": reason,
                "target": str(target),
                "backup": str(backup) if backup else None,
            }
        return {
            "succeeded": False,
            "restored": False,
            "reason": reason,
            "target": str(target),
            "backup": str(backup) if backup else None,
        }
    return {
        "succeeded": True,
        "restored": False,
        "reason": "ok",
        "target": str(target),
        "backup": str(backup) if backup else None,
    }

