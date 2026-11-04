"""External, read-only probes for patch application and syntax validity.

For every recorded case with a candidate patch this driver:

  1. Splices the patch into an in-memory copy of the target file exactly the way
     the Judge does (`judge_agent._get_full_file_code`, patched=True) and runs
     the application's own `vulnguard.data.parser.validate_syntax` on it. This
     measures the *syntactic validity* of the candidate patch.
  2. Copies the fixture file to a disposable temp directory and calls the
     application's real writeback primitive
     `vulnguard.sandbox.patcher.apply_patch` with the same byte span. This
     measures whether a candidate patch can actually be applied to a workspace.

The project's original fixture is never written to: step 1 is in-memory, step 2
writes only to a temp directory that is deleted afterwards.

Usage:
    python evaluation/run-2026-10-28T-baseline/procedure/patch_probe.py --out <dir>
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
import traceback
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from vulnguard.data.parser import validate_syntax  # noqa: E402
from vulnguard.sandbox.patcher import apply_patch  # noqa: E402


def _splice(original: bytes, start: int, end: int, patch: str) -> str:
    cleaned = patch.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if len(lines) > 2 and lines[-1].strip() == "```":
            cleaned = "\n".join(lines[1:-1])
    return (original[:start] + cleaned.encode("utf-8") + original[end:]).decode(
        "utf-8", errors="replace"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    cases_dir = Path(args.cases)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    for case_file in sorted(cases_dir.glob("C*.json")):
        record = json.loads(case_file.read_text(encoding="utf-8"))
        state = record["final_state"]
        patch = state.get("patched_code")
        row = {
            "case_id": record["case_id"],
            "relative_path": record["relative_path"],
            "language": record["language"],
            "has_patch": bool(patch),
        }
        if not patch:
            rows.append(row)
            continue

        target = PROJECT_ROOT / record["relative_path"]
        original = target.read_bytes()
        start, end = state.get("start_byte"), state.get("end_byte")
        row["byte_span"] = [start, end]

        spliced = _splice(original, start, end, patch)
        ok, error = validate_syntax(spliced, record["language"])
        row["syntax_valid"] = bool(ok)
        row["syntax_error"] = None if ok else str(error)[:400]

        tmp = Path(tempfile.mkdtemp(prefix="vg_patchprobe_"))
        try:
            copy = tmp / target.name
            shutil.copy2(target, copy)
            before = copy.read_bytes()
            try:
                _, backup = apply_patch(
                    str(copy), start, end, patch, backup_dir=tmp / "backups"
                )
                row["applied"] = True
                row["apply_error"] = None
                row["file_changed"] = copy.read_bytes() != before
                row["backup_created"] = backup is not None and Path(backup).exists()
            except Exception as exc:
                row["applied"] = False
                row["apply_error"] = f"{type(exc).__name__}: {exc}"
                row["file_changed"] = copy.read_bytes() != before
                row["traceback_tail"] = traceback.format_exc().strip().splitlines()[-1]
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

        rows.append(row)
        print(
            f"{row['case_id']}: syntax_valid={row['syntax_valid']} "
            f"applied={row['applied']} apply_error={row['apply_error']}"
        )

    payload = {
        "cases": rows,
        "patches_generated": sum(1 for r in rows if r["has_patch"]),
        "syntactically_valid": sum(1 for r in rows if r.get("syntax_valid")),
        "applications_attempted": sum(1 for r in rows if r["has_patch"]),
        "applications_succeeded": sum(1 for r in rows if r.get("applied")),
    }
    (out_dir / "patch_probe.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in payload.items() if k != "cases"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
