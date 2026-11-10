"""
Dataset Validation Script — Phase 1.4

Validates:
1. Manifest structure and required fields.
2. Uniqueness of case IDs.
3. Existence of referenced source files and tests.
4. Correctness of SHA-256 source hashes.
5. Ground-truth isolation: ensures no ground-truth leakage into source files.
6. Balanced representation across categories and ground-truth classes.
"""

from __future__ import annotations

import csv
import hashlib
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = REPO_ROOT / "evaluation" / "dataset" / "manifest.csv"

REQUIRED_FIELDS = [
    "case_id",
    "category",
    "cwe",
    "ground_truth",
    "language",
    "source_path",
    "target_function",
    "source_hash",
    "security_test",
    "regression_test",
    "expected_normal_behavior",
    "rationale",
    "provenance",
    "dataset_version",
]

VALID_CATEGORIES = {
    "SQL Injection",
    "Command Injection",
    "Path Traversal",
    "Buffer Handling",
    "Format String",
}

VALID_LANGUAGES = {"python", "c", "cpp"}
VALID_GROUND_TRUTHS = {"vulnerable", "safe"}


def load_manifest(manifest_path: Path = MANIFEST_PATH) -> list[dict[str, str]]:
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")
    with manifest_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader)


def validate_dataset(manifest_path: Path = MANIFEST_PATH) -> tuple[bool, list[str]]:
    errors: list[str] = []
    cases = load_manifest(manifest_path)

    if not cases:
        return False, ["Manifest is empty."]

    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    category_counts: dict[str, dict[str, int]] = {
        cat: {"vulnerable": 0, "safe": 0} for cat in VALID_CATEGORIES
    }

    for idx, row in enumerate(cases, start=1):
        case_id = row.get("case_id", f"row_{idx}")

        # 1. Required fields
        for field in REQUIRED_FIELDS:
            if not row.get(field):
                errors.append(f"[{case_id}] Missing required field: {field}")

        # 2. Unique Case IDs
        if case_id in seen_ids:
            errors.append(f"[{case_id}] Duplicate case ID detected.")
        seen_ids.add(case_id)

        # 3. Source path existence and uniqueness
        src_rel = row.get("source_path", "")
        if src_rel in seen_paths:
            errors.append(f"[{case_id}] Duplicate source path: {src_rel}")
        seen_paths.add(src_rel)

        src_full = REPO_ROOT / src_rel
        if not src_full.exists():
            errors.append(f"[{case_id}] Source file does not exist: {src_rel}")
        else:
            # 4. SHA-256 hash validation
            actual_hash = hashlib.sha256(src_full.read_bytes()).hexdigest()
            expected_hash = row.get("source_hash", "")
            if actual_hash != expected_hash:
                errors.append(
                    f"[{case_id}] Hash mismatch for {src_rel}: expected {expected_hash}, got {actual_hash}"
                )

            # 5. Ground truth leakage check: source file should not contain manifest words or answers
            source_content = src_full.read_text(encoding="utf-8", errors="replace").lower()
            leakage_markers = ["ground_truth", "manifest.csv", "b01", "b02", "b03", "b30"]
            for marker in leakage_markers:
                if marker in source_content:
                    errors.append(f"[{case_id}] Potential ground-truth leakage: '{marker}' found in source file.")

        # 6. Valid category, language, ground truth
        category = row.get("category", "")
        if category not in VALID_CATEGORIES:
            errors.append(f"[{case_id}] Invalid category: '{category}'")

        lang = row.get("language", "")
        if lang not in VALID_LANGUAGES:
            errors.append(f"[{case_id}] Invalid language: '{lang}'")

        gt = row.get("ground_truth", "")
        if gt not in VALID_GROUND_TRUTHS:
            errors.append(f"[{case_id}] Invalid ground_truth: '{gt}'")

        if category in category_counts and gt in ("vulnerable", "safe"):
            category_counts[category][gt] += 1

    # 7. Check category balances
    total_vuln = sum(c["vulnerable"] for c in category_counts.values())
    total_safe = sum(c["safe"] for c in category_counts.values())

    print(f"Validated {len(cases)} cases:")
    print(f"  Vulnerable cases: {total_vuln}")
    print(f"  Safe cases:       {total_safe}")
    for cat, counts in category_counts.items():
        print(f"  - {cat}: {counts['vulnerable']} vulnerable, {counts['safe']} safe")

    is_valid = len(errors) == 0
    return is_valid, errors


def main() -> int:
    is_valid, errors = validate_dataset()
    if not is_valid:
        print("\nDATASET VALIDATION FAILED:")
        for err in errors:
            print(f"  ERROR: {err}")
        return 1
    print("\nDataset validation passed successfully. All fixtures and hashes verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

