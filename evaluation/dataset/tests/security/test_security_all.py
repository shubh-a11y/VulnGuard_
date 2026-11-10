"""
Pytest runner for all security test harnesses across the 30 benchmark cases.
"""

import sys
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from evaluation.dataset.harness import run_security_test
from evaluation.scripts.validate_dataset import load_manifest


MANIFEST_PATH = REPO_ROOT / "evaluation" / "dataset" / "manifest.csv"


def get_all_cases():
    if not MANIFEST_PATH.exists():
        return []
    manifest = load_manifest(MANIFEST_PATH)
    return [(c["case_id"], c["ground_truth"], REPO_ROOT / c["source_path"]) for c in manifest]


@pytest.mark.parametrize("case_id,ground_truth,source_path", get_all_cases())
def test_case_security(case_id, ground_truth, source_path):
    assert source_path.exists(), f"Source file does not exist: {source_path}"
    res = run_security_test(case_id, source_path)
    assert res.passed, f"Harness execution error for {case_id}: {res.error}"

    if ground_truth == "vulnerable":
        assert res.vulnerability_demonstrated, (
            f"Vulnerability was NOT demonstrated on vulnerable fixture {case_id}. Evidence: {res.evidence}"
        )
    else:
        assert not res.vulnerability_demonstrated, (
            f"Security flaw unexpectedly demonstrated on safe control {case_id}. Evidence: {res.evidence}"
        )
