"""
Environment Metadata Capture — Phase 11.1

Records git commit, branch, python runtime, OS platform, docker status,
and dependency versions without logging any credentials or secrets.
"""

from __future__ import annotations

import hashlib
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]


def _safe_cmd(cmd: list[str]) -> str:
    try:
        proc = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=5)
        return proc.stdout.strip() if proc.returncode == 0 else ""
    except Exception:
        return ""


def get_git_info() -> dict[str, str]:
    commit = _safe_cmd(["git", "rev-parse", "HEAD"]) or "unknown"
    branch = _safe_cmd(["git", "rev-parse", "--abbrev-ref", "HEAD"]) or "unknown"
    status = _safe_cmd(["git", "status", "--porcelain"])
    dirty = bool(status)
    return {
        "commit_sha": commit,
        "branch": branch,
        "is_dirty": dirty,
    }


def get_docker_info() -> dict[str, Any]:
    version = _safe_cmd(["docker", "--version"])
    is_running = False
    if version:
        ps_out = _safe_cmd(["docker", "ps", "-q"])
        is_running = True if ps_out is not None else False
    return {
        "docker_available": bool(version),
        "docker_version": version,
        "docker_daemon_active": is_running,
    }


def get_package_versions() -> dict[str, str]:
    packages = [
        "xgboost",
        "scikit-learn",
        "numpy",
        "pandas",
        "matplotlib",
        "tree-sitter",
        "langgraph",
        "langchain",
        "pytest",
        "joblib",
    ]
    versions = {}
    for pkg in packages:
        try:
            mod = __import__(pkg.replace("-", "_"))
            versions[pkg] = getattr(mod, "__version__", "unknown")
        except Exception:
            versions[pkg] = "not installed"
    return versions


def capture_environment_metadata() -> dict[str, Any]:
    manifest_path = REPO_ROOT / "evaluation" / "dataset" / "manifest.csv"
    manifest_hash = (
        hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        if manifest_path.exists()
        else "missing"
    )

    return {
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
        },
        "python": {
            "version": sys.version,
            "executable": sys.executable,
        },
        "git": get_git_info(),
        "docker": get_docker_info(),
        "packages": get_package_versions(),
        "dataset": {
            "version": "1.0.0",
            "manifest_sha256": manifest_hash,
        },
    }


if __name__ == "__main__":
    import json
    print(json.dumps(capture_environment_metadata(), indent=2))

