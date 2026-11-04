"""
Baseline 1: Traditional SAST tool wrapper.

Wraps Cppcheck (C/C++) and Semgrep (multi-language) for benchmark comparison.
Feature-flagged — gracefully skips if tools are not installed.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class SASTFinding:
    """Normalized SAST finding."""

    tool: str
    file: str
    line: int
    rule_id: str
    severity: str
    message: str


@dataclass
class SASTResult:
    """Result from a SAST scan."""

    tool: str
    findings: list[SASTFinding] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    available: bool = True
    error: str = ""


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


# ── Cppcheck ──────────────────────────────────────────────────────────────

def run_cppcheck(target_path: str, timeout: int = 120) -> SASTResult:
    """Run Cppcheck on C/C++ files.

    Args:
        target_path: File or directory to scan.
        timeout: Max execution time in seconds.
    """
    if not _tool_available("cppcheck"):
        return SASTResult(tool="cppcheck", available=False, error="cppcheck not installed")

    start = time.time()
    try:
        proc = subprocess.run(
            [
                "cppcheck",
                "--enable=all",
                "--template={file}:{line}:{severity}:{id}:{message}",
                "--quiet",
                target_path,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = proc.stderr  # Cppcheck outputs to stderr

        findings = []
        for line in output.splitlines():
            parts = line.split(":", 4)
            if len(parts) >= 5:
                findings.append(
                    SASTFinding(
                        tool="cppcheck",
                        file=parts[0],
                        line=int(parts[1]) if parts[1].isdigit() else 0,
                        severity=parts[2],
                        rule_id=parts[3],
                        message=parts[4],
                    )
                )

        return SASTResult(tool="cppcheck", findings=findings, elapsed_seconds=time.time() - start)

    except subprocess.TimeoutExpired:
        return SASTResult(tool="cppcheck", elapsed_seconds=timeout, error="timeout")
    except Exception as exc:
        return SASTResult(tool="cppcheck", error=str(exc))


# ── Semgrep ───────────────────────────────────────────────────────────────

def run_semgrep(target_path: str, timeout: int = 120) -> SASTResult:
    """Run Semgrep with auto-detected rules.

    Args:
        target_path: File or directory to scan.
        timeout: Max execution time in seconds.
    """
    if not _tool_available("semgrep"):
        return SASTResult(tool="semgrep", available=False, error="semgrep not installed")

    start = time.time()
    try:
        proc = subprocess.run(
            [
                "semgrep",
                "--config", "auto",
                "--json",
                "--quiet",
                target_path,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        findings = []
        if proc.stdout:
            try:
                data = json.loads(proc.stdout)
                for result in data.get("results", []):
                    findings.append(
                        SASTFinding(
                            tool="semgrep",
                            file=result.get("path", ""),
                            line=result.get("start", {}).get("line", 0),
                            rule_id=result.get("check_id", ""),
                            severity=result.get("extra", {}).get("severity", "INFO"),
                            message=result.get("extra", {}).get("message", ""),
                        )
                    )
            except json.JSONDecodeError:
                pass

        return SASTResult(tool="semgrep", findings=findings, elapsed_seconds=time.time() - start)

    except subprocess.TimeoutExpired:
        return SASTResult(tool="semgrep", elapsed_seconds=timeout, error="timeout")
    except Exception as exc:
        return SASTResult(tool="semgrep", error=str(exc))


def run_all_sast(target_path: str) -> list[SASTResult]:
    """Run all available SAST tools."""
    return [run_cppcheck(target_path), run_semgrep(target_path)]
