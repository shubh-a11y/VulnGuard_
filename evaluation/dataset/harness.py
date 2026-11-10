"""
Independent Security and Functional Regression Test Harness for VulnGuard Benchmark.

Completely decoupled from VulnGuard: no reliance on LLM output, judge verdicts,
or internal application state. Evaluates ground truth on target files.
"""

from __future__ import annotations

import importlib.util
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class TestResult:
    passed: bool
    vulnerability_demonstrated: bool
    evidence: str
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "vulnerability_demonstrated": self.vulnerability_demonstrated,
            "evidence": self.evidence,
            "error": self.error,
        }


def _compile_c(source_path: Path, output_binary: Path, extra_flags: list[str] | None = None) -> tuple[bool, str]:
    """Compile a C file using gcc."""
    cmd = ["gcc", "-O0", str(source_path), "-o", str(output_binary)]
    if extra_flags:
        cmd.extend(extra_flags)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if proc.returncode != 0:
            return False, f"Compilation failed: {proc.stderr}"
        return True, "Compilation succeeded"
    except Exception as exc:
        return False, f"Compilation error: {exc}"


def _import_python_module(file_path: Path, module_name: str = "target_mod"):
    """Dynamically import a python file as a module."""
    spec = importlib.util.spec_from_file_location(module_name, str(file_path))
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load spec from {file_path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# SQL INJECTION (B01-B06)
# ---------------------------------------------------------------------------

def _setup_sql_users_db(db_path: Path):
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT)")
    cur.execute("INSERT INTO users VALUES (1, 'alice', 'user')")
    cur.execute("INSERT INTO users VALUES (2, 'admin', 'admin')")
    conn.commit()
    conn.close()


def _setup_sql_shop_db(db_path: Path):
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    cur.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, category TEXT, price REAL)")
    cur.execute("INSERT INTO items VALUES (1, 'Book A', 'books', 15.0)")
    cur.execute("INSERT INTO items VALUES (2, 'Laptop', 'electronics', 999.0)")
    conn.commit()
    conn.close()


def _setup_sql_orders_db(db_path: Path):
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    cur.execute("CREATE TABLE orders (order_id INTEGER PRIMARY KEY, customer TEXT, status TEXT, total REAL)")
    cur.execute("INSERT INTO orders VALUES (1, 'alice', 'completed', 50.0)")
    cur.execute("INSERT INTO orders VALUES (2, 'bob', 'cancelled', 100.0)")
    conn.commit()
    conn.close()


def run_sql_security_test(case_id: str, target_file: Path) -> TestResult:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        try:
            mod = _import_python_module(target_file, f"mod_sec_{case_id}_{time.time_ns()}")
            if case_id in ("B01", "B04"):
                _setup_sql_users_db(db_path)
                rows = mod.get_user("admin' OR '1'='1", db_path=str(db_path))
                is_vuln = len(rows) > 1
                return TestResult(
                    passed=True,
                    vulnerability_demonstrated=is_vuln,
                    evidence=f"get_user returned {len(rows)} rows: {rows}",
                )
            elif case_id in ("B02", "B05"):
                _setup_sql_shop_db(db_path)
                # Use SQL comment -- to bypass price check
                rows = mod.search_products("' OR 1=1 --", 10.0, db_path=str(db_path))
                is_vuln = any(r[1] == "Laptop" for r in rows) or len(rows) >= 2
                return TestResult(
                    passed=True,
                    vulnerability_demonstrated=is_vuln,
                    evidence=f"search_products returned {len(rows)} rows: {rows}",
                )
            elif case_id in ("B03", "B06"):
                _setup_sql_orders_db(db_path)
                try:
                    rows = mod.filter_orders("' OR '1'='1", db_path=str(db_path))
                    is_vuln = len(rows) >= 2
                    evidence = f"filter_orders returned {len(rows)} rows: {rows}"
                except ValueError as ve:
                    is_vuln = False
                    evidence = f"filter_orders rejected injection with ValueError: {ve}"
                return TestResult(
                    passed=True,
                    vulnerability_demonstrated=is_vuln,
                    evidence=evidence,
                )
            return TestResult(passed=False, vulnerability_demonstrated=False, evidence="Unknown case")
        except Exception as exc:
            return TestResult(passed=False, vulnerability_demonstrated=False, evidence=str(exc), error=str(exc))


def run_sql_regression_test(case_id: str, target_file: Path) -> TestResult:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        try:
            mod = _import_python_module(target_file, f"mod_reg_{case_id}_{time.time_ns()}")
            if case_id in ("B01", "B04"):
                _setup_sql_users_db(db_path)
                rows = mod.get_user("alice", db_path=str(db_path))
                ok = len(rows) == 1 and rows[0][1] == "alice"
                return TestResult(passed=ok, vulnerability_demonstrated=False, evidence=f"Returned {rows}")
            elif case_id in ("B02", "B05"):
                _setup_sql_shop_db(db_path)
                rows = mod.search_products("books", 20.0, db_path=str(db_path))
                ok = len(rows) == 1 and rows[0][1] == "Book A"
                return TestResult(passed=ok, vulnerability_demonstrated=False, evidence=f"Returned {rows}")
            elif case_id in ("B03", "B06"):
                _setup_sql_orders_db(db_path)
                rows = mod.filter_orders("completed", db_path=str(db_path))
                ok = len(rows) == 1 and rows[0][1] == "alice"
                return TestResult(passed=ok, vulnerability_demonstrated=False, evidence=f"Returned {rows}")
            return TestResult(passed=False, vulnerability_demonstrated=False, evidence="Unknown case")
        except Exception as exc:
            return TestResult(passed=False, vulnerability_demonstrated=False, evidence=str(exc), error=str(exc))


# ---------------------------------------------------------------------------
# COMMAND INJECTION (B07-B12)
# ---------------------------------------------------------------------------

def run_command_security_test(case_id: str, target_file: Path) -> TestResult:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        canary = Path(tmpdir) / "canary.txt"
        canary_cmd = f"echo CMDI_PWNED > \"{canary}\""
        try:
            mod = _import_python_module(target_file, f"mod_cmdi_{case_id}_{time.time_ns()}")
            if case_id in ("B07", "B10"):
                payload = f"localhost & {canary_cmd}"
                try:
                    mod.ping_host(payload)
                except Exception:
                    pass
            elif case_id in ("B08", "B11"):
                payload = f"web & {canary_cmd}"
                try:
                    mod.check_service(payload)
                except Exception:
                    pass
            elif case_id in ("B09", "B12"):
                payload = f"node1 & {canary_cmd}"
                try:
                    mod.execute_diagnostic(payload)
                except Exception:
                    pass

            is_vuln = canary.exists() and "CMDI_PWNED" in canary.read_text(encoding="utf-8", errors="replace")
            return TestResult(
                passed=True,
                vulnerability_demonstrated=is_vuln,
                evidence=f"Canary file created: {is_vuln}",
            )
        except Exception as exc:
            return TestResult(passed=False, vulnerability_demonstrated=False, evidence=str(exc), error=str(exc))


def run_command_regression_test(case_id: str, target_file: Path) -> TestResult:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        try:
            mod = _import_python_module(target_file, f"mod_cmdreg_{case_id}_{time.time_ns()}")
            if case_id in ("B07", "B10"):
                rc = mod.ping_host("localhost")
                return TestResult(passed=(rc == 0), vulnerability_demonstrated=False, evidence=f"ping returncode: {rc}")
            elif case_id in ("B08", "B11"):
                res = mod.check_service("web_server")
                ok = "web_server" in str(res)
                return TestResult(passed=ok, vulnerability_demonstrated=False, evidence=f"check_service returned: {res}")
            elif case_id in ("B09", "B12"):
                res = mod.execute_diagnostic("node1")
                ok = "node1" in str(res)
                return TestResult(passed=ok, vulnerability_demonstrated=False, evidence=f"execute_diagnostic returned: {res}")
            return TestResult(passed=False, vulnerability_demonstrated=False, evidence="Unknown case")
        except Exception as exc:
            return TestResult(passed=False, vulnerability_demonstrated=False, evidence=str(exc), error=str(exc))


# ---------------------------------------------------------------------------
# PATH TRAVERSAL (B13-B18)
# ---------------------------------------------------------------------------

def run_path_security_test(case_id: str, target_file: Path) -> TestResult:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        base_dir = Path(tmpdir) / "app_data"
        base_dir.mkdir()
        secret_file = Path(tmpdir) / "secret.txt"
        secret_file.write_text("CANARY_SECRET_DATA_TRAVERSAL_CONFIRMED", encoding="utf-8")

        try:
            if case_id in ("B13", "B16"):
                mod = _import_python_module(target_file, f"mod_path_{case_id}_{time.time_ns()}")
                try:
                    content = mod.read_user_file(str(base_dir), "../secret.txt")
                    is_vuln = "CANARY_SECRET_DATA" in content
                    evidence = f"Read secret: {content}"
                except PermissionError:
                    is_vuln = False
                    evidence = "PermissionError correctly raised"
                return TestResult(passed=True, vulnerability_demonstrated=is_vuln, evidence=evidence)

            elif case_id in ("B14", "B17"):
                mod = _import_python_module(target_file, f"mod_path_{case_id}_{time.time_ns()}")
                try:
                    content = mod.fetch_document(str(base_dir), "../secret.txt")
                    is_vuln = "CANARY_SECRET_DATA" in content
                    evidence = f"Read secret: {content}"
                except PermissionError:
                    is_vuln = False
                    evidence = "PermissionError correctly raised"
                return TestResult(passed=True, vulnerability_demonstrated=is_vuln, evidence=evidence)

            elif case_id in ("B15", "B18"):
                bin_path = Path(tmpdir) / f"path_{case_id}.exe"
                compiled, msg = _compile_c(target_file, bin_path)
                if not compiled:
                    return TestResult(passed=False, vulnerability_demonstrated=False, evidence=msg, error=msg)
                proc = subprocess.run([str(bin_path), str(base_dir), "../secret.txt"], capture_output=True, text=True, timeout=10)
                is_vuln = "CANARY_SECRET_DATA" in proc.stdout
                return TestResult(
                    passed=True,
                    vulnerability_demonstrated=is_vuln,
                    evidence=f"stdout={proc.stdout.strip()}, exit={proc.returncode}",
                )
            return TestResult(passed=False, vulnerability_demonstrated=False, evidence="Unknown case")
        except Exception as exc:
            return TestResult(passed=False, vulnerability_demonstrated=False, evidence=str(exc), error=str(exc))


def run_path_regression_test(case_id: str, target_file: Path) -> TestResult:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        base_dir = Path(tmpdir) / "app_data"
        base_dir.mkdir()
        valid_file = base_dir / "normal.txt"
        valid_file.write_text("VALID_FILE_CONTENT", encoding="utf-8")

        try:
            if case_id in ("B13", "B16"):
                mod = _import_python_module(target_file, f"mod_pathreg_{case_id}_{time.time_ns()}")
                content = mod.read_user_file(str(base_dir), "normal.txt")
                ok = content == "VALID_FILE_CONTENT"
                return TestResult(passed=ok, vulnerability_demonstrated=False, evidence=f"Read {content}")
            elif case_id in ("B14", "B17"):
                mod = _import_python_module(target_file, f"mod_pathreg_{case_id}_{time.time_ns()}")
                content = mod.fetch_document(str(base_dir), "normal.txt")
                ok = content == "VALID_FILE_CONTENT"
                return TestResult(passed=ok, vulnerability_demonstrated=False, evidence=f"Read {content}")
            elif case_id in ("B15", "B18"):
                bin_path = Path(tmpdir) / f"path_{case_id}.exe"
                compiled, msg = _compile_c(target_file, bin_path)
                if not compiled:
                    return TestResult(passed=False, vulnerability_demonstrated=False, evidence=msg, error=msg)
                proc = subprocess.run([str(bin_path), str(base_dir), "normal.txt"], capture_output=True, text=True, timeout=10)
                ok = "VALID_FILE_CONTENT" in proc.stdout
                return TestResult(passed=ok, vulnerability_demonstrated=False, evidence=proc.stdout.strip())
            return TestResult(passed=False, vulnerability_demonstrated=False, evidence="Unknown case")
        except Exception as exc:
            return TestResult(passed=False, vulnerability_demonstrated=False, evidence=str(exc), error=str(exc))


# ---------------------------------------------------------------------------
# BUFFER OVERFLOW / MEMORY SAFETY (B19-B24)
# ---------------------------------------------------------------------------

def run_memory_security_test(case_id: str, target_file: Path) -> TestResult:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        bin_path = Path(tmpdir) / f"mem_{case_id}.exe"
        compiled, msg = _compile_c(target_file, bin_path)
        if not compiled:
            return TestResult(passed=False, vulnerability_demonstrated=False, evidence=msg, error=msg)

        overflow_payload = "A" * 120
        try:
            proc = subprocess.run([str(bin_path), overflow_payload], capture_output=True, text=True, timeout=5)
            # Vulnerable cases overflow stack return address or crash (segfault 0xC0000005, abort, or long string)
            crashed = proc.returncode != 0
            overflow_printed = "A" * 70 in proc.stdout
            is_vuln = crashed or overflow_printed
            evidence = f"exit_code={proc.returncode}, stdout_len={len(proc.stdout)}, stdout={proc.stdout.strip()[:60]}"
            return TestResult(passed=True, vulnerability_demonstrated=is_vuln, evidence=evidence)
        except subprocess.TimeoutExpired:
            return TestResult(passed=True, vulnerability_demonstrated=True, evidence="Process hung on buffer overflow")
        except Exception as exc:
            return TestResult(passed=False, vulnerability_demonstrated=False, evidence=str(exc), error=str(exc))


def run_memory_regression_test(case_id: str, target_file: Path) -> TestResult:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        bin_path = Path(tmpdir) / f"mem_{case_id}.exe"
        compiled, msg = _compile_c(target_file, bin_path)
        if not compiled:
            return TestResult(passed=False, vulnerability_demonstrated=False, evidence=msg, error=msg)
        try:
            proc = subprocess.run([str(bin_path), "ValidInput"], capture_output=True, text=True, timeout=5)
            ok = proc.returncode == 0 and "ValidInput" in proc.stdout
            return TestResult(passed=ok, vulnerability_demonstrated=False, evidence=f"stdout={proc.stdout.strip()}")
        except Exception as exc:
            return TestResult(passed=False, vulnerability_demonstrated=False, evidence=str(exc), error=str(exc))


# ---------------------------------------------------------------------------
# FORMAT STRING (B25-B30)
# ---------------------------------------------------------------------------

def run_format_security_test(case_id: str, target_file: Path) -> TestResult:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        bin_path = Path(tmpdir) / f"fmt_{case_id}.exe"
        compiled, msg = _compile_c(target_file, bin_path)
        if not compiled:
            return TestResult(passed=False, vulnerability_demonstrated=False, evidence=msg, error=msg)

        fmt_payload = "%x.%x.%x.%x"
        try:
            proc = subprocess.run([str(bin_path), fmt_payload], capture_output=True, text=True, timeout=5)
            combined_output = proc.stdout + proc.stderr
            has_literal = "%x.%x.%x.%x" in combined_output
            hex_pattern = bool(re.search(r"[0-9a-fA-F]+\.[0-9a-fA-F]+", combined_output))

            is_vuln = hex_pattern and not has_literal
            return TestResult(
                passed=True,
                vulnerability_demonstrated=is_vuln,
                evidence=f"output={combined_output.strip()[:60]}, literal_found={has_literal}, hex_leak={hex_pattern}",
            )
        except Exception as exc:
            return TestResult(passed=False, vulnerability_demonstrated=False, evidence=str(exc), error=str(exc))


def run_format_regression_test(case_id: str, target_file: Path) -> TestResult:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        bin_path = Path(tmpdir) / f"fmt_{case_id}.exe"
        compiled, msg = _compile_c(target_file, bin_path)
        if not compiled:
            return TestResult(passed=False, vulnerability_demonstrated=False, evidence=msg, error=msg)
        try:
            proc = subprocess.run([str(bin_path), "HelloNormalLog"], capture_output=True, text=True, timeout=5)
            combined = proc.stdout + proc.stderr
            ok = proc.returncode == 0 and "HelloNormalLog" in combined
            return TestResult(passed=ok, vulnerability_demonstrated=False, evidence=f"output={combined.strip()}")
        except Exception as exc:
            return TestResult(passed=False, vulnerability_demonstrated=False, evidence=str(exc), error=str(exc))


# ---------------------------------------------------------------------------
# UNIFIED HARNESS DISPATCHER
# ---------------------------------------------------------------------------

def run_security_test(case_id: str, target_file: Path) -> TestResult:
    if case_id in ("B01", "B02", "B03", "B04", "B05", "B06"):
        return run_sql_security_test(case_id, target_file)
    elif case_id in ("B07", "B08", "B09", "B10", "B11", "B12"):
        return run_command_security_test(case_id, target_file)
    elif case_id in ("B13", "B14", "B15", "B16", "B17", "B18"):
        return run_path_security_test(case_id, target_file)
    elif case_id in ("B19", "B20", "B21", "B22", "B23", "B24"):
        return run_memory_security_test(case_id, target_file)
    elif case_id in ("B25", "B26", "B27", "B28", "B29", "B30"):
        return run_format_security_test(case_id, target_file)
    raise ValueError(f"Unrecognized benchmark case ID: {case_id}")


def run_regression_test(case_id: str, target_file: Path) -> TestResult:
    if case_id in ("B01", "B02", "B03", "B04", "B05", "B06"):
        return run_sql_regression_test(case_id, target_file)
    elif case_id in ("B07", "B08", "B09", "B10", "B11", "B12"):
        return run_command_regression_test(case_id, target_file)
    elif case_id in ("B13", "B14", "B15", "B16", "B17", "B18"):
        return run_path_regression_test(case_id, target_file)
    elif case_id in ("B19", "B20", "B21", "B22", "B23", "B24"):
        return run_memory_regression_test(case_id, target_file)
    elif case_id in ("B25", "B26", "B27", "B28", "B29", "B30"):
        return run_format_regression_test(case_id, target_file)
    raise ValueError(f"Unrecognized benchmark case ID: {case_id}")
