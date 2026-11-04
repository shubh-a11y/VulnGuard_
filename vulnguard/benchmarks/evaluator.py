"""
Benchmark evaluator — computes and compares metrics across approaches.

Compares: VulnGuard (multi-agent) vs SAST (Cppcheck/Semgrep) vs Single-LLM.
Outputs JSON report and Markdown summary.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from vulnguard.config import cfg

logger = logging.getLogger(__name__)


@dataclass
class ApproachMetrics:
    """Metrics for a single approach (VulnGuard, SAST, or Single-LLM)."""

    approach_name: str
    total_functions: int = 0
    vulnerabilities_detected: int = 0
    patches_generated: int = 0
    patches_validated: int = 0
    regressions_caused: int = 0
    total_tokens: int = 0
    total_time_seconds: float = 0.0
    false_positives: int = 0
    false_negatives: int = 0
    ground_truth_available: bool = False

    @property
    def detection_rate(self) -> float:
        return self.vulnerabilities_detected / max(self.total_functions, 1)

    @property
    def patch_success_rate(self) -> float:
        return self.patches_validated / max(self.patches_generated, 1)

    @property
    def regression_rate(self) -> float:
        return self.regressions_caused / max(self.patches_validated, 1)

    @property
    def avg_tokens_per_fix(self) -> float:
        return self.total_tokens / max(self.patches_validated, 1)

    @property
    def avg_time_per_fix(self) -> float:
        return self.total_time_seconds / max(self.patches_validated, 1)

    @property
    def precision(self) -> Optional[float]:
        if not self.ground_truth_available:
            return None
        tp = self.vulnerabilities_detected - self.false_positives
        return max(tp, 0) / max(self.vulnerabilities_detected, 1)

    @property
    def recall(self) -> Optional[float]:
        if not self.ground_truth_available:
            return None
        tp = self.vulnerabilities_detected - self.false_positives
        fn = self.false_negatives
        return max(tp, 0) / max(tp + fn, 1)

    def to_dict(self) -> dict:
        return {
            "approach": self.approach_name,
            "total_functions": self.total_functions,
            "vulnerabilities_detected": self.vulnerabilities_detected,
            "detection_rate": round(self.detection_rate, 4),
            "patches_generated": self.patches_generated,
            "patches_validated": self.patches_validated,
            "patch_success_rate": round(self.patch_success_rate, 4),
            "regressions_caused": self.regressions_caused,
            "regression_rate": round(self.regression_rate, 4),
            "total_tokens": self.total_tokens,
            "avg_tokens_per_fix": round(self.avg_tokens_per_fix, 1),
            "total_time_seconds": round(self.total_time_seconds, 2),
            "avg_time_per_fix_seconds": round(self.avg_time_per_fix, 2),
            "precision": round(self.precision, 4) if self.precision is not None else None,
            "recall": round(self.recall, 4) if self.recall is not None else None,
        }


@dataclass
class BenchmarkReport:
    """Full benchmark comparison report."""

    approaches: list[ApproachMetrics] = field(default_factory=list)
    generated_at: str = ""
    dataset_info: dict = field(default_factory=dict)

    def to_json(self, path: Optional[Path] = None) -> str:
        """Export as JSON. Optionally write to file."""
        data = {
            "generated_at": self.generated_at,
            "dataset": self.dataset_info,
            "results": [a.to_dict() for a in self.approaches],
        }
        text = json.dumps(data, indent=2)
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            logger.info("Report saved to %s", path)
        return text

    def to_markdown(self, path: Optional[Path] = None) -> str:
        """Export as Markdown table. Optionally write to file."""
        headers = [
            "Approach", "Detected", "Patches", "Success Rate",
            "Regression Rate", "Avg Tokens/Fix", "Avg Time/Fix (s)",
            "Precision", "Recall",
        ]

        rows = []
        for a in self.approaches:
            d = a.to_dict()
            rows.append([
                d["approach"],
                str(d["vulnerabilities_detected"]),
                str(d["patches_validated"]),
                f"{d['patch_success_rate']:.1%}",
                f"{d['regression_rate']:.1%}",
                f"{d['avg_tokens_per_fix']:.0f}",
                f"{d['avg_time_per_fix_seconds']:.1f}",
                f"{d['precision']:.1%}" if d["precision"] is not None else "N/A",
                f"{d['recall']:.1%}" if d["recall"] is not None else "N/A",
            ])

        # Build markdown table
        col_widths = [max(len(h), max((len(r[i]) for r in rows), default=0)) for i, h in enumerate(headers)]
        header_line = "| " + " | ".join(h.ljust(w) for h, w in zip(headers, col_widths)) + " |"
        sep_line = "| " + " | ".join("-" * w for w in col_widths) + " |"
        data_lines = ["| " + " | ".join(cell.ljust(w) for cell, w in zip(row, col_widths)) + " |" for row in rows]

        md = f"# VulnGuard Benchmark Results\n\n{header_line}\n{sep_line}\n" + "\n".join(data_lines) + "\n"

        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(md)
            logger.info("Markdown report saved to %s", path)
        return md


def create_empty_report() -> BenchmarkReport:
    """Create an empty report with timestamp."""
    from datetime import datetime, timezone

    return BenchmarkReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


# ── Vul4J Benchmark Integration ──────────────────────────────────────────

class Vul4JBenchmark:
    """Benchmark runner using the Vul4J dataset.

    Vul4J provides reproducible Java vulnerabilities with Proof of Vulnerability
    (PoV) test cases. This class loads the dataset, runs VulnGuard against each
    vulnerability, and verifies patches using the provided PoV tests.

    Based on: "Vul4J: A Dataset of Reproducible Java Vulnerabilities"
    """

    def __init__(self, dataset_path: Optional[Path] = None):
        self.dataset_path = dataset_path or Path("data") / "vul4j"
        self.results: list[dict] = []

    def load_dataset(self) -> list[dict]:
        """Load Vul4J dataset entries.

        Each entry contains:
          - vul_id: Vulnerability identifier
          - project: Project name
          - cve_id: CVE identifier
          - cwe_id: CWE classification
          - vulnerable_file: Path to the vulnerable source file
          - vulnerable_code: The vulnerable code snippet
          - fixed_code: The ground-truth fix
          - pov_test: The Proof of Vulnerability test case
          - build_system: Maven/Gradle build system info
        """
        entries = []

        if not self.dataset_path.exists():
            logger.warning("Vul4J dataset not found at %s", self.dataset_path)
            return entries

        # Load from JSON manifest
        manifest = self.dataset_path / "vul4j_manifest.json"
        if manifest.exists():
            import json
            data = json.loads(manifest.read_text(encoding="utf-8"))
            entries = data.get("vulnerabilities", [])
            logger.info("Loaded %d Vul4J entries from manifest", len(entries))
        else:
            # Scan for individual JSON files
            for json_file in self.dataset_path.glob("*.json"):
                try:
                    import json
                    entry = json.loads(json_file.read_text(encoding="utf-8"))
                    entries.append(entry)
                except Exception as exc:
                    logger.warning("Failed to load %s: %s", json_file.name, exc)

            logger.info("Loaded %d Vul4J entries from individual files", len(entries))

        return entries

    def run_benchmark(
        self,
        entries: Optional[list[dict]] = None,
        max_entries: int = 50,
    ) -> BenchmarkReport:
        """Run VulnGuard against Vul4J entries and collect metrics.

        Args:
            entries: Vul4J dataset entries. If None, loads from disk.
            max_entries: Maximum entries to benchmark.

        Returns:
            BenchmarkReport with VulnGuard metrics.
        """
        from datetime import datetime, timezone

        if entries is None:
            entries = self.load_dataset()

        entries = entries[:max_entries]
        report = create_empty_report()
        report.dataset_info = {
            "name": "Vul4J",
            "total_entries": len(entries),
        }

        metrics = ApproachMetrics(
            approach_name="VulnGuard (Multi-Agent)",
            ground_truth_available=True,
        )
        metrics.total_functions = len(entries)

        for entry in entries:
            result = self._evaluate_single(entry)
            self.results.append(result)

            if result.get("vulnerability_detected"):
                metrics.vulnerabilities_detected += 1
            else:
                metrics.false_negatives += 1
            if result.get("patch_generated"):
                metrics.patches_generated += 1
            if result.get("pov_test_passed"):
                metrics.patches_validated += 1
            if result.get("regression_detected"):
                metrics.regressions_caused += 1
            metrics.total_tokens += result.get("tokens_used", 0)
            metrics.total_time_seconds += result.get("time_seconds", 0)

        report.approaches.append(metrics)
        report.generated_at = datetime.now(timezone.utc).isoformat()

        logger.info(
            "Vul4J benchmark complete: %d/%d patches validated (%.1f%% success rate)",
            metrics.patches_validated,
            metrics.total_functions,
            metrics.patch_success_rate * 100,
        )

        return report

    def _evaluate_single(self, entry: dict) -> dict:
        """Evaluate VulnGuard on a single Vul4J entry.

        Returns a result dict with detection, patching, and PoV test outcomes.
        """
        start = time.time()
        result = {
            "vul_id": entry.get("vul_id", "unknown"),
            "cve_id": entry.get("cve_id", "unknown"),
            "vulnerability_detected": False,
            "patch_generated": False,
            "pov_test_passed": False,
            "regression_detected": False,
            "tokens_used": 0,
            "time_seconds": 0,
        }

        try:
            from vulnguard.agents.graph import run_pipeline

            vulnerable_code = entry.get("vulnerable_code", "")
            language = entry.get("language", "java")

            if not vulnerable_code:
                return result

            final_state = run_pipeline(
                function_id=entry.get("vul_id", "vul4j"),
                code=vulnerable_code,
                language=language,
                risk_score=100.0,  # Vul4J entries are all known vulnerabilities
                context_bundle={},
                max_attempts=2,
            )

            result["vulnerability_detected"] = final_state.get("vulnerability_found", False)
            result["patch_generated"] = final_state.get("patched_code") is not None

            # Verify against PoV test if patch was generated
            if result["patch_generated"] and entry.get("pov_test"):
                pov_passed = self._run_pov_test(
                    patched_code=final_state["patched_code"],
                    pov_test=entry["pov_test"],
                    language=language,
                )
                result["pov_test_passed"] = pov_passed

            # Check for regressions against ground-truth fix
            if result["patch_generated"] and entry.get("fixed_code"):
                result["regression_detected"] = not self._check_semantic_equivalence(
                    final_state["patched_code"],
                    entry["fixed_code"],
                )

        except Exception as exc:
            logger.warning("Vul4J evaluation failed for %s: %s", entry.get("vul_id"), exc)

        result["time_seconds"] = time.time() - start
        return result

    def _run_pov_test(
        self,
        patched_code: str,
        pov_test: str,
        language: str,
    ) -> bool:
        """Run a Proof of Vulnerability test against patched code.

        The PoV test should FAIL on vulnerable code and PASS on fixed code.
        Returns True if the PoV test passes (vulnerability is fixed).
        """
        try:
            from vulnguard.sandbox.docker_runner import run_in_sandbox

            # Combine patched code + PoV test
            test_script = f"{patched_code}\n\n{pov_test}"
            result = run_in_sandbox(test_script, language=language, timeout=30)
            return result.get("exit_code") == 0
        except ImportError:
            logger.debug("Docker sandbox not available for PoV testing")
            return False
        except Exception as exc:
            logger.debug("PoV test execution failed: %s", exc)
            return False

    @staticmethod
    def _check_semantic_equivalence(generated: str, ground_truth: str) -> bool:
        """Basic semantic equivalence check between generated and ground-truth patches.

        Uses normalized token comparison — not perfect, but catches obvious regressions.
        """
        import re

        def normalize(code: str) -> set[str]:
            # Strip comments, whitespace, normalize
            code = re.sub(r"#.*$|//.*$", "", code, flags=re.MULTILINE)
            code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
            tokens = set(re.findall(r"\w+", code.lower()))
            return tokens

        gen_tokens = normalize(generated)
        truth_tokens = normalize(ground_truth)

        if not truth_tokens:
            return True

        # Jaccard similarity
        intersection = gen_tokens & truth_tokens
        union = gen_tokens | truth_tokens
        similarity = len(intersection) / max(len(union), 1)

        return similarity >= 0.7  # 70% token overlap threshold
