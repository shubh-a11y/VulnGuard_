from vulnguard.benchmarks.evaluator import ApproachMetrics
from vulnguard.benchmarks.runner import benchmark_repository
from vulnguard.benchmarks.static_analyzer import SASTFinding, SASTResult
from vulnguard.models.risk_scorer import RiskResult


class _FakeScorer:
    optimal_threshold = 65

    def score(self, code, language):
        return RiskResult(risk_score=90.0 if "eval" in code else 10.0)


def test_repository_benchmark_produces_comparison(monkeypatch, tmp_path):
    (tmp_path / "app.py").write_text(
        "def unsafe(value):\n    return eval(value)\n\ndef safe(value):\n    return value\n"
    )
    monkeypatch.setattr("vulnguard.benchmarks.runner.RiskScorer", _FakeScorer)
    monkeypatch.setattr(
        "vulnguard.benchmarks.runner.run_all_sast",
        lambda path: [
            SASTResult(
                tool="semgrep",
                findings=[SASTFinding("semgrep", "app.py", 2, "eval", "ERROR", "eval used")],
                elapsed_seconds=0.1,
            ),
            SASTResult(tool="cppcheck", available=False),
        ],
    )

    report = benchmark_repository(tmp_path)

    assert report.dataset_info["functions"] == 2
    assert report.dataset_info["unavailable_tools"] == ["cppcheck"]
    assert report.approaches[0].vulnerabilities_detected == 1
    assert report.approaches[1].approach_name == "SAST (semgrep)"
    assert report.approaches[1].vulnerabilities_detected == 1
    assert report.approaches[0].precision is None
    assert "N/A" in report.to_markdown()


def test_labeled_metrics_count_missed_findings_in_recall():
    metrics = ApproachMetrics(
        approach_name="labeled",
        vulnerabilities_detected=1,
        false_negatives=1,
        ground_truth_available=True,
    )

    assert metrics.precision == 1.0
    assert metrics.recall == 0.5
