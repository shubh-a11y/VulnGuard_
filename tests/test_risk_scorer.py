"""
Tests for the risk scorer module.

Validates language routing, template dampening, mega-function slicing,
and bypass reasons.
"""

import pytest
from unittest.mock import patch, MagicMock
import numpy as np


class TestRiskScorerLanguageRouting:
    """Test EC-5.4: Language-aware routing."""

    def test_unsupported_language_returns_100(self):
        from vulnguard.models.risk_scorer import RiskScorer, RiskResult, _ML_SUPPORTED_LANGUAGES

        # Mock model loading
        with patch("vulnguard.models.risk_scorer.joblib") as mock_joblib:
            mock_model = MagicMock()
            mock_model.predict_proba.return_value = np.array([[0.3, 0.7]])
            mock_joblib.load.return_value = mock_model

            with patch("vulnguard.models.risk_scorer.cfg") as mock_cfg:
                mock_cfg.triage.model_path = MagicMock()
                mock_cfg.triage.model_path.exists.return_value = True
                mock_cfg.triage.mega_function_loc_limit = 2000
                mock_cfg.triage.template_dampening_factor = 0.5

                scorer = RiskScorer.__new__(RiskScorer)
                scorer._model = mock_model

                result = scorer.score("public void foo() {}", language="java")
                assert result.risk_score == 100.0
                assert result.bypass_reason == "LANGUAGE_UNSUPPORTED:java"

    def test_supported_language_uses_model(self):
        from vulnguard.models.risk_scorer import RiskScorer

        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.6, 0.4]])

        scorer = RiskScorer.__new__(RiskScorer)
        scorer._model = mock_model

        with patch("vulnguard.models.risk_scorer.cfg") as mock_cfg:
            mock_cfg.triage.mega_function_loc_limit = 2000
            mock_cfg.triage.template_dampening_factor = 0.5

            result = scorer.score("int f() { return 1; }", language="c")
            # Model was called (not bypassed)
            assert result.bypass_reason is None
            assert 0 <= result.risk_score <= 100

    @pytest.mark.parametrize(
        ("code", "language", "signal"),
        [
            ("void f(char *x) { strcpy(buf, x); }", "c", "UNBOUNDED_C_API"),
            ("void f(char *x) { printf(x); }", "c", "NON_LITERAL_FORMAT_STRING"),
            ("void f(char *p) { if (!access(p, 2)) open(p, 1); }", "c", "TOCTOU_FILE_ACCESS"),
            ("def f(x):\n    return os.system(x)", "python", "SHELL_EXECUTION"),
            (
                "def f(cursor, value):\n    query = f\"UPDATE users SET name='{value}'\"\n    cursor.executescript(query)",
                "python",
                "DYNAMIC_SQL",
            ),
        ],
    )
    def test_known_dangerous_patterns_bypass_ml_threshold(self, code, language, signal):
        from vulnguard.models.risk_scorer import RiskScorer

        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.99, 0.01]])
        scorer = RiskScorer.__new__(RiskScorer)
        scorer._model = mock_model

        with patch("vulnguard.models.risk_scorer.cfg") as mock_cfg:
            mock_cfg.triage.mega_function_loc_limit = 2000
            mock_cfg.triage.template_dampening_factor = 0.5
            mock_cfg.triage.risk_threshold = 65
            result = scorer.score(code, language)

        assert result.risk_score >= 65
        assert result.bypass_reason == f"STATIC_SIGNAL:{signal}"


class TestMegaFunctionSlicing:
    """Test Section 4.1: Mega-function handling."""

    def test_mega_function_splits_into_blocks(self):
        from vulnguard.models.risk_scorer import RiskScorer

        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.5, 0.5]])

        scorer = RiskScorer.__new__(RiskScorer)
        scorer._model = mock_model

        # Create a function with > 2000 lines
        lines = ["int x = 0;"] * 2500
        mega_code = "\n".join(lines)

        with patch("vulnguard.models.risk_scorer.cfg") as mock_cfg:
            mock_cfg.triage.mega_function_loc_limit = 2000
            mock_cfg.triage.template_dampening_factor = 0.5

            result = scorer.score(mega_code, language="c")
            assert result.sub_block_scores is not None
            assert len(result.sub_block_scores) >= 2


class TestTemplateDampening:
    """Test EC-5.5: Template dampening."""

    def test_template_score_is_halved(self):
        from vulnguard.models.risk_scorer import RiskScorer

        mock_model = MagicMock()
        # Model gives 80% probability
        mock_model.predict_proba.return_value = np.array([[0.2, 0.8]])

        scorer = RiskScorer.__new__(RiskScorer)
        scorer._model = mock_model

        with patch("vulnguard.models.risk_scorer.cfg") as mock_cfg:
            mock_cfg.triage.mega_function_loc_limit = 2000
            mock_cfg.triage.template_dampening_factor = 0.5

            template_code = "template<typename T>\nT add(T a, T b) { return a + b; }"
            result = scorer.score(template_code, language="cpp")

            # Score should be dampened by 0.5x
            assert result.risk_score <= 50.0  # 80 * 0.5 = 40
