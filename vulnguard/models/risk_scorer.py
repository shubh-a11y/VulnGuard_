"""
Risk scorer — maps raw source code to a 0–100 vulnerability risk score.

Loads the trained XGBoost model and applies language routing (EC-5.4),
template dampening (EC-5.5), and mega-function slicing (Section 4.1).
"""

from __future__ import annotations

import logging
import re
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import joblib
import numpy as np

from vulnguard.config import cfg
from vulnguard.data.feature_extractor import FeatureResult, extract_features

logger = logging.getLogger(__name__)

# Supported languages for ML triage
_ML_SUPPORTED_LANGUAGES = frozenset({"python", "c", "cpp"})


def _static_security_signal(code: str, language: str) -> str | None:
    """Return a high-confidence signal that must bypass probabilistic triage."""
    if language in {"c", "cpp"}:
        if re.search(r"\b(?:strcpy|strcat|sprintf|vsprintf|gets)\s*\(", code):
            return "UNBOUNDED_C_API"
        if re.search(r"\b(?:printf|vprintf)\s*\(\s*(?![\"'])\w+\s*\)", code):
            return "NON_LITERAL_FORMAT_STRING"
        if re.search(r"\baccess\s*\(", code) and re.search(
            r"\b(?:open|fopen|unlink|rename|chmod|chown)\s*\(", code
        ):
            return "TOCTOU_FILE_ACCESS"
    elif language == "python":
        if re.search(r"\bos\.(?:system|popen)\s*\(|\bshell\s*=\s*True\b", code):
            return "SHELL_EXECUTION"
        dynamic_sql = re.search(
            r"(?is)\b(?:query|sql)\s*=\s*(?:f[\"']|[^\n]*(?:\+|\.format\s*\())",
            code,
        )
        if dynamic_sql and re.search(r"\b(?:execute|executemany|executescript)\s*\(", code):
            return "DYNAMIC_SQL"
    return None


@dataclass
class RiskResult:
    """Scoring result for a single function."""

    risk_score: float = 0.0
    features: dict[str, float] = field(default_factory=dict)
    parse_errors: list[str] = field(default_factory=list)
    bypass_reason: Optional[str] = None  # e.g. LANGUAGE_UNSUPPORTED
    sub_block_scores: Optional[list[float]] = None  # For mega-functions


class RiskScorer:
    """Stateful scorer that loads the model once and scores many functions."""

    def __init__(self, model_path: Optional[Path] = None):
        model_path = model_path or cfg.triage.model_path
        if not model_path.exists():
            raise FileNotFoundError(
                f"Trained model not found at {model_path}. Run 'vulnguard train' first."
            )
        loaded = joblib.load(model_path)
        # Support both old format (plain model) and new format (dict bundle)
        if isinstance(loaded, dict):
            self._model = loaded["model"]
            self._threshold = loaded.get("threshold", 0.5)
        else:
            self._model = loaded
            self._threshold = 0.5
        logger.info("Loaded model from %s (threshold=%.4f)", model_path, self._threshold)

    @property
    def optimal_threshold(self) -> int:
        """The dynamically tuned risk threshold (0-100 scale)."""
        # If user explicitly configured a lower threshold in .env, honor it.
        ml_thresh = int(round(self._threshold * 100))
        return min(ml_thresh, cfg.triage.risk_threshold)

    def score(self, code: str, language: str = "c") -> RiskResult:
        """Score a single function's vulnerability risk.

        Args:
            code: Function source code.
            language: Programming language ("c", "cpp", "python", "java", "javascript").

        Returns:
            RiskResult with 0–100 risk score.
        """
        # ── Language routing (EC-5.4) ─────────────────────
        if language not in _ML_SUPPORTED_LANGUAGES:
            return RiskResult(
                risk_score=100.0,
                bypass_reason=f"LANGUAGE_UNSUPPORTED:{language}",
            )

        static_signal = _static_security_signal(code, language)

        # ── Mega-function slicing (Section 4.1) ──────────
        loc = len(code.splitlines())
        if loc > cfg.triage.mega_function_loc_limit:
            result = self._score_mega_function(code, language)
        else:
            # ── Standard scoring ──────────────────────────────
            feat = extract_features(code, language)
            result = self._score_from_features(feat)

        if static_signal:
            result.risk_score = max(result.risk_score, float(cfg.triage.risk_threshold))
            result.bypass_reason = f"STATIC_SIGNAL:{static_signal}"
        return result

    def _score_from_features(self, feat: FeatureResult) -> RiskResult:
        """Convert extracted features to a risk score via the trained model."""
        X = feat.vector.reshape(1, -1)
        proba = self._model.predict_proba(X)[0, 1]
        score = round(float(proba) * 100, 1)

        # Template dampening (EC-5.5)
        if feat.features.get("is_template"):
            score = round(score * cfg.triage.template_dampening_factor, 1)

        return RiskResult(
            risk_score=min(score, 100.0),
            features=feat.features,
            parse_errors=feat.parse_errors,
        )

    def _score_mega_function(self, code: str, language: str) -> RiskResult:
        """Slice mega-functions into blocks and return the max score."""
        lines = code.splitlines()
        block_size = cfg.triage.mega_function_loc_limit
        blocks = [
            "\n".join(lines[i : i + block_size])
            for i in range(0, len(lines), block_size)
        ]

        sub_scores = []
        all_errors: list[str] = []
        best_features: dict = {}
        best_score = 0.0

        for i, block in enumerate(blocks):
            feat = extract_features(block, language)
            result = self._score_from_features(feat)
            sub_scores.append(result.risk_score)
            all_errors.extend(result.parse_errors)
            if result.risk_score >= best_score:
                best_score = result.risk_score
                best_features = result.features

        return RiskResult(
            risk_score=best_score,
            features=best_features,
            parse_errors=all_errors,
            sub_block_scores=sub_scores,
        )

    def score_batch(self, code_list: list[str], language: str = "c") -> list[RiskResult]:
        """Score a list of functions."""
        return [self.score(code, language) for code in code_list]
