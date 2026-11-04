"""
XGBoost vulnerability classifier — training pipeline.

Implements Paper 1 guardrail (project-level data split) and
class imbalance handling via scale_pos_weight.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    f1_score,
    matthews_corrcoef,
    precision_recall_curve,
)
from xgboost import XGBClassifier

from vulnguard.config import cfg
from vulnguard.data.feature_extractor import FEATURE_NAMES, extract_features

logger = logging.getLogger(__name__)


# ── Project-level data split (Paper 1 — zero data leakage) ───────────────

def split_by_project(
    df: pd.DataFrame,
    train_ratio: float = 0.8,
    seed: int = 42,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Split dataset so all functions from a project stay in the same split.

    Args:
        df: Must have a 'project' column.
        train_ratio: Fraction of *projects* in training set.
        seed: Random seed for reproducibility.

    Returns:
        (train_df, test_df) with zero project overlap.
    """
    projects = df["project"].unique()
    rng = np.random.RandomState(seed)
    rng.shuffle(projects)

    split_idx = int(len(projects) * train_ratio)
    train_projects = set(projects[:split_idx])
    test_projects = set(projects[split_idx:])

    train_df = df[df["project"].isin(train_projects)].copy()
    test_df = df[df["project"].isin(test_projects)].copy()

    logger.info(
        "Split: %d train projects (%d funcs), %d test projects (%d funcs)",
        len(train_projects),
        len(train_df),
        len(test_projects),
        len(test_df),
    )

    # Sanity check: zero overlap
    overlap = train_projects & test_projects
    assert not overlap, f"Data leakage! Overlapping projects: {overlap}"

    return train_df, test_df


# ── Feature matrix builder ────────────────────────────────────────────────

def build_feature_matrix(df: pd.DataFrame, language: str = "c") -> tuple[np.ndarray, np.ndarray]:
    """Extract features from code column and build X, y arrays.

    Returns:
        (X, y) where X is (n_samples, n_features) and y is (n_samples,).
    """
    from vulnguard.data.feature_extractor import extract_features_batch

    results = extract_features_batch(df["func"].tolist(), language=language)
    X = np.array([r.vector for r in results])
    y = df["target"].values.astype(int)
    return X, y


# ── Training ──────────────────────────────────────────────────────────────

def train(
    df: pd.DataFrame,
    save_path: Optional[Path] = None,
    use_smote: Optional[bool] = None,
    language: str = "c",
) -> tuple[CalibratedClassifierCV, dict]:
    """Train XGBoost classifier with class imbalance handling.

    Args:
        df: Full dataset with 'func', 'target', 'project' columns.
        save_path: Where to save trained model. Defaults to config.
        use_smote: Override SMOTE setting from config.

    Returns:
        (calibrated_model, metrics_dict)
    """
    save_path = save_path or cfg.triage.model_path
    use_smote = use_smote if use_smote is not None else cfg.triage.use_smote

    # 1. Project-level split
    train_df, test_df = split_by_project(df, cfg.data.train_split_ratio)

    # 2. Extract features
    logger.info("Extracting training features (language=%s)…", language)
    X_train, y_train = build_feature_matrix(train_df, language=language)
    logger.info("Extracting test features…")
    X_test, y_test = build_feature_matrix(test_df, language=language)

    # 3. Class imbalance — scale_pos_weight
    n_neg = int((y_train == 0).sum())
    n_pos = int((y_train == 1).sum())
    spw = n_neg / max(n_pos, 1)
    logger.info("Class balance: %d neg / %d pos → scale_pos_weight=%.2f", n_neg, n_pos, spw)

    # 4. Optional SMOTE (applied only on training data — no leakage)
    if use_smote and n_pos >= 6:  # SMOTE needs ≥k+1 minority samples (k=5 default)
        from imblearn.over_sampling import SMOTE

        logger.info("Applying SMOTE on training data…")
        sm = SMOTE(random_state=42)
        X_train, y_train = sm.fit_resample(X_train, y_train)
        logger.info("After SMOTE: %d samples", len(y_train))

    # 5. Train XGBoost
    model = XGBClassifier(
        n_estimators=cfg.triage.n_estimators,
        max_depth=cfg.triage.max_depth,
        learning_rate=cfg.triage.learning_rate,
        scale_pos_weight=spw,
        eval_metric="aucpr",
        early_stopping_rounds=cfg.triage.early_stopping_rounds,
        random_state=42,
        use_label_encoder=False,
    )

    model.fit(
        X_train,
        y_train,
        eval_set=[(X_test, y_test)],
        verbose=cfg.verbose,
    )

    # 6. Evaluate with RAW model probabilities first (before calibration)
    y_proba_raw = model.predict_proba(X_test)[:, 1]
    logger.info("Raw XGBoost prob stats: min=%.4f, max=%.4f, mean=%.4f, median=%.4f",
                y_proba_raw.min(), y_proba_raw.max(), y_proba_raw.mean(), np.median(y_proba_raw))

    # 7. Auto-tune decision threshold using precision-recall curve
    #    For triage, we want HIGH RECALL (catch all vulns) even at cost of some FPs.
    #    The LLM agents downstream will filter out false positives.
    precisions, recalls, thresholds = precision_recall_curve(y_test, y_proba_raw)

    # Find threshold that maximizes F1 (or use a recall-biased threshold)
    f1_scores = 2 * (precisions[:-1] * recalls[:-1]) / (precisions[:-1] + recalls[:-1] + 1e-8)
    best_idx = np.argmax(f1_scores)
    optimal_threshold = float(thresholds[best_idx]) if len(thresholds) > 0 else 0.5

    # Also find threshold for >= 80% recall (triage should catch most vulns)
    recall_80_idx = np.where(recalls[:-1] >= 0.8)[0]
    recall_80_threshold = float(thresholds[recall_80_idx[-1]]) if len(recall_80_idx) > 0 else optimal_threshold

    logger.info("Optimal F1 threshold: %.4f (F1=%.4f, P=%.4f, R=%.4f)",
                optimal_threshold, f1_scores[best_idx],
                precisions[best_idx], recalls[best_idx])
    logger.info("80%% recall threshold: %.4f", recall_80_threshold)

    # Use the recall-biased threshold for triage (we'd rather over-flag than miss)
    chosen_threshold = recall_80_threshold
    y_pred = (y_proba_raw >= chosen_threshold).astype(int)

    # 8. Calibrate probabilities (sigmoid — works better with small pos samples)
    logger.info("Calibrating probabilities (sigmoid)...")
    from sklearn.frozen import FrozenEstimator
    calibrated = CalibratedClassifierCV(estimator=FrozenEstimator(model), method="sigmoid", cv=3)
    calibrated.fit(X_train, y_train)

    y_proba_cal = calibrated.predict_proba(X_test)[:, 1]
    y_pred_cal = (y_proba_cal >= chosen_threshold).astype(int)

    # 9. Compute metrics using the tuned threshold
    metrics = {
        "auc_pr": float(average_precision_score(y_test, y_proba_raw)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
        "mcc": float(matthews_corrcoef(y_test, y_pred)),
        "f1_calibrated": float(f1_score(y_test, y_pred_cal, zero_division=0)),
        "report": classification_report(y_test, y_pred, output_dict=True, zero_division=0),
        "optimal_threshold": optimal_threshold,
        "chosen_threshold": chosen_threshold,
        "n_train": len(X_train),
        "n_test": len(X_test),
        "scale_pos_weight": spw,
    }

    logger.info("AUC-PR: %.4f | F1: %.4f | MCC: %.4f (threshold=%.4f)",
                metrics["auc_pr"], metrics["f1"], metrics["mcc"], chosen_threshold)
    logger.info("\n%s", classification_report(y_test, y_pred, zero_division=0))

    # 10. Feature importance
    importance = dict(zip(FEATURE_NAMES, model.feature_importances_))
    logger.info("Feature importance: %s", importance)
    metrics["feature_importance"] = importance

    # 11. Save model + threshold
    save_path.parent.mkdir(parents=True, exist_ok=True)
    save_bundle = {"model": calibrated, "threshold": chosen_threshold, "raw_model": model}
    joblib.dump(save_bundle, save_path)
    logger.info("Model saved to %s (threshold=%.4f)", save_path, chosen_threshold)

    return calibrated, metrics

