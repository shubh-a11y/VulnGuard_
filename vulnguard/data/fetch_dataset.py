"""
VulnGuard dataset fetcher and loader.

Supports:
  - Python vulnerability datasets (PyCode-Vul + CVEFixes Python slice)
  - Legacy C/C++ dataset (DiverseVul)

Downloads from HuggingFace or loads from local cache.
Validates schema and prints dataset statistics.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Optional

import pandas as pd

from vulnguard.config import cfg

logger = logging.getLogger(__name__)

# Required columns for the unified schema
_REQUIRED_COLS = {"func", "target", "project"}


# ── Python dataset loaders ────────────────────────────────────────────────

def _fetch_pycodevul() -> pd.DataFrame:
    """Load S-AIR-L/PyCode-Vul train set from HuggingFace.

    Maps: vulnerable_function_source → func, label → target, repo → project.
    """
    from datasets import load_dataset

    logger.info("Downloading PyCode-Vul from HuggingFace…")
    ds = load_dataset("csv", data_files={"train": cfg.data.pycodevul_csv}, split="train")
    df = ds.to_pandas()

    # Map columns to our unified schema
    df = df.rename(columns={
        "vulnerable_function_source": "func",
        "label": "target",
        "repo": "project",
    })

    # Keep useful metadata
    cols_to_keep = ["func", "target", "project"]
    for optional_col in ["cwe_ids", "cve_ids", "file_path"]:
        if optional_col in df.columns:
            cols_to_keep.append(optional_col)
    df = df[[c for c in cols_to_keep if c in df.columns]]

    # Drop rows with missing code
    df = df.dropna(subset=["func"])
    df = df[df["func"].str.strip().astype(bool)]

    logger.info("PyCode-Vul: loaded %d samples", len(df))
    return df


def _fetch_cvefixes_python() -> pd.DataFrame:
    """Load hitoshura25/cvefixes, filter to Python, create vuln+fixed pairs.

    Each CVEFixes row has vulnerable_code and fixed_code.
    We create TWO rows per entry:
      - vulnerable_code → target=1
      - fixed_code → target=0
    This effectively doubles our sample count from this source.
    """
    from datasets import load_dataset

    logger.info("Downloading CVEFixes from HuggingFace…")
    ds = load_dataset(cfg.data.cvefixes_name, split="train")
    df = ds.to_pandas()

    # Filter Python-only rows
    df["language"] = df["language"].fillna("").str.lower()
    df = df[df["language"].str.contains("python")]
    logger.info("CVEFixes: %d Python entries found", len(df))

    if df.empty:
        return pd.DataFrame(columns=["func", "target", "project"])

    rows = []
    for _, row in df.iterrows():
        vuln_code = str(row.get("vulnerable_code", "")).strip()
        fixed_code = str(row.get("fixed_code", "")).strip()
        # Use repo_url as project identifier
        project = str(row.get("repo_url", "cvefixes"))

        if vuln_code:
            rows.append({"func": vuln_code, "target": 1, "project": project})
        if fixed_code:
            rows.append({"func": fixed_code, "target": 0, "project": project})

    result = pd.DataFrame(rows)
    logger.info("CVEFixes: created %d samples (vuln + fixed pairs)", len(result))
    return result


def _deduplicate(df: pd.DataFrame) -> pd.DataFrame:
    """Remove duplicate code snippets by content hash."""
    before = len(df)
    df["_hash"] = df["func"].apply(lambda x: hashlib.md5(x.encode("utf-8", errors="replace")).hexdigest())
    df = df.drop_duplicates(subset=["_hash"])
    df = df.drop(columns=["_hash"])
    after = len(df)
    if before != after:
        logger.info("Deduplication: %d → %d samples (%d removed)", before, after, before - after)
    return df


# ── Public API ────────────────────────────────────────────────────────────

def fetch_dataset(
    cache_dir: Optional[Path] = None,
    max_samples: Optional[int] = None,
    language: str = "python",
) -> pd.DataFrame:
    """Load vulnerability dataset. Downloads on first call, caches locally.

    Args:
        cache_dir: Override cache directory. Defaults to config value.
        max_samples: Cap total rows (useful for dev/testing).
        language: Target language. 'python' loads the combined Python dataset,
                  anything else falls back to DiverseVul (C/C++).

    Returns:
        DataFrame with columns: func, target, project (and optional metadata).
    """
    cache_dir = cache_dir or cfg.data.cache_dir
    cache_dir.mkdir(parents=True, exist_ok=True)

    if language == "python":
        return _fetch_python_combined(cache_dir, max_samples)
    else:
        return _fetch_diversevul(cache_dir, max_samples)


def _fetch_python_combined(cache_dir: Path, max_samples: Optional[int]) -> pd.DataFrame:
    """Fetch and merge Python vulnerability datasets."""
    parquet_path = cache_dir / "python_vulns.parquet"

    if parquet_path.exists():
        logger.info("Loading cached Python dataset from %s", parquet_path)
        df = pd.read_parquet(parquet_path)
    else:
        # Fetch both sources
        df_pycode = _fetch_pycodevul()
        df_cvefixes = _fetch_cvefixes_python()

        # Merge
        df = pd.concat([df_pycode, df_cvefixes], ignore_index=True)
        logger.info("Merged dataset: %d total samples", len(df))

        # Deduplicate
        df = _deduplicate(df)

        # Cache
        df.to_parquet(parquet_path, index=False)
        logger.info("Cached Python dataset to %s", parquet_path)

    # Validate
    missing = _REQUIRED_COLS - set(df.columns)
    if missing:
        raise ValueError(f"Dataset missing required columns: {missing}")

    if max_samples:
        df = df.head(max_samples)

    _log_stats(df)
    return df


def _fetch_diversevul(cache_dir: Path, max_samples: Optional[int]) -> pd.DataFrame:
    """Fetch the legacy DiverseVul C/C++ dataset."""
    parquet_path = cache_dir / "diversevul.parquet"

    if parquet_path.exists():
        logger.info("Loading cached dataset from %s", parquet_path)
        df = pd.read_parquet(parquet_path)
    else:
        logger.info("Downloading DiverseVul from HuggingFace…")
        try:
            from datasets import load_dataset

            ds = load_dataset(cfg.data.dataset_name, split="train")
            df = ds.to_pandas()
            df.to_parquet(parquet_path, index=False)
            logger.info("Cached dataset to %s", parquet_path)
        except Exception:
            logger.exception("Failed to download dataset")
            raise

    # Validate schema
    missing = _REQUIRED_COLS - set(df.columns)
    if missing:
        raise ValueError(f"Dataset missing required columns: {missing}")

    if max_samples:
        df = df.head(max_samples)

    _log_stats(df)
    return df


def _log_stats(df: pd.DataFrame) -> None:
    """Print dataset statistics."""
    total = len(df)
    vuln = int(df["target"].sum())
    safe = total - vuln
    projects = df["project"].nunique()
    logger.info(
        "Dataset: %d functions (%d vuln / %d safe, %.1f%% vuln), %d projects",
        total,
        vuln,
        safe,
        100 * vuln / max(total, 1),
        projects,
    )
