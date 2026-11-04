"""
Historical Fix Retriever — Vector search over past bug fixes.

Based on InferFix's retrieval-augmented prompting approach, this module
maintains a vector database of historical vulnerability fixes (from CVEfixes
and other sources) and finds structurally similar fixes to inject as
"hints" into the Blue Agent's prompt.

This enables few-shot demonstration: showing the LLM a real-world example
of how a similar vulnerability was fixed in the past dramatically improves
patch quality.

Usage:
    retriever = get_retriever()  # Returns None if DB not populated yet
    hint = retriever.find_similar_fix(buggy_code, "SQL_INJECTION")
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np

from vulnguard.config import cfg

logger = logging.getLogger(__name__)

# Path to the vector database
_DB_DIR = cfg.project_root / "data" / "retriever_db"
_INDEX_FILE = _DB_DIR / "index.json"
_VECTORS_FILE = _DB_DIR / "vectors.npy"

# Singleton retriever instance
_retriever_instance: Optional[FixRetriever] = None


@dataclass
class FixExample:
    """A single historical bug fix example."""

    fix_id: str
    vulnerability_type: str  # e.g., SQL_INJECTION, BUFFER_OVERFLOW
    cwe_id: str              # e.g., CWE-89
    language: str            # e.g., python, c
    vulnerable_code: str     # The buggy code
    fixed_code: str          # The patched code
    diff_summary: str        # Human-readable summary of the fix


@dataclass
class FixRetriever:
    """Vector-based retriever for historical vulnerability fixes.

    Uses simple TF-IDF-like token overlap for similarity instead of
    requiring a heavy embedding model. This keeps the dependency
    footprint minimal while still providing useful results.
    """

    examples: list[FixExample] = field(default_factory=list)
    _vocabulary: dict[str, int] = field(default_factory=dict)
    _vectors: Optional[np.ndarray] = None

    def _tokenize(self, code: str) -> list[str]:
        """Simple code tokenizer: split on whitespace and punctuation."""
        import re
        # Split on non-alphanumeric characters, lowercase, filter short tokens
        tokens = re.findall(r"[a-zA-Z_]\w{2,}", code.lower())
        return tokens

    def _build_vocabulary(self) -> None:
        """Build vocabulary from all examples."""
        vocab: dict[str, int] = {}
        idx = 0
        for ex in self.examples:
            for token in self._tokenize(ex.vulnerable_code + " " + ex.fixed_code):
                if token not in vocab:
                    vocab[token] = idx
                    idx += 1
        self._vocabulary = vocab

    def _vectorize(self, text: str) -> np.ndarray:
        """Convert text to a sparse TF vector."""
        vec = np.zeros(len(self._vocabulary), dtype=np.float32)
        tokens = self._tokenize(text)
        for token in tokens:
            if token in self._vocabulary:
                vec[self._vocabulary[token]] += 1
        # L2 normalize
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec /= norm
        return vec

    def build_index(self) -> None:
        """Build the search index from loaded examples."""
        if not self.examples:
            logger.warning("No examples loaded — index will be empty")
            return

        self._build_vocabulary()
        vectors = []
        for ex in self.examples:
            vec = self._vectorize(ex.vulnerable_code)
            vectors.append(vec)
        self._vectors = np.array(vectors)
        logger.info(
            "Built retriever index: %d examples, %d vocabulary tokens",
            len(self.examples),
            len(self._vocabulary),
        )

    def find_similar_fix(
        self,
        buggy_code: str,
        vulnerability_type: str = "",
        top_k: int = 1,
    ) -> Optional[str]:
        """Find the most similar historical fix for the given buggy code.

        Args:
            buggy_code: The current vulnerable code.
            vulnerability_type: Optional filter by vulnerability type.
            top_k: Number of results to consider.

        Returns:
            A formatted string showing the vulnerable→fixed code transition,
            or None if no suitable match is found.
        """
        if self._vectors is None or len(self.examples) == 0:
            return None

        query_vec = self._vectorize(buggy_code)
        # Cosine similarity (vectors are already L2-normalized)
        similarities = self._vectors @ query_vec

        # If vulnerability_type filter is provided, boost matching types
        if vulnerability_type:
            vt_lower = vulnerability_type.lower()
            for i, ex in enumerate(self.examples):
                if vt_lower in ex.vulnerability_type.lower():
                    similarities[i] *= 1.5  # Boost matching vuln types

        # Get top match
        best_idx = int(np.argmax(similarities))
        best_score = float(similarities[best_idx])

        if best_score < 0.1:
            return None  # No sufficiently similar match

        ex = self.examples[best_idx]
        hint = (
            f"Vulnerability Type: {ex.vulnerability_type} ({ex.cwe_id})\n"
            f"Language: {ex.language}\n\n"
            f"Vulnerable code:\n{ex.vulnerable_code[:500]}\n\n"
            f"Fixed code:\n{ex.fixed_code[:500]}\n\n"
            f"Fix summary: {ex.diff_summary}"
        )
        logger.debug(
            "Retriever found match (score=%.3f): %s (%s)",
            best_score,
            ex.fix_id,
            ex.vulnerability_type,
        )
        return hint

    def save(self, db_dir: Optional[Path] = None) -> None:
        """Save the retriever index to disk."""
        db_dir = db_dir or _DB_DIR
        db_dir.mkdir(parents=True, exist_ok=True)

        # Save examples as JSON
        index_data = {
            "vocabulary": self._vocabulary,
            "examples": [
                {
                    "fix_id": ex.fix_id,
                    "vulnerability_type": ex.vulnerability_type,
                    "cwe_id": ex.cwe_id,
                    "language": ex.language,
                    "vulnerable_code": ex.vulnerable_code,
                    "fixed_code": ex.fixed_code,
                    "diff_summary": ex.diff_summary,
                }
                for ex in self.examples
            ],
        }
        (db_dir / "index.json").write_text(
            json.dumps(index_data, indent=2), encoding="utf-8"
        )

        # Save vectors as numpy array
        if self._vectors is not None:
            np.save(str(db_dir / "vectors.npy"), self._vectors)

        logger.info("Retriever saved to %s (%d examples)", db_dir, len(self.examples))

    @classmethod
    def load(cls, db_dir: Optional[Path] = None) -> Optional[FixRetriever]:
        """Load a saved retriever index from disk."""
        db_dir = db_dir or _DB_DIR
        index_file = db_dir / "index.json"
        vectors_file = db_dir / "vectors.npy"

        if not index_file.exists():
            return None

        try:
            index_data = json.loads(index_file.read_text(encoding="utf-8"))
            retriever = cls()
            retriever._vocabulary = index_data["vocabulary"]
            retriever.examples = [
                FixExample(**ex) for ex in index_data["examples"]
            ]

            if vectors_file.exists():
                retriever._vectors = np.load(str(vectors_file))

            logger.info(
                "Loaded retriever from %s (%d examples)",
                db_dir,
                len(retriever.examples),
            )
            return retriever
        except Exception as exc:
            logger.warning("Failed to load retriever: %s", exc)
            return None


def get_retriever(db_dir: Optional[Path] = None) -> Optional[FixRetriever]:
    """Get the singleton retriever instance. Returns None if not populated."""
    global _retriever_instance
    if _retriever_instance is None:
        _retriever_instance = FixRetriever.load(db_dir)
    return _retriever_instance


# ── CVEfixes ingestion ────────────────────────────────────────────────────

def populate_from_cvefixes(
    max_examples: int = 1000,
    language_filter: str = "python",
    db_dir: Optional[Path] = None,
) -> FixRetriever:
    """Download CVEfixes dataset and populate the retriever database.

    This creates a vector search index of historical vulnerability fixes
    that the Blue Agent can query for "hints" during patch generation.

    Args:
        max_examples: Maximum number of examples to store.
        language_filter: Filter by programming language.
        db_dir: Override database directory.

    Returns:
        The populated FixRetriever instance.
    """
    from datasets import load_dataset

    logger.info("Downloading CVEfixes dataset for retriever...")
    ds = load_dataset(cfg.data.cvefixes_name, split="train")
    df = ds.to_pandas()

    # Filter by language
    df["language"] = df["language"].fillna("").str.lower()
    df = df[df["language"].str.contains(language_filter.lower())]
    logger.info("CVEfixes: %d %s entries found", len(df), language_filter)

    examples: list[FixExample] = []
    for _, row in df.iterrows():
        vuln_code = str(row.get("vulnerable_code", "")).strip()
        fixed_code = str(row.get("fixed_code", "")).strip()

        if not vuln_code or not fixed_code:
            continue

        cwe = str(row.get("cwe_id", "unknown"))
        fix_id = hashlib.md5(
            (vuln_code + fixed_code).encode("utf-8", errors="replace")
        ).hexdigest()[:12]

        # Generate a brief diff summary
        vuln_lines = vuln_code.splitlines()
        fixed_lines = fixed_code.splitlines()
        diff_lines = list(
            set(fixed_lines) - set(vuln_lines)
        )
        summary = f"Added/changed {len(diff_lines)} lines to fix {cwe}"

        examples.append(
            FixExample(
                fix_id=fix_id,
                vulnerability_type=cwe,
                cwe_id=cwe,
                language=language_filter,
                vulnerable_code=vuln_code[:2000],  # Cap to prevent huge entries
                fixed_code=fixed_code[:2000],
                diff_summary=summary,
            )
        )

        if len(examples) >= max_examples:
            break

    logger.info("Created %d fix examples from CVEfixes", len(examples))

    retriever = FixRetriever(examples=examples)
    retriever.build_index()
    retriever.save(db_dir)

    # Update singleton
    global _retriever_instance
    _retriever_instance = retriever

    return retriever
