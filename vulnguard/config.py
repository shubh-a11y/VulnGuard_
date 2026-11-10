"""
Central configuration for VulnGuard AI.

Loads settings from environment variables (.env file) with sensible defaults.
All thresholds, timeouts, API keys, and paths are defined here.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

# Load .env from project root
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_PROJECT_ROOT / ".env")


def _env(key: str, default: str = "") -> str:
    return os.getenv(key, default)


def _env_int(key: str, default: int = 0) -> int:
    return int(os.getenv(key, str(default)))


def _env_float(key: str, default: float = 0.0) -> float:
    return float(os.getenv(key, str(default)))


def _env_bool(key: str, default: bool = False) -> bool:
    return os.getenv(key, str(default)).lower() in ("true", "1", "yes")


# ---------------------------------------------------------------------------
# ML Triage Config
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class TriageConfig:
    """ML triage layer settings."""

    risk_threshold: int = _env_int("VULNGUARD_RISK_THRESHOLD", 65)
    model_path: Path = _PROJECT_ROOT / "vulnguard" / "models" / "artifacts" / "vulnguard_classifier.joblib"
    parse_timeout_seconds: int = _env_int("VULNGUARD_PARSE_TIMEOUT", 5)
    mega_function_loc_limit: int = 2000
    template_dampening_factor: float = 0.5
    # XGBoost training
    n_estimators: int = 300
    max_depth: int = 6
    learning_rate: float = 0.1
    early_stopping_rounds: int = 20
    use_smote: bool = _env_bool("VULNGUARD_USE_SMOTE", False)


# ---------------------------------------------------------------------------
# LLM / Agent Config
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class LLMConfig:
    """LLM provider settings (legacy single-model config)."""

    provider: str = _env("VULNGUARD_LLM_PROVIDER", "gemini")
    model_name: str = _env("VULNGUARD_LLM_MODEL", "gemini-3.8-flash")
    # Deterministic output — EC-7.5. NOTE: Gemini 3 models are documented to
    # reason best at temperature 1.0; Gemini 3 reasoning can also consume the
    # output budget before JSON completes, which is addressed by the
    # truncation retry escalation in vulnguard.agents.*_agent._call_llm.
    temperature: float = _env_float("VULNGUARD_LLM_TEMPERATURE", 0.0)
    max_tokens: int = _env_int("VULNGUARD_LLM_MAX_TOKENS", 4096)
    # A proof-of-concept harness is a complete program embedded in a JSON string,
    # so it needs more room than a diagnosis. Starting the harness call at this
    # budget is what stops reasoning tokens from truncating the JSON.
    harness_max_tokens: int = _env_int("VULNGUARD_LLM_HARNESS_MAX_TOKENS", 8192)
    # Hard cap for truncation escalation. The per-request budget doubles on
    # finish_reason=length up to this ceiling; once the ceiling is reached a
    # further identical request is pointless, so the call fails explicitly
    # instead of burning the retry budget on the same cap.
    max_token_ceiling: int = _env_int("VULNGUARD_LLM_MAX_TOKEN_CEILING", 16384)
    request_timeout_seconds: float = _env_float("VULNGUARD_LLM_TIMEOUT", 120.0)
    api_key: str = _env("GEMINI_API_KEY", "")
    # Retry / backoff — EC-7.4
    max_retries: int = _env_int("VULNGUARD_LLM_MAX_RETRIES", 3)
    retry_base_delay_seconds: float = _env_float("VULNGUARD_LLM_RETRY_DELAY", 2.0)
    mock_mode: bool = _env_bool("VULNGUARD_MOCK_LLM", False)


@dataclass(frozen=True)
class ModelRoutingConfig:
    """Severity-based model routing — routes high-risk to powerful models,
    medium-risk to cheaper ones. Reduces cost by ~60-70%."""

    high_risk_threshold: int = _env_int("VULNGUARD_HIGH_RISK_THRESHOLD", 80)
    # High-risk tier (score >= threshold) — complex multi-file vulns
    high_risk_provider: str = _env("VULNGUARD_HIGH_RISK_PROVIDER", "gemini")
    high_risk_model: str = _env("VULNGUARD_HIGH_RISK_MODEL", "gemini-3.1-pro-preview")
    # Medium-risk tier (score 65-79) — single-file, textbook vulns
    medium_risk_provider: str = _env("VULNGUARD_MEDIUM_RISK_PROVIDER", "gemini")
    medium_risk_model: str = _env("VULNGUARD_MEDIUM_RISK_MODEL", "gemini-3.1-pro-preview")

    def get_model_for_score(self, risk_score: float) -> tuple[str, str]:
        """Return (provider, model_name) for the given risk score."""
        if risk_score >= self.high_risk_threshold:
            return self.high_risk_provider, self.high_risk_model
        return self.medium_risk_provider, self.medium_risk_model


# ---------------------------------------------------------------------------
# Agent Pipeline Config
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class AgentConfig:
    """Multi-agent pipeline settings."""

    max_retry_attempts: int = _env_int("VULNGUARD_MAX_RETRIES", 3)
    context_token_budget: int = _env_int("VULNGUARD_CONTEXT_TOKEN_BUDGET", 6000)
    # Anti-triviality — Section 4.4
    min_ast_ratio: float = 0.4  # Patched must retain ≥40% of original AST nodes
    # Re-scan after patch — EC-7.3
    rescan_patched_code: bool = _env_bool("VULNGUARD_RESCAN_PATCH", True)
    # Flaky test double-run — Section 4.6
    double_run_validation: bool = True


# ---------------------------------------------------------------------------
# Docker Sandbox Config
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class SandboxConfig:
    """Docker sandbox settings."""

    memory_limit: str = _env("VULNGUARD_DOCKER_MEMORY", "512m")
    cpu_count: int = _env_int("VULNGUARD_DOCKER_CPUS", 1)
    pids_limit: int = 64
    network_mode: str = "none"
    execution_timeout_seconds: int = _env_int("VULNGUARD_DOCKER_TIMEOUT", 60)
    sandbox_image: str = _env("VULNGUARD_SANDBOX_IMAGE", "vulnguard-sandbox:latest")
    env_file: Optional[str] = _env("VULNGUARD_ENV_FILE") or None


# ---------------------------------------------------------------------------
# Data / Dataset Config
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class DataConfig:
    """Dataset and cache paths."""

    cache_dir: Path = _PROJECT_ROOT / "data" / "cache"
    # Legacy C/C++ dataset (DiverseVul)
    dataset_name: str = "benjis/DiverseVul"  # HuggingFace dataset ID
    # Python vulnerability datasets
    pycodevul_csv: str = "hf://datasets/S-AIR-L/PyCode-Vul/PyCode_Vul-train-set.csv"
    cvefixes_name: str = "hitoshura25/cvefixes"
    train_split_ratio: float = 0.8  # 80% train / 20% test by project


# ---------------------------------------------------------------------------
# Queue / Async Config
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class QueueConfig:
    """Redis and RQ settings."""

    redis_url: str = _env("VULNGUARD_REDIS_URL", "redis://localhost:6379/0")
    queue_name: str = _env("VULNGUARD_QUEUE_NAME", "vulnguard_scans")


# ---------------------------------------------------------------------------
# Aggregate Config
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class VulnGuardConfig:
    """Root config — single access point for all settings."""

    triage: TriageConfig = field(default_factory=TriageConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    routing: ModelRoutingConfig = field(default_factory=ModelRoutingConfig)
    agent: AgentConfig = field(default_factory=AgentConfig)
    sandbox: SandboxConfig = field(default_factory=SandboxConfig)
    data: DataConfig = field(default_factory=DataConfig)
    queue: QueueConfig = field(default_factory=QueueConfig)
    verbose: bool = _env_bool("VULNGUARD_VERBOSE", False)
    project_root: Path = _PROJECT_ROOT


# Singleton — importable as `from vulnguard.config import cfg`
cfg = VulnGuardConfig()
