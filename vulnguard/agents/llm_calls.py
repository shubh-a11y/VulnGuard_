"""Shared, bounded LLM invocation for the agent nodes.

Why this module exists (see context.md §Agent reliability):
  - Provider failures must surface as *typed* errors so an agent node can turn
    them into explicit pipeline state instead of letting an exception escape
    through LangGraph and crash the WebSocket scan handler.
  - A truncated completion (``finish_reason=length``) is retried with a larger
    output budget, but only up to a configured ceiling. Asking again with the
    same cap is guaranteed to fail and only burns latency and money.
  - Permanent failures (auth, bad request, unsupported parameter) are not
    retried; transient ones (rate limit, timeout, connection) use bounded
    exponential backoff.
"""

from __future__ import annotations

import logging
from typing import Any

from vulnguard.config import cfg

logger = logging.getLogger(__name__)


class LLMCallError(RuntimeError):
    """Base class for an exhausted or non-retryable LLM call."""

    def __init__(
        self,
        message: str,
        *,
        attempts_used: int = 0,
        finish_reason: str = "",
        partial_response: str = "",
    ) -> None:
        super().__init__(message)
        self.attempts_used = attempts_used
        self.finish_reason = finish_reason
        self.partial_response = partial_response


class LLMTruncationError(LLMCallError):
    """The provider stopped because the output budget ran out, every time."""


class LLMProviderError(LLMCallError):
    """The provider failed in a way that retrying cannot fix (or ran out)."""


# Provider errors that are worth retrying. Everything else fails fast.
_TRANSIENT_NAMES = (
    "RateLimitError",
    "Timeout",
    "APIConnectionError",
    "ServiceUnavailableError",
    "InternalServerError",
)


def _is_transient(exc: Exception) -> bool:
    try:
        import litellm

        transient = tuple(
            getattr(litellm.exceptions, name)
            for name in _TRANSIENT_NAMES
            if hasattr(litellm.exceptions, name)
        )
    except Exception:  # pragma: no cover - litellm is a hard dependency
        return False
    return bool(transient) and isinstance(exc, transient)


def _backoff_seconds(attempt: int, base_delay: float) -> float:
    return min(base_delay * (2 ** max(attempt - 1, 0)), 30.0)


def call_llm_json(
    messages: list[dict],
    *,
    model: str,
    attempts: int | None = None,
    base_max_tokens: int | None = None,
    temperature: float | None = None,
    ceiling: int | None = None,
    timeout: float | None = None,
    retry_base_delay: float | None = None,
) -> str:
    """Call the model for a JSON object response, with bounded recovery.

    Args:
        messages: Chat messages.
        model: LiteLLM model id (``provider/model``).
        attempts: Total provider calls allowed (default ``cfg.llm.max_retries``).
        base_max_tokens: Initial completion budget.
        temperature: Sampling temperature override.

    Returns:
        The assistant text with one surrounding Markdown fence removed.

    Raises:
        LLMTruncationError: output budget exhausted (or ceiling reached).
        LLMProviderError: non-retryable provider failure or retries exhausted.
    """
    from vulnguard.llm_runtime import completion, response_text
    from vulnguard.agents.llm_parsing import (
        finish_reason,
        is_truncated_response,
        raw_response_preview,
        strip_code_fences,
    )

    total_attempts = max(int(attempts or cfg.llm.max_retries or 1), 1)
    ceiling = max(int(ceiling if ceiling is not None else cfg.llm.max_token_ceiling), 1)
    budget = min(int(base_max_tokens or cfg.llm.max_tokens), ceiling)
    temperature = cfg.llm.temperature if temperature is None else temperature
    timeout = timeout if timeout is not None else cfg.llm.request_timeout_seconds
    base_delay = (
        retry_base_delay
        if retry_base_delay is not None
        else cfg.llm.retry_base_delay_seconds
    )

    for attempt in range(1, total_attempts + 1):
        try:
            response = completion(
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=budget,
                timeout=timeout,
                response_format={"type": "json_object"},
            )
        except Exception as exc:
            if not _is_transient(exc):
                logger.error("LLM call failed permanently (%s): %s", model, exc)
                raise LLMProviderError(
                    f"LLM provider rejected the request: {exc}",
                    attempts_used=attempt,
                ) from exc
            if attempt >= total_attempts:
                logger.error("LLM call failed after %d attempts: %s", attempt, exc)
                raise LLMProviderError(
                    f"LLM provider unavailable after {attempt} attempts: {exc}",
                    attempts_used=attempt,
                ) from exc
            delay = _backoff_seconds(attempt, base_delay)
            logger.warning(
                "Transient LLM error (attempt %d/%d): %s — retrying in %.1fs",
                attempt,
                total_attempts,
                exc,
                delay,
            )
            if delay:
                import time

                time.sleep(delay)
            continue

        if is_truncated_response(response):
            reason = finish_reason(response) or "unknown"
            try:
                partial = raw_response_preview(response_text(response))
            except Exception:
                partial = ""
            if budget >= ceiling:
                raise LLMTruncationError(
                    "LLM response truncated (finish_reason=%s) at the %d-token "
                    "ceiling; the requested output does not fit the budget"
                    % (reason, ceiling),
                    attempts_used=attempt,
                    finish_reason=reason,
                    partial_response=partial,
                )
            if attempt >= total_attempts:
                raise LLMTruncationError(
                    "LLM response truncated (finish_reason=%s) after %d attempts"
                    % (reason, attempt),
                    attempts_used=attempt,
                    finish_reason=reason,
                    partial_response=partial,
                )
            budget = min(budget * 2, ceiling)
            logger.warning(
                "Attempt %d/%d truncated (finish_reason=%s) — retrying with "
                "max_tokens=%d",
                attempt,
                total_attempts,
                reason,
                budget,
            )
            continue

        try:
            return strip_code_fences(response_text(response))
        except ValueError as exc:
            if attempt >= total_attempts:
                raise LLMProviderError(
                    f"LLM returned no usable content after {attempt} attempts: {exc}",
                    attempts_used=attempt,
                    finish_reason=finish_reason(response),
                ) from exc
            delay = _backoff_seconds(attempt, base_delay)
            logger.warning(
                "Empty LLM content (attempt %d/%d): %s — retrying in %.1fs",
                attempt,
                total_attempts,
                exc,
                delay,
            )
            if delay:
                import time

                time.sleep(delay)
            continue

    # Unreachable: every branch either returns or raises.
    raise LLMProviderError("LLM call exhausted without a response")  # pragma: no cover
