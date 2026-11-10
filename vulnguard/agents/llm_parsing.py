"""
Shared LLM response handling — structured-JSON extraction, parsing, and
truncation detection used by the Red and Blue agent nodes.

Goals (see context.md §Agent reliability):
  - One well-defined parsing path per agent schema (no per-agent str slicing).
  - Markdown code fences are handled without brittle `.split("```")` chains
    that silently corrupt JSON containing fence-like text.
  - Truncated completions (finish_reason length/MAX_TOKENS) are detected so a
    caller can retry with a larger output budget.
  - A parse failure NEVER becomes a default "no vulnerability" result.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from pydantic import BaseModel

logger = logging.getLogger(__name__)

_FENCE_RE = re.compile(r"^```[a-zA-Z0-9_-]*\s*\n(.*?)\n?```\s*$", re.DOTALL)

# LiteLLM finishes truncated completions with one of these reasons.
_TRUNCATED_FINISH_REASONS = {"length", "max_tokens"}


def strip_code_fences(text: str) -> str:
    """Return the text with a single surrounding Markdown fence removed.

    Only strips a fence that wraps the whole payload; JSON embedded in
    prose without fences is returned trimmed, unchanged otherwise.
    """
    if not text:
        return ""
    trimmed = text.strip()
    match = _FENCE_RE.match(trimmed)
    if match:
        return match.group(1).strip()
    return trimmed


def unwrap_schema_payload(data: Any, schema: type[BaseModel]) -> Any:
    """Unwrap a JSON payload that echoes the schema itself.

    Some models respond with their own schema description
    ({"type": "object", "properties": {...}}); the real values then live
    under "properties". Only unwraps when no schema field name appears on
    top level and "properties" carries the required fields.
    """
    fields = list(schema.model_fields.keys())
    if not isinstance(data, dict):
        return data
    if any(field in data for field in fields):
        return data
    properties = data.get("properties")
    if isinstance(properties, dict) and any(field in properties for field in fields):
        return properties
    return data


def parse_agent_json(
    raw: str,
    schema: type[BaseModel],
) -> tuple[Any, str]:
    """Parse an assistant completion into a ``schema`` instance.

    Accepts plain JSON objects and whole-payload Markdown code fences.

    Returns:
        (instance, "") on success or (None, failure_reason) on failure. The
        failure reason lists what was attempted so diagnostics stay
        actionable without dumping the whole response into logs.
    """
    stripped = (raw or "").strip()
    if not stripped:
        return None, "empty response text"

    candidates = [stripped]
    inner = strip_code_fences(stripped)
    if inner and inner != stripped:
        candidates.append(inner)
    # A model may wrap the JSON object in prose; recover the object itself
    # (never arbitrary code) before giving up on the response.
    embedded = _first_json_object(stripped)
    if embedded and embedded not in candidates:
        candidates.append(embedded)

    errors: list[str] = []
    for payload in candidates:
        try:
            return schema.model_validate_json(payload), ""
        except Exception as exc:
            errors.append(f"schema validation: {exc}")
        try:
            data = json.loads(payload)
            instance = schema.model_validate(unwrap_schema_payload(data, schema))
            return instance, ""
        except Exception as exc:
            errors.append(f"dict coercion: {exc}")

    return None, "; ".join(errors)


def _first_json_object(text: str) -> str:
    """Return the first balanced ``{...}`` object in ``text``, or "".

    Only a syntactically balanced object is returned, so a truncated response
    still fails to parse instead of being silently repaired into a wrong value.
    """
    start = text.find("{")
    while start != -1:
        depth = 0
        in_string = False
        escaped = False
        for index in range(start, len(text)):
            char = text[index]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return text[start : index + 1].strip()
        start = text.find("{", start + 1)
    return ""


def finish_reason(response: Any) -> str:
    """Best-effort extraction of the completion finish reason."""
    try:
        reason = response.choices[0].finish_reason
    except (AttributeError, IndexError, TypeError):
        return ""
    return str(reason or "")


def is_truncated_response(response: Any) -> bool:
    """True when the provider reported that the completion ran out of budget."""
    return finish_reason(response).lower() in _TRUNCATED_FINISH_REASONS


def raw_response_preview(raw: str, limit: int = 400) -> str:
    """Return a short, log-safe preview of an assistant response."""
    if not raw:
        return "(empty)"
    preview = raw.strip()
    if len(preview) <= limit:
        return preview
    return f"{preview[:limit]}... [truncated, {len(preview)} chars total]"
