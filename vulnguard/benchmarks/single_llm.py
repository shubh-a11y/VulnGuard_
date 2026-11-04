"""
Baseline 2: Single direct-prompt LLM vulnerability fix.

Sends vulnerable code directly to an LLM with a one-shot "find and fix"
prompt. No multi-agent pipeline, no triage, no sandbox validation.
Used as a benchmark comparison against VulnGuard's multi-agent approach.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass

from pydantic import BaseModel, Field
from typing import Optional

from vulnguard.config import cfg

logger = logging.getLogger(__name__)


class SingleLLMResult(BaseModel):
    """Output schema for the single-LLM baseline."""

    vulnerability_found: bool = False
    vulnerability_type: Optional[str] = None
    explanation: Optional[str] = None
    patched_code: Optional[str] = None
    fix_summary: Optional[str] = None


@dataclass
class SingleLLMBenchmark:
    """Benchmark result for a single function."""

    function_id: str
    result: SingleLLMResult
    token_count: int = 0
    elapsed_seconds: float = 0.0
    error: str = ""


_PROMPT = """\
You are a security expert. Analyze the following {language} function for security vulnerabilities.

If you find a vulnerability:
1. Identify the vulnerability type and affected lines
2. Provide a COMPLETE patched version of the function that fixes the vulnerability
3. The patch must preserve the function signature, behavior, and all existing logic

If the function is safe, set vulnerability_found=false.

Function:
```{language}
{code}
```

Respond with a JSON object:
{{
  "vulnerability_found": true/false,
  "vulnerability_type": "type or null",
  "explanation": "explanation or null",
  "patched_code": "complete patched function or null",
  "fix_summary": "one-line summary or null"
}}
"""


def run_single_llm(
    function_id: str,
    code: str,
    language: str = "c",
) -> SingleLLMBenchmark:
    """Run the single-LLM baseline on a function.

    Args:
        function_id: Unique function identifier.
        code: Source code to analyze.
        language: Programming language.

    Returns:
        SingleLLMBenchmark with result and cost metrics.
    """
    from vulnguard.llm_runtime import completion

    model = f"{cfg.llm.provider}/{cfg.llm.model_name}"
    prompt = _PROMPT.format(language=language, code=code)

    start = time.time()
    try:
        response = completion(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0,
            max_tokens=cfg.llm.max_tokens,
            response_format={"type": "json_object"},
        )

        raw = response.choices[0].message.content
        token_count = getattr(response.usage, "total_tokens", 0)

        try:
            result = SingleLLMResult.model_validate_json(raw)
        except Exception:
            data = json.loads(raw)
            result = SingleLLMResult(**data)

        return SingleLLMBenchmark(
            function_id=function_id,
            result=result,
            token_count=token_count,
            elapsed_seconds=time.time() - start,
        )

    except Exception as exc:
        logger.error("Single LLM baseline failed: %s", exc)
        return SingleLLMBenchmark(
            function_id=function_id,
            result=SingleLLMResult(),
            elapsed_seconds=time.time() - start,
            error=str(exc),
        )
