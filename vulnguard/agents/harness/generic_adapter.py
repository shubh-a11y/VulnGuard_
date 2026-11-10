"""Fallback adapter for languages without an execution path yet."""

from __future__ import annotations

from typing import Any, Mapping

from vulnguard.agents.harness.base import HarnessAdapter


class GenericAdapter(HarnessAdapter):
    """`unsupported`: a harness may be written, but it is never validated."""

    language = "generic"
    display_name = "Unsupported language"
    runtime_status = "unsupported"
    runtime_note = (
        "No sandbox execution path exists for this language. The Red Agent still "
        "reports what it can, but the result is never marked as security-validated."
    )

    def shape(self) -> str:
        return (
            "Write a complete runnable program in the target language with an entry "
            "point, load or link the real target, and print VULNGUARD_POC_SUCCESS "
            "only after the defect is observed."
        )

    def validation_error(self, report: Any, state: Mapping[str, Any]) -> str | None:
        return None
