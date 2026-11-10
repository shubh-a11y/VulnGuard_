"""Adapter registry for language-aware harness generation."""

from __future__ import annotations

from vulnguard.agents.harness.base import HarnessAdapter
from vulnguard.agents.harness.c_adapter import CAdapter, CppAdapter
from vulnguard.agents.harness.generic_adapter import GenericAdapter
from vulnguard.agents.harness.java_adapter import JavaAdapter
from vulnguard.agents.harness.javascript_adapter import JavaScriptAdapter
from vulnguard.agents.harness.python_adapter import PythonAdapter

_CONCRETE: tuple[HarnessAdapter, ...] = (
    PythonAdapter(),
    CAdapter(),
    CppAdapter(),
    JavaScriptAdapter(),
    JavaAdapter(),
)

_BY_ALIAS: dict[str, HarnessAdapter] = {}
for _adapter in _CONCRETE:
    _BY_ALIAS[_adapter.language] = _adapter
    for _alias in _adapter.aliases:
        _BY_ALIAS[_alias] = _adapter

_GENERIC = GenericAdapter()


def get_adapter(language: str | None) -> HarnessAdapter:
    """Return the adapter for a language name/alias, or the generic fallback."""
    key = (language or "").strip().lower()
    return _BY_ALIAS.get(key, _GENERIC)


def supported_languages() -> tuple[str, ...]:
    """Languages with a real adapter (executed or experimental)."""
    return tuple(adapter.language for adapter in _CONCRETE)


def executable_languages() -> tuple[str, ...]:
    """Languages the sandbox runner executes today."""
    return tuple(
        adapter.language for adapter in _CONCRETE if adapter.runtime_status == "verified"
    )


def adapter_capabilities() -> list[dict[str, object]]:
    """Documented support matrix (also used by the docs and tests)."""
    return [adapter.to_dict() for adapter in _CONCRETE]


__all__ = [
    "HarnessAdapter",
    "get_adapter",
    "supported_languages",
    "executable_languages",
    "adapter_capabilities",
]
