"""Per-scan event bridge for progressive agent streaming.

LangGraph only hands the WebSocket handler a completed node's state. The live
stream needs the actual intermediate results (diagnosis, harness, patch,
sandbox runs) as they happen, so a node emits through this module while it is
executing.

Why a registry instead of a field on the state: the graph runs sync nodes in a
worker thread, so `contextvars` set by the WebSocket coroutine are not reliably
visible inside them, and a callback inside `VulnGuardState` is not a value
LangGraph should have to merge. A small locked registry keyed by `scan_id` is
thread-safe, needs no graph changes, and is a no-op when no client is attached
(evaluation runs, CLI, tests).

Events are plain dictionaries of real data only — never model
chain-of-thought, never invented progress.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)

EventSink = Callable[[dict[str, Any]], None]

_SINKS: dict[str, EventSink] = {}
_LOCK = threading.Lock()


def bind_events(scan_id: str, sink: EventSink) -> None:
    """Route events for ``scan_id`` to ``sink`` until it is unbound."""
    if not scan_id:
        return
    with _LOCK:
        _SINKS[scan_id] = sink


def unbind_events(scan_id: str) -> None:
    """Stop routing events for a finished scan."""
    with _LOCK:
        _SINKS.pop(scan_id, None)


def emit(state: dict[str, Any], event_type: str, **payload: Any) -> None:
    """Emit one real event for the scan that owns ``state``.

    Never raises: a broken sink must not fail an agent node or invalidate a
    result that was already computed.
    """
    scan_id = str(state.get("scan_id") or "")
    if not scan_id:
        return
    with _LOCK:
        sink = _SINKS.get(scan_id)
    if sink is None:
        return

    event: dict[str, Any] = {
        "type": event_type,
        "scan_id": scan_id,
        "function_id": state.get("function_id", ""),
    }
    event.update(payload)
    try:
        sink(event)
    except Exception:  # pragma: no cover - defensively never break the node
        logger.exception("Failed to deliver %s event for scan %s", event_type, scan_id)
