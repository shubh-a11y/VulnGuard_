"""
LangGraph state graph wiring for the VulnGuard pipeline.

Connects: Triage → Red Agent → Blue Agent → Judge Agent
with conditional edges for short-circuiting (safe/no-vuln)
and retry loops (Judge → Blue).
"""

from __future__ import annotations

import logging
import time
from typing import Any

from langgraph.graph import END, StateGraph

from vulnguard.agents.blue_agent import blue_agent_node
from vulnguard.agents.judge_agent import JudgeVerdict, judge_agent_node
from vulnguard.agents.red_agent import red_agent_node
from vulnguard.agents.state import VulnGuardState, initial_state
from vulnguard.config import cfg


logger = logging.getLogger(__name__)


# ── Conditional edge functions ────────────────────────────────────────────

def _after_red(state: VulnGuardState) -> str:
    """Route after Red Agent: Blue if vuln found, else END."""
    if state.get("vulnerability_found"):
        return "blue_agent"
    if state.get("pipeline_status") == "RED_ERROR":
        # Generation/parsing failure is not a confirmed negative detection.
        logger.warning(
            "🔴 Red Agent failed to produce a valid report for %s — ending pipeline with RED_AGENT_ERROR",
            state.get("function_id", "unknown"),
        )
        return END
    logger.info("🟢 No vulnerability found — skipping Blue/Judge")
    return END


def _after_judge(state: VulnGuardState) -> str:
    """Route after Judge: END if PASS or FAILED, Blue if RETRY."""
    status = state.get("pipeline_status", "")
    if status == "COMPLETE":
        logger.info("✅ Pipeline COMPLETE — patch validated")
        return END
    if status == "FAILED":
        logger.warning(
            "❌ Pipeline FAILED — verdict=%s", state.get("judge_verdict", "unknown")
        )
        return END
    # RETRY → back to Blue Agent
    return "blue_agent"


# ── Graph builder ─────────────────────────────────────────────────────────

def build_graph() -> StateGraph:
    """Build the VulnGuard LangGraph state graph.

    Graph topology:
        red_agent → [vuln_found?] → blue_agent → judge_agent
                                                  ↓ (RETRY)
                                                  blue_agent
    """
    graph = StateGraph(VulnGuardState)

    # Add nodes
    graph.add_node("red_agent", red_agent_node)
    graph.add_node("blue_agent", blue_agent_node)
    graph.add_node("judge_agent", judge_agent_node)

    # Set entry point
    graph.set_entry_point("red_agent")

    # Conditional edges
    graph.add_conditional_edges("red_agent", _after_red, {"blue_agent": "blue_agent", END: END})
    graph.add_edge("blue_agent", "judge_agent")
    graph.add_conditional_edges("judge_agent", _after_judge, {"blue_agent": "blue_agent", END: END})

    return graph


def compile_graph(checkpointer=None):
    """Compile the graph with optional checkpointing (EC-7.4).

    Args:
        checkpointer: LangGraph checkpointer (SqliteSaver, PostgresSaver, etc.).
                      Enables fault-tolerant resume after crashes.

    Returns:
        Compiled LangGraph application.
    """
    graph = build_graph()
    return graph.compile(checkpointer=checkpointer)


# ── Convenience runner ────────────────────────────────────────────────────


def run_pipeline(
    function_id: str,
    code: str,
    language: str = "c",
    risk_score: float = 100.0,
    context_bundle: dict | None = None,
    file_path: str = "",
    repo_root: str = "",
    start_byte: int | None = None,
    end_byte: int | None = None,
    max_attempts: int | None = None,
    checkpointer=None,
) -> VulnGuardState:
    """Run the full VulnGuard pipeline for a single function.

    Args:
        function_id: Unique identifier for the function being analyzed.
        code: Source code of the function.
        language: Programming language.
        risk_score: Pre-computed ML risk score (0-100).
        context_bundle: Serialized ContextBundle dict.
        file_path: Path to the source file.
        repo_root: Repository root path.
        start_byte: Start byte offset of the function in the file.
        end_byte: End byte offset of the function in the file.
        max_attempts: Override max retry attempts.
        checkpointer: LangGraph checkpointer for fault tolerance.

    Returns:
        Final pipeline state after execution.
    """
    max_att = max_attempts or cfg.agent.max_retry_attempts
    state = initial_state(
        function_id=function_id,
        code=code,
        language=language,
        risk_score=risk_score,
        context_bundle=context_bundle or {},
        file_path=file_path,
        repo_root=repo_root,
        start_byte=start_byte,
        end_byte=end_byte,
        max_attempts=max_att,
    )
    state["timestamps"] = {"pipeline_start": time.time()}

    app = compile_graph(checkpointer=checkpointer)
    final_state = app.invoke(state)

    final_state["timestamps"]["pipeline_end"] = time.time()
    elapsed = final_state["timestamps"]["pipeline_end"] - final_state["timestamps"]["pipeline_start"]
    logger.info(
        "Pipeline finished: status=%s, verdict=%s, attempts=%d, time=%.1fs",
        final_state.get("pipeline_status"),
        final_state.get("judge_verdict"),
        final_state.get("attempt_number", 0) + 1,
        elapsed,
    )

    return final_state
