"""
RQ integration for running VulnGuard pipelines asynchronously.
"""

from __future__ import annotations

import logging
from redis import Redis
from rq import Queue
from vulnguard.config import cfg

logger = logging.getLogger(__name__)


def get_redis_connection() -> Redis:
    """Get a connected Redis instance."""
    return Redis.from_url(cfg.queue.redis_url)


def get_queue() -> Queue:
    """Get the RQ Queue for background scans."""
    redis_conn = get_redis_connection()
    return Queue(cfg.queue.queue_name, connection=redis_conn)


def enqueue_scan(
    function_id: str,
    code: str,
    language: str,
    risk_score: float,
    context_bundle: dict,
    file_path: str,
    repo_root: str,
    start_byte: int | None = None,
    end_byte: int | None = None,
):
    """Push a scan task to the RQ background queue."""
    q = get_queue()
    job = q.enqueue(
        "vulnguard.queue.run_scan_job",
        kwargs={
            "function_id": function_id,
            "code": code,
            "language": language,
            "risk_score": risk_score,
            "context_bundle": context_bundle,
            "file_path": file_path,
            "repo_root": repo_root,
            "start_byte": start_byte,
            "end_byte": end_byte,
        },
        job_timeout="10m",
        result_ttl=86400,
    )
    logger.info("Enqueued background scan job %s for %s", job.id, function_id)
    return job


def run_scan_job(**kwargs):
    """Wrapper function executed by the RQ worker."""
    from vulnguard.agents.graph import run_pipeline
    
    # We re-import config inside the worker to ensure it initializes fresh if needed
    from vulnguard.config import cfg
    
    logger.info("Worker processing scan for %s", kwargs.get("function_id"))
    state = run_pipeline(**kwargs)
    
    # Return serializable summary of the state
    return {
        "status": state.get("pipeline_status"),
        "verdict": state.get("judge_verdict"),
        "vuln_found": state.get("vulnerability_found"),
        "attempts": state.get("attempt_number", 0) + 1,
    }
