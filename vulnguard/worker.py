"""
RQ Worker script for consuming background scan tasks.
"""

from __future__ import annotations

import logging
from rq import Worker
from vulnguard.queue import get_redis_connection
from vulnguard.config import cfg

logger = logging.getLogger(__name__)


def start_worker():
    """Start an RQ worker listening on the default queue."""
    redis_conn = get_redis_connection()
    queues = [cfg.queue.queue_name]
    
    logger.info("Starting VulnGuard RQ worker on queue(s): %s", queues)
    
    # Pre-warm any imports or models if necessary
    from vulnguard.models.risk_scorer import RiskScorer
    try:
        RiskScorer()
        logger.info("Pre-warmed ML models")
    except FileNotFoundError:
        pass
        
    import os
    from rq import SimpleWorker
    worker_cls = SimpleWorker if os.name == 'nt' else Worker
        
    worker = worker_cls(queues, connection=redis_conn)
    worker.work(with_scheduler=False)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s │ %(levelname)-7s │ %(message)s")
    start_worker()
