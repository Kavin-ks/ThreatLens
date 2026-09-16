"""
Celery tasks for asynchronous scan execution.
The run_scan task is dispatched by the API and executed by a Celery worker.
"""
import json
import logging
from datetime import datetime, timezone

from app.workers.celery_app import celery_app
from app.core.database import SessionLocal
from app.models.scan import ScanRun, ScanStatus

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="threatlens.run_scan")
def run_scan(self, scan_run_id: str):
    """
    Execute a full scan run for the given scan_run_id.
    Dispatches each applicable scanner, collects findings, and updates the DB.
    """
    db = SessionLocal()
    try:
        scan_run = db.get(ScanRun, scan_run_id)
        if not scan_run:
            logger.error("Scan run %s not found", scan_run_id)
            return

        scan_run.status = ScanStatus.RUNNING
        db.commit()

        config = json.loads(scan_run.scanner_config or "{}")

        # Import here to avoid circular imports at module load time
        from scanners.orchestrator import ScanOrchestrator
        from scanners.models import ScanTarget
        from pathlib import Path

        target = ScanTarget(
            project_id=scan_run.project_id,
            target_path=Path(config["target_path"]) if config.get("target_path") else None,
            target_url=config.get("target_url"),
        )

        orchestrator = ScanOrchestrator(db=db)
        summary = orchestrator.run(scan_run=scan_run, target=target, scanner_ids=config.get("scanner_ids"))

        scan_run.status = ScanStatus.COMPLETED
        scan_run.summary = json.dumps(summary)
        db.commit()

    except Exception as exc:
        logger.exception("Scan run %s failed: %s", scan_run_id, exc)
        if scan_run:
            scan_run.status = ScanStatus.FAILED
            scan_run.error_message = str(exc)
            db.commit()
        raise self.retry(exc=exc, max_retries=0)
    finally:
        db.close()
