"""
Scan execution — shared logic callable from Celery or FastAPI BackgroundTasks.
"""
import json
import logging
from pathlib import Path

from app.workers.celery_app import celery_app
from app.core.database import SessionLocal
from app.models.scan import ScanRun, ScanStatus

logger = logging.getLogger(__name__)


def execute_scan(scan_run_id: str) -> None:
    """
    Execute a scan run synchronously using its own DB session.
    Safe to call from both Celery tasks and FastAPI BackgroundTasks.
    """
    db = SessionLocal()
    scan_run = None
    try:
        scan_run = db.get(ScanRun, scan_run_id)
        if not scan_run:
            logger.error("Scan run %s not found", scan_run_id)
            return

        scan_run.status = ScanStatus.RUNNING
        db.commit()

        config = json.loads(scan_run.scanner_config or "{}")

        from scanners.orchestrator import ScanOrchestrator
        from scanners.models import ScanTarget

        target = ScanTarget(
            project_id=scan_run.project_id,
            target_path=Path(config["target_path"]) if config.get("target_path") else None,
            target_url=config.get("target_url"),
        )

        orchestrator = ScanOrchestrator(db=db)
        summary = orchestrator.run(
            scan_run=scan_run,
            target=target,
            scanner_ids=config.get("scanner_ids"),
        )

        scan_run.status = ScanStatus.COMPLETED
        scan_run.summary = json.dumps(summary)
        db.commit()

    except Exception as exc:
        logger.exception("Scan run %s failed: %s", scan_run_id, exc)
        if scan_run:
            try:
                db.refresh(scan_run)
                scan_run.status = ScanStatus.FAILED
                scan_run.error_message = str(exc)[:2048]
                db.commit()
            except Exception:
                pass
        raise
    finally:
        db.close()


@celery_app.task(bind=True, name="threatlens.run_scan")
def run_scan(self, scan_run_id: str):
    """Celery task wrapper — delegates to execute_scan."""
    try:
        execute_scan(scan_run_id)
    except Exception as exc:
        raise self.retry(exc=exc, max_retries=0)
