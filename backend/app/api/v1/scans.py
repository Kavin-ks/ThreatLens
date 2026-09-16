from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import select
from app.core.database import get_db
from app.models.project import Project
from app.models.scan import ScanRun, ScanStatus
from app.schemas.scan import ScanTriggerRequest, ScanRunResponse
import json

router = APIRouter()


@router.get("/", response_model=List[ScanRunResponse])
def list_scans(project_id: str, db: Session = Depends(get_db)):
    _get_project_or_404(project_id, db)
    runs = db.execute(
        select(ScanRun)
        .where(ScanRun.project_id == project_id)
        .order_by(ScanRun.created_at.desc())
    ).scalars().all()
    return runs


@router.post("/", response_model=ScanRunResponse, status_code=status.HTTP_202_ACCEPTED)
def trigger_scan(
    project_id: str,
    payload: ScanTriggerRequest,
    db: Session = Depends(get_db),
):
    """
    Trigger a new security scan run for this project.
    Returns immediately with status=pending; scan runs asynchronously via Celery.
    """
    project = _get_project_or_404(project_id, db)

    config = {
        "scanner_ids": payload.scanner_ids,
        "target_path": project.target_path,
        "target_url": project.target_url,
        "options": payload.options or {},
    }

    scan_run = ScanRun(
        project_id=project_id,
        status=ScanStatus.PENDING,
        scanner_config=json.dumps(config),
    )
    db.add(scan_run)
    db.commit()
    db.refresh(scan_run)

    # Dispatch Celery task (when Celery/Redis is available)
    try:
        from app.workers.scan_tasks import run_scan
        task = run_scan.delay(scan_run.id)
        scan_run.celery_task_id = task.id
        db.commit()
    except Exception:
        # Celery not available in development without Redis — scan stays PENDING
        pass

    return scan_run


@router.get("/{scan_id}", response_model=ScanRunResponse)
def get_scan(project_id: str, scan_id: str, db: Session = Depends(get_db)):
    _get_project_or_404(project_id, db)
    run = db.execute(
        select(ScanRun).where(ScanRun.id == scan_id, ScanRun.project_id == project_id)
    ).scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Scan run not found")
    return run


def _get_project_or_404(project_id: str, db: Session) -> Project:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project
