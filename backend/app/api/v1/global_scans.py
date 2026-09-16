"""Global scans endpoint — scan runs across all projects."""
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import select

from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models.scan import ScanRun, ScanStatus, ScannerResult
from app.schemas.scan import ScanRunResponse

router = APIRouter()


@router.get("/", response_model=List[ScanRunResponse])
def list_all_scans(
    status: Optional[str] = Query(None),
    project_id: Optional[str] = Query(None),
    after: Optional[str] = Query(None, description="ISO datetime — return scans created after this"),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    query = select(ScanRun).options(selectinload(ScanRun.scanner_results))
    if status:
        query = query.where(ScanRun.status == status)
    if project_id:
        query = query.where(ScanRun.project_id == project_id)
    if after:
        try:
            after_dt = datetime.fromisoformat(after)
            query = query.where(ScanRun.created_at > after_dt)
        except ValueError:
            pass
    query = query.order_by(ScanRun.created_at.desc()).limit(limit)
    return db.execute(query).scalars().all()
