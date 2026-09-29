from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import select
from app.core.database import get_db
from app.models.report import SecurityReport
from app.schemas.report import ReportResponse

router = APIRouter()


@router.get("/", response_model=List[ReportResponse])
def list_global_reports(
    project_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """List security reports across all projects or filtered by project_id."""
    query = select(SecurityReport)
    if project_id:
        query = query.where(SecurityReport.project_id == project_id)
    reports = db.execute(query.order_by(SecurityReport.created_at.desc())).scalars().all()
    return reports
