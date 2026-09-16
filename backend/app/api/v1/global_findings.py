"""Global findings endpoint — findings across all projects."""
from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.core.database import get_db
from app.models.finding import Finding
from app.schemas.finding import FindingSummary

router = APIRouter()


class GlobalFindingSummary(FindingSummary):
    project_id: str

    model_config = {"from_attributes": True}


@router.get("/", response_model=List[GlobalFindingSummary])
def list_all_findings(
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    confidence: Optional[str] = Query(None),
    project_id: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=500),
    db: Session = Depends(get_db),
):
    query = select(Finding)
    if severity:
        query = query.where(Finding.severity == severity)
    if status:
        query = query.where(Finding.status == status)
    if category:
        query = query.where(Finding.category == category)
    if confidence:
        query = query.where(Finding.confidence == confidence)
    if project_id:
        query = query.where(Finding.project_id == project_id)
    if search:
        like = f"%{search}%"
        query = query.where(
            Finding.title.ilike(like) | Finding.description.ilike(like)
        )
    query = query.order_by(Finding.created_at.desc()).limit(limit)
    return db.execute(query).scalars().all()
