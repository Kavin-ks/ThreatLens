from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, selectinload
from sqlalchemy import select
from app.core.database import get_db
from app.models.project import Project
from app.models.finding import Finding, FindingStatus, Severity, SecurityCategory
from app.models.finding import FindingHistory
from app.schemas.finding import FindingResponse, FindingStatusUpdate, FindingSummary

router = APIRouter()


@router.get("/", response_model=List[FindingSummary])
def list_findings(
    project_id: str,
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    confidence: Optional[str] = Query(None),
    scan_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    _get_project_or_404(project_id, db)
    query = select(Finding).where(Finding.project_id == project_id)
    if severity:
        query = query.where(Finding.severity == severity)
    if status:
        query = query.where(Finding.status == status)
    if category:
        query = query.where(Finding.category == category)
    if confidence:
        query = query.where(Finding.confidence == confidence)
    if scan_id:
        query = query.where(Finding.scan_run_id == scan_id)
    query = query.order_by(Finding.created_at.desc())
    findings = db.execute(query).scalars().all()
    return findings


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding(project_id: str, finding_id: str, db: Session = Depends(get_db)):
    _get_project_or_404(project_id, db)
    finding = db.execute(
        select(Finding)
        .options(
            selectinload(Finding.evidence),
            selectinload(Finding.history),
        )
        .where(Finding.id == finding_id, Finding.project_id == project_id)
    ).scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.patch("/{finding_id}/status", response_model=FindingResponse)
def update_finding_status(
    project_id: str,
    finding_id: str,
    payload: FindingStatusUpdate,
    db: Session = Depends(get_db),
):
    """Update the lifecycle status of a finding and record the transition."""
    _get_project_or_404(project_id, db)
    finding = db.execute(
        select(Finding)
        .options(
            selectinload(Finding.evidence),
            selectinload(Finding.history),
        )
        .where(Finding.id == finding_id, Finding.project_id == project_id)
    ).scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    history_entry = FindingHistory(
        finding_id=finding.id,
        from_status=finding.status,
        to_status=payload.status,
        changed_by="user",
        note=payload.note,
    )
    db.add(history_entry)
    finding.status = payload.status
    db.commit()
    db.refresh(finding)
    return finding


def _get_project_or_404(project_id: str, db: Session) -> Project:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project
