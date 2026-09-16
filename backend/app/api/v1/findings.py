from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.orm import Session, selectinload
from sqlalchemy import select
from app.core.database import get_db
from app.models.project import Project
from app.models.finding import Finding, FindingStatus, FindingHistory, Confidence
from app.models.remediation import RemediationRecord, RetestStatus
from app.schemas.finding import FindingResponse, FindingStatusUpdate, FindingSummary
from app.schemas.remediation import (
    RemediationRecordCreate,
    RemediationRecordResponse,
    RetestRequest,
    RetestResponse,
    ValidateFindingRequest,
)

router = APIRouter()


# ─── Findings list / detail ────────────────────────────────────────────────────

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
            selectinload(Finding.remediation_records),
        )
        .where(Finding.id == finding_id, Finding.project_id == project_id)
    ).scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


# ─── Status update ─────────────────────────────────────────────────────────────

@router.patch("/{finding_id}/status", response_model=FindingResponse)
def update_finding_status(
    project_id: str,
    finding_id: str,
    payload: FindingStatusUpdate,
    db: Session = Depends(get_db),
):
    _get_project_or_404(project_id, db)
    finding = db.execute(
        select(Finding)
        .options(
            selectinload(Finding.evidence),
            selectinload(Finding.history),
            selectinload(Finding.remediation_records),
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


# ─── Validation ───────────────────────────────────────────────────────────────

@router.post("/{finding_id}/validate", response_model=FindingResponse)
def validate_finding(
    project_id: str,
    finding_id: str,
    payload: ValidateFindingRequest,
    db: Session = Depends(get_db),
):
    """
    Update a finding's confidence level and record the validation action.
    Moves status to CONFIRMED when confidence is CONFIRMED/LIKELY,
    or REJECTED when FALSE_POSITIVE.
    """
    _get_project_or_404(project_id, db)
    finding = db.execute(
        select(Finding)
        .options(
            selectinload(Finding.evidence),
            selectinload(Finding.history),
            selectinload(Finding.remediation_records),
        )
        .where(Finding.id == finding_id, Finding.project_id == project_id)
    ).scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    old_status = finding.status
    finding.confidence = payload.confidence

    # Auto-advance status based on confidence
    if payload.confidence == Confidence.FALSE_POSITIVE:
        new_status = FindingStatus.REJECTED
    elif payload.confidence in (Confidence.CONFIRMED, Confidence.LIKELY):
        new_status = FindingStatus.CONFIRMED
    else:
        new_status = FindingStatus.VALIDATING

    finding.status = new_status
    db.add(FindingHistory(
        finding_id=finding.id,
        from_status=old_status,
        to_status=new_status,
        changed_by="user",
        note=payload.note or f"Validated as {payload.confidence}",
    ))
    db.commit()
    db.refresh(finding)
    return finding


# ─── Remediation records ──────────────────────────────────────────────────────

@router.get("/{finding_id}/remediation", response_model=List[RemediationRecordResponse])
def list_remediation(project_id: str, finding_id: str, db: Session = Depends(get_db)):
    _get_project_or_404(project_id, db)
    _get_finding_or_404(project_id, finding_id, db)
    records = db.execute(
        select(RemediationRecord)
        .where(RemediationRecord.finding_id == finding_id)
        .order_by(RemediationRecord.created_at.desc())
    ).scalars().all()
    return records


@router.post("/{finding_id}/remediation", response_model=RemediationRecordResponse, status_code=201)
def create_remediation(
    project_id: str,
    finding_id: str,
    payload: RemediationRecordCreate,
    db: Session = Depends(get_db),
):
    _get_project_or_404(project_id, db)
    finding = _get_finding_or_404(project_id, finding_id, db)

    record = RemediationRecord(
        finding_id=finding.id,
        description=payload.description,
        applied_by=payload.applied_by,
        applied_at=payload.applied_at,
        patch_diff=payload.patch_diff,
        retest_status=RetestStatus.PENDING,
    )
    db.add(record)

    # Advance finding to REMEDIATION status if not already past it
    active_statuses = {FindingStatus.DETECTED, FindingStatus.VALIDATING, FindingStatus.CONFIRMED}
    if finding.status in active_statuses:
        old = finding.status
        finding.status = FindingStatus.REMEDIATION
        db.add(FindingHistory(
            finding_id=finding.id,
            from_status=old,
            to_status=FindingStatus.REMEDIATION,
            changed_by="user",
            note=f"Remediation recorded: {payload.description[:100]}",
        ))
    db.commit()
    db.refresh(record)
    return record


# ─── Retest ───────────────────────────────────────────────────────────────────

@router.post("/{finding_id}/remediation/{remediation_id}/retest", response_model=RetestResponse)
def retest_finding(
    project_id: str,
    finding_id: str,
    remediation_id: str,
    payload: RetestRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Re-run the scanner that produced the finding against the (now remediated) target.
    Updates the remediation record and, if the vulnerability is gone, auto-resolves the finding.
    Only operates on local, authorized targets.
    """
    _get_project_or_404(project_id, db)
    finding = _get_finding_or_404(project_id, finding_id, db)
    rec = db.execute(
        select(RemediationRecord).where(
            RemediationRecord.id == remediation_id,
            RemediationRecord.finding_id == finding_id,
        )
    ).scalar_one_or_none()
    if not rec:
        raise HTTPException(status_code=404, detail="Remediation record not found")

    # Advance finding to RETESTING
    if finding.status != FindingStatus.RETESTING:
        old = finding.status
        finding.status = FindingStatus.RETESTING
        db.add(FindingHistory(
            finding_id=finding.id,
            from_status=old,
            to_status=FindingStatus.RETESTING,
            changed_by="user",
            note="Retest initiated",
        ))
        db.commit()

    from app.services.retest_service import run_retest
    try:
        retest_status = run_retest(
            db=db,
            finding_id=finding_id,
            remediation_id=remediation_id,
            notes=payload.notes or "",
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Retest failed: {exc}")

    db.refresh(rec)
    return RetestResponse(
        retest_status=retest_status,
        notes=rec.retest_notes or "",
        remediation_id=remediation_id,
    )


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _get_project_or_404(project_id: str, db: Session) -> Project:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


def _get_finding_or_404(project_id: str, finding_id: str, db: Session) -> Finding:
    finding = db.execute(
        select(Finding).where(Finding.id == finding_id, Finding.project_id == project_id)
    ).scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding
