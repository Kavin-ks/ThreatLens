"""Dashboard statistics endpoint — real database aggregations only."""
from typing import Dict
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import select, func

from app.core.database import get_db
from app.models.finding import Finding, Severity, FindingStatus
from app.models.project import Project
from app.models.scan import ScanRun, ScanStatus
from pydantic import BaseModel

router = APIRouter()


class SeverityDistribution(BaseModel):
    CRITICAL: int = 0
    HIGH: int = 0
    MEDIUM: int = 0
    LOW: int = 0
    INFO: int = 0


class StatusDistribution(BaseModel):
    DETECTED: int = 0
    VALIDATING: int = 0
    CONFIRMED: int = 0
    REJECTED: int = 0
    REMEDIATION: int = 0
    RETESTING: int = 0
    RESOLVED: int = 0


class DashboardStats(BaseModel):
    total_projects: int
    active_projects: int
    total_findings: int
    confirmed_findings: int
    resolved_findings: int
    critical_findings: int
    high_findings: int
    total_scans: int
    running_scans: int
    severity_distribution: SeverityDistribution
    status_distribution: StatusDistribution
    recent_scans_count: int


@router.get("/stats", response_model=DashboardStats)
def get_dashboard_stats(db: Session = Depends(get_db)):
    total_projects = db.execute(select(func.count(Project.id))).scalar() or 0
    active_projects = db.execute(
        select(func.count(Project.id)).where(Project.status == "active")
    ).scalar() or 0

    total_findings = db.execute(select(func.count(Finding.id))).scalar() or 0
    confirmed_findings = db.execute(
        select(func.count(Finding.id)).where(Finding.status == FindingStatus.CONFIRMED)
    ).scalar() or 0
    resolved_findings = db.execute(
        select(func.count(Finding.id)).where(Finding.status == FindingStatus.RESOLVED)
    ).scalar() or 0
    critical_findings = db.execute(
        select(func.count(Finding.id)).where(Finding.severity == Severity.CRITICAL)
    ).scalar() or 0
    high_findings = db.execute(
        select(func.count(Finding.id)).where(Finding.severity == Severity.HIGH)
    ).scalar() or 0

    total_scans = db.execute(select(func.count(ScanRun.id))).scalar() or 0
    running_scans = db.execute(
        select(func.count(ScanRun.id)).where(ScanRun.status == ScanStatus.RUNNING)
    ).scalar() or 0

    # Severity distribution
    sev_rows = db.execute(
        select(Finding.severity, func.count(Finding.id)).group_by(Finding.severity)
    ).all()
    sev_dist = SeverityDistribution()
    for sev, cnt in sev_rows:
        setattr(sev_dist, sev, cnt)

    # Status distribution
    status_rows = db.execute(
        select(Finding.status, func.count(Finding.id)).group_by(Finding.status)
    ).all()
    status_dist = StatusDistribution()
    for st, cnt in status_rows:
        setattr(status_dist, st, cnt)

    # Scans in last 7 days
    from datetime import datetime, timedelta, timezone
    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    recent_scans_count = db.execute(
        select(func.count(ScanRun.id)).where(ScanRun.created_at >= cutoff)
    ).scalar() or 0

    return DashboardStats(
        total_projects=total_projects,
        active_projects=active_projects,
        total_findings=total_findings,
        confirmed_findings=confirmed_findings,
        resolved_findings=resolved_findings,
        critical_findings=critical_findings,
        high_findings=high_findings,
        total_scans=total_scans,
        running_scans=running_scans,
        severity_distribution=sev_dist,
        status_distribution=status_dist,
        recent_scans_count=recent_scans_count,
    )
