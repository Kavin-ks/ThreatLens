import json
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session, selectinload
from sqlalchemy import select

from app.core.database import get_db
from app.models.project import Project
from app.models.finding import Finding
from app.models.scan import ScanRun
from app.models.report import SecurityReport, ReportFormat
from app.schemas.report import ReportGenerateRequest, ReportResponse

router = APIRouter()


@router.get("/", response_model=List[ReportResponse])
def list_reports(project_id: str, db: Session = Depends(get_db)):
    _get_project_or_404(project_id, db)
    reports = db.execute(
        select(SecurityReport)
        .where(SecurityReport.project_id == project_id)
        .order_by(SecurityReport.created_at.desc())
    ).scalars().all()
    return reports


@router.post("/", response_model=ReportResponse, status_code=201)
def generate_report(
    project_id: str,
    payload: ReportGenerateRequest,
    db: Session = Depends(get_db),
):
    """
    Generate a PDF security assessment report for this project.
    Optionally scoped to a specific scan_run_id.
    """
    project = _get_project_or_404(project_id, db)

    # Load findings (with evidence and remediation records)
    query = (
        select(Finding)
        .options(
            selectinload(Finding.evidence),
            selectinload(Finding.remediation_records),
            selectinload(Finding.history),
        )
        .where(Finding.project_id == project_id)
    )
    if payload.scan_run_id:
        query = query.where(Finding.scan_run_id == payload.scan_run_id)
    findings = db.execute(query).scalars().all()

    scan_run = None
    if payload.scan_run_id:
        scan_run = db.get(ScanRun, payload.scan_run_id)

    title = payload.title or f"{project.name} - Security Assessment Report"

    from app.services.report_generator import generate_pdf_report
    try:
        pdf_bytes = generate_pdf_report(
            project=project,
            findings=findings,
            scan_run=scan_run,
            title=title,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {exc}")

    meta = {
        "finding_count": len(findings),
        "scan_run_id": payload.scan_run_id,
    }
    report = SecurityReport(
        project_id=project_id,
        scan_run_id=payload.scan_run_id,
        format=ReportFormat.PDF,
        title=title,
        generated_by="system",
        report_data=pdf_bytes,
        metadata_json=json.dumps(meta),
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


@router.get("/{report_id}", response_model=ReportResponse)
def get_report(project_id: str, report_id: str, db: Session = Depends(get_db)):
    _get_project_or_404(project_id, db)
    report = db.execute(
        select(SecurityReport).where(
            SecurityReport.id == report_id,
            SecurityReport.project_id == project_id,
        )
    ).scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.get("/{report_id}/download")
def download_report(project_id: str, report_id: str, db: Session = Depends(get_db)):
    """Download the generated PDF report."""
    _get_project_or_404(project_id, db)
    report = db.execute(
        select(SecurityReport).where(
            SecurityReport.id == report_id,
            SecurityReport.project_id == project_id,
        )
    ).scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if not report.report_data:
        raise HTTPException(status_code=404, detail="Report data not available")

    safe_title = "".join(c if c.isalnum() or c in "-_ " else "_" for c in report.title)[:60]
    filename = f"threatlens_{safe_title}.pdf"
    return Response(
        content=report.report_data,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _get_project_or_404(project_id: str, db: Session) -> Project:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project
