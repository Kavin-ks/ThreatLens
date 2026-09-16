from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, select
from app.core.database import get_db
from app.models.project import Project, ProjectStatus
from app.models.finding import Finding, Severity, FindingStatus
from app.models.scan import ScanRun
from app.schemas.project import ProjectCreate, ProjectUpdate, ProjectResponse, ProjectSummary

router = APIRouter()


@router.get("/", response_model=List[ProjectSummary])
def list_projects(
    status: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """List all assessment projects with finding summaries."""
    query = select(Project)
    if status:
        query = query.where(Project.status == status)
    projects = db.execute(query.order_by(Project.created_at.desc())).scalars().all()

    summaries = []
    for p in projects:
        total = db.execute(
            select(func.count()).where(Finding.project_id == p.id)
        ).scalar() or 0
        confirmed = db.execute(
            select(func.count()).where(
                Finding.project_id == p.id,
                Finding.status == FindingStatus.CONFIRMED,
            )
        ).scalar() or 0
        critical = db.execute(
            select(func.count()).where(
                Finding.project_id == p.id,
                Finding.severity == Severity.CRITICAL,
            )
        ).scalar() or 0
        high = db.execute(
            select(func.count()).where(
                Finding.project_id == p.id,
                Finding.severity == Severity.HIGH,
            )
        ).scalar() or 0
        last_scan = db.execute(
            select(ScanRun.created_at)
            .where(ScanRun.project_id == p.id)
            .order_by(ScanRun.created_at.desc())
            .limit(1)
        ).scalar()

        summaries.append(
            ProjectSummary(
                id=p.id,
                name=p.name,
                description=p.description,
                status=p.status,
                total_findings=total,
                confirmed_findings=confirmed,
                critical_count=critical,
                high_count=high,
                last_scan_at=last_scan,
                created_at=p.created_at,
            )
        )
    return summaries


@router.post("/", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
def create_project(payload: ProjectCreate, db: Session = Depends(get_db)):
    """Create a new security assessment project."""
    project = Project(
        name=payload.name,
        description=payload.description,
        target_path=payload.target_path,
        target_url=payload.target_url,
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


@router.get("/{project_id}", response_model=ProjectResponse)
def get_project(project_id: str, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


@router.patch("/{project_id}", response_model=ProjectResponse)
def update_project(project_id: str, payload: ProjectUpdate, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(project, field, value)
    db.commit()
    db.refresh(project)
    return project


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(project_id: str, db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    db.delete(project)
    db.commit()
