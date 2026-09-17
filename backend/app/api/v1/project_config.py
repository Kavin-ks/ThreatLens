"""Per-project scanner configuration endpoint."""
import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.core.database import get_db
from app.models.project import Project
from app.models.project_config import ProjectConfig
from app.schemas.project_config import ProjectConfigResponse, ProjectConfigUpdate

router = APIRouter()


def _get_project_or_404(project_id: str, db: Session) -> Project:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


def _config_to_response(project_id: str, cfg: ProjectConfig | None) -> ProjectConfigResponse:
    enabled: list | None = None
    authorized: list = []
    if cfg:
        if cfg.enabled_scanners_json:
            enabled = json.loads(cfg.enabled_scanners_json)
        if cfg.authorized_targets_json:
            authorized = json.loads(cfg.authorized_targets_json)
    return ProjectConfigResponse(
        project_id=project_id,
        enabled_scanners=enabled,
        authorized_targets=authorized,
    )


@router.get("/scanner-config", response_model=ProjectConfigResponse)
def get_scanner_config(project_id: str, db: Session = Depends(get_db)):
    _get_project_or_404(project_id, db)
    cfg = db.execute(
        select(ProjectConfig).where(ProjectConfig.project_id == project_id)
    ).scalar_one_or_none()
    return _config_to_response(project_id, cfg)


@router.patch("/scanner-config", response_model=ProjectConfigResponse)
def update_scanner_config(
    project_id: str,
    payload: ProjectConfigUpdate,
    db: Session = Depends(get_db),
):
    _get_project_or_404(project_id, db)
    cfg = db.execute(
        select(ProjectConfig).where(ProjectConfig.project_id == project_id)
    ).scalar_one_or_none()
    if not cfg:
        cfg = ProjectConfig(project_id=project_id)
        db.add(cfg)

    if "enabled_scanners" in payload.model_fields_set:
        cfg.enabled_scanners_json = (
            json.dumps(payload.enabled_scanners)
            if payload.enabled_scanners is not None
            else None
        )
    if "authorized_targets" in payload.model_fields_set:
        cfg.authorized_targets_json = (
            json.dumps(payload.authorized_targets)
            if payload.authorized_targets is not None
            else None
        )

    db.commit()
    db.refresh(cfg)
    return _config_to_response(project_id, cfg)
