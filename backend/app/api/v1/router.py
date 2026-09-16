from fastapi import APIRouter
from app.api.v1 import projects, scans, findings, scanners, reports
from app.api.v1 import global_findings, global_scans, dashboard, project_config

api_v1_router = APIRouter()

api_v1_router.include_router(projects.router, prefix="/projects", tags=["projects"])
api_v1_router.include_router(scans.router, prefix="/projects/{project_id}/scans", tags=["scans"])
api_v1_router.include_router(findings.router, prefix="/projects/{project_id}/findings", tags=["findings"])
api_v1_router.include_router(reports.router, prefix="/projects/{project_id}/reports", tags=["reports"])
api_v1_router.include_router(project_config.router, prefix="/projects/{project_id}", tags=["scanner-config"])
api_v1_router.include_router(scanners.router, prefix="/scanners", tags=["scanners"])
api_v1_router.include_router(global_findings.router, prefix="/findings", tags=["global-findings"])
api_v1_router.include_router(global_scans.router, prefix="/scans", tags=["global-scans"])
api_v1_router.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])
