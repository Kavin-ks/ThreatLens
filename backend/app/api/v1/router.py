from fastapi import APIRouter
from app.api.v1 import projects, scans, findings, scanners

api_v1_router = APIRouter()

api_v1_router.include_router(projects.router, prefix="/projects", tags=["projects"])
api_v1_router.include_router(scans.router, prefix="/projects/{project_id}/scans", tags=["scans"])
api_v1_router.include_router(findings.router, prefix="/projects/{project_id}/findings", tags=["findings"])
api_v1_router.include_router(scanners.router, prefix="/scanners", tags=["scanners"])
