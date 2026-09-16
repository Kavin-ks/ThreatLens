from typing import List
from fastapi import APIRouter
from pydantic import BaseModel
from scanners.registry import scanner_registry

router = APIRouter()


class ScannerInfo(BaseModel):
    scanner_id: str
    name: str
    description: str
    category: str
    requires_running_app: bool
    cwe_ids: List[str]


@router.get("/", response_model=List[ScannerInfo])
def list_scanners():
    """Return all registered security scanners with their metadata."""
    scanner_registry.autodiscover()
    return [
        ScannerInfo(
            scanner_id=s.scanner_id,
            name=s.name,
            description=s.description,
            category=s.category.value if hasattr(s.category, "value") else str(s.category),
            requires_running_app=s.requires_running_app,
            cwe_ids=list(s.cwe_ids or []),
        )
        for s in scanner_registry.all()
    ]
