from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel


class ScanTriggerRequest(BaseModel):
    scanner_ids: Optional[List[str]] = None  # None = run all applicable scanners
    options: Optional[dict] = None


class ScannerResultResponse(BaseModel):
    id: str
    scanner_id: str
    status: str
    raw_finding_count: int
    confirmed_finding_count: int
    duration_ms: Optional[int]
    error_message: Optional[str]

    model_config = {"from_attributes": True}


class ScanRunResponse(BaseModel):
    id: str
    project_id: str
    status: str
    scanner_config: Optional[str]
    summary: Optional[str]
    error_message: Optional[str]
    celery_task_id: Optional[str]
    created_at: datetime
    updated_at: datetime
    scanner_results: List[ScannerResultResponse] = []

    model_config = {"from_attributes": True}
