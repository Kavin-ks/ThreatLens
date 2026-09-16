from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class ReportGenerateRequest(BaseModel):
    scan_run_id: Optional[str] = None
    title: Optional[str] = None


class ReportResponse(BaseModel):
    id: str
    project_id: str
    scan_run_id: Optional[str]
    title: str
    format: str
    generated_by: Optional[str]
    metadata_json: Optional[str]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
