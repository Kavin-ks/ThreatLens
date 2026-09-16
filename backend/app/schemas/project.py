from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    target_path: Optional[str] = Field(None, max_length=1024)
    target_url: Optional[str] = Field(None, max_length=2048)


class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    target_path: Optional[str] = Field(None, max_length=1024)
    target_url: Optional[str] = Field(None, max_length=2048)
    status: Optional[str] = None


class ProjectResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    target_path: Optional[str]
    target_url: Optional[str]
    status: str
    stack_info: Optional[str]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ProjectSummary(BaseModel):
    id: str
    name: str
    description: Optional[str]
    status: str
    total_findings: int = 0
    confirmed_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    last_scan_at: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}
