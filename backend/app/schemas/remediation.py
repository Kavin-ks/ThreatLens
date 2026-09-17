from datetime import datetime
from typing import Optional
from pydantic import BaseModel
from app.models.finding import Confidence


class RemediationRecordCreate(BaseModel):
    description: str
    applied_by: Optional[str] = None
    applied_at: Optional[datetime] = None
    patch_diff: Optional[str] = None


class RemediationRecordResponse(BaseModel):
    id: str
    finding_id: str
    description: str
    applied_by: Optional[str]
    applied_at: Optional[datetime]
    patch_diff: Optional[str]
    retest_status: str
    retest_at: Optional[datetime]
    retest_notes: Optional[str]
    retest_scan_run_id: Optional[str]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class RetestRequest(BaseModel):
    notes: Optional[str] = None
    # When True and the scanner returns inconclusive (e.g. scanner_id="manual"),
    # record the fix as manually verified and resolve the finding.
    # Only accepted when retest_status would otherwise be "inconclusive".
    manual_resolve: bool = False


class RetestResponse(BaseModel):
    retest_status: str
    notes: str
    remediation_id: str


class ValidateFindingRequest(BaseModel):
    confidence: Confidence
    note: Optional[str] = None
