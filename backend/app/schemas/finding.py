from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel
from app.models.finding import Severity, Confidence, FindingStatus, SecurityCategory
from app.models.remediation import RetestStatus
from app.schemas.ai_analysis import AiAnalysisResponse


class RemediationRecordSummary(BaseModel):
    id: str
    description: str
    applied_by: Optional[str]
    retest_status: str
    retest_at: Optional[datetime]
    retest_notes: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


class EvidenceResponse(BaseModel):
    id: str
    evidence_type: str
    content: Optional[str]
    file_path: Optional[str]
    metadata_json: Optional[str]
    title: Optional[str]
    description: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingHistoryEntry(BaseModel):
    id: str
    from_status: Optional[str]
    to_status: str
    changed_by: str
    note: Optional[str]
    timestamp: datetime

    model_config = {"from_attributes": True}


class FindingResponse(BaseModel):
    id: str
    project_id: str
    scan_run_id: str
    scanner_id: str
    title: str
    description: str
    category: str
    severity: str
    confidence: str
    status: str
    affected_component: Optional[str]
    affected_file: Optional[str]
    affected_line: Optional[int]
    affected_endpoint: Optional[str]
    cwe_id: Optional[str]
    owasp_category: Optional[str]
    cvss_vector: Optional[str]
    cvss_score: Optional[float]
    impact: Optional[str]
    remediation: Optional[str]
    evidence: List[EvidenceResponse] = []
    history: List[FindingHistoryEntry] = []
    remediation_records: List[RemediationRecordSummary] = []
    ai_analysis: Optional[AiAnalysisResponse] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class FindingStatusUpdate(BaseModel):
    status: FindingStatus
    note: Optional[str] = None


class FindingSummary(BaseModel):
    id: str
    scan_run_id: str
    title: str
    category: str
    severity: str
    confidence: str
    status: str
    affected_file: Optional[str]
    affected_endpoint: Optional[str]
    affected_component: Optional[str]
    scanner_id: str
    created_at: datetime

    model_config = {"from_attributes": True}
