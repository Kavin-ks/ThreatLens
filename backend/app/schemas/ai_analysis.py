from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class AiAnalysisResponse(BaseModel):
    id: str
    finding_id: str
    model_used: str
    technical_explanation: Optional[str]
    impact_assessment: Optional[str]
    false_positive_likelihood: Optional[str]
    false_positive_reasoning: Optional[str]
    remediation_recommendation: Optional[str]
    analyst_summary: Optional[str]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class CvssUpdateRequest(BaseModel):
    vector: str


class CvssUpdateResponse(BaseModel):
    cvss_vector: str
    cvss_score: float
    severity_label: str
