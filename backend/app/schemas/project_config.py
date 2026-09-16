from typing import List, Optional
from pydantic import BaseModel


class ProjectConfigResponse(BaseModel):
    project_id: str
    enabled_scanners: Optional[List[str]]
    authorized_targets: List[str]

    model_config = {"from_attributes": False}


class ProjectConfigUpdate(BaseModel):
    enabled_scanners: Optional[List[str]] = None
    authorized_targets: Optional[List[str]] = None
