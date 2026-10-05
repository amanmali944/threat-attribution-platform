from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field

class IncidentCreate(BaseModel):
    tenant_id: str = Field(..., example="tenant-01")
    title: str = Field(..., example="Lateral Movement & C2 Activity Detected")
    description: Optional[str] = Field(None, example="Correlated alerts across workstation-01 and domain controller")
    severity: str = Field("high", example="critical")
    status: str = Field("open", example="investigating")
    assigned_to: Optional[str] = Field(None, example="analyst@corp.com")
    alert_ids: Optional[List[str]] = Field(default_factory=list)

class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    assigned_to: Optional[str] = None
    created_at: datetime
    updated_at: datetime

class IncidentListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: List[IncidentResponse]
