from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field

class AlertCreate(BaseModel):
    tenant_id: str = Field(..., example="tenant-01")
    rule_id: str = Field(..., example="RULE-WIN-001")
    title: str = Field(..., example="Encoded PowerShell Execution")
    description: Optional[str] = Field(None, example="Suspicious base64 command detected")
    severity: str = Field("medium", example="high")
    status: str = Field("open", example="open")
    observed_at: datetime
    event_ids: Optional[List[str]] = Field(default_factory=list)

class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    rule_id: str
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    observed_at: datetime
    created_at: datetime

class AlertListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: List[AlertResponse]
