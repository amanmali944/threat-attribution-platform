from datetime import datetime
from typing import List, Optional, Any, Dict
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

    # Developer A Analytical Detection Extension Fields (CR-03)
    detector: Optional[str] = Field(None, example="rules")
    detector_version: Optional[str] = Field(None, example="rules-1.0.0")
    technique: Optional[str] = Field(None, example="credential_access")
    technique_id: Optional[str] = Field(None, example="T1110")
    entity_id: Optional[str] = Field(None, example="ent-user-3f9a1c22")
    score: Optional[float] = Field(None, example=0.91)
    confidence: Optional[float] = Field(None, example=0.87)
    decision: Optional[str] = Field(None, example="alert")
    evidence: Optional[Any] = Field(default_factory=list)

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

    # Developer A Analytical Detection Extension Fields (CR-03)
    detector: Optional[str] = None
    detector_version: Optional[str] = None
    technique: Optional[str] = None
    technique_id: Optional[str] = None
    entity_id: Optional[str] = None
    score: Optional[float] = None
    confidence: Optional[float] = None
    decision: Optional[str] = None
    evidence: Optional[Any] = None

    created_at: datetime

class AlertListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: List[AlertResponse]
