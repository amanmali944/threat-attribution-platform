from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, ConfigDict, Field

class TTPDetail(BaseModel):
    tactic: str = Field(..., example="Execution")
    technique_id: str = Field(..., example="T1059.001")
    technique_name: str = Field(..., example="PowerShell")

class AttributionCreate(BaseModel):
    tenant_id: str = Field(..., example="tenant-01")
    incident_id: str = Field(..., example="inc-9001")
    actor_name: str = Field(..., example="APT29")
    campaign: Optional[str] = Field(None, example="SolarWinds Supply Chain")
    confidence_score: float = Field(..., ge=0.0, le=1.0, example=0.88)
    tactics_techniques: List[Dict[str, Any]] = Field(default_factory=list)

class AttributionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    incident_id: str
    actor_name: str
    campaign: Optional[str] = None
    confidence_score: float
    tactics_techniques: List[Dict[str, Any]]
    created_at: datetime
