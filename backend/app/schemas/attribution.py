from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, ConfigDict, Field

class TTPDetail(BaseModel):
    tactic: str = Field(..., example="Execution")
    technique_id: str = Field(..., example="T1059.001")
    technique_name: str = Field(..., example="PowerShell")

class AttributionCreate(BaseModel):
    model_config = ConfigDict(extra="ignore")

    tenant_id: str = Field(..., example="tenant-01")
    incident_id: str = Field(..., example="inc-9001")
    id: Optional[str] = None
    attribution_id: Optional[str] = None
    actor_name: Optional[str] = Field(None, example="APT29")  # Nullable per CR-05
    campaign: Optional[str] = Field(None, example="SolarWinds Supply Chain")
    confidence_score: Optional[float] = Field(0.0, ge=0.0, le=1.0, example=0.88)
    confidence: Optional[float] = None
    tactics_techniques: List[Dict[str, Any]] = Field(default_factory=list)
    techniques: Optional[List[Any]] = None

    # Developer A Analytical Graph Attribution Fields (CR-04)
    entry_point: Optional[Dict[str, Any]] = None
    attack_path: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    reached_assets: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    blast_radius: Optional[Dict[str, Any]] = None
    dwell_time_seconds: Optional[float] = None
    explanation: Optional[Any] = None
    graph: Optional[Dict[str, Any]] = None
    method: Optional[str] = None
    schema_version: Optional[str] = "1.0"

class AttributionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    attribution_id: Optional[str] = None
    tenant_id: str
    incident_id: str
    actor_name: Optional[str] = None
    campaign: Optional[str] = None
    confidence_score: float = 0.0
    confidence: Optional[float] = None
    tactics_techniques: List[Dict[str, Any]] = Field(default_factory=list)
    techniques: Optional[List[Any]] = None

    # Developer A Analytical Graph Attribution Fields (CR-04)
    entry_point: Optional[Dict[str, Any]] = None
    attack_path: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    reached_assets: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    blast_radius: Optional[Dict[str, Any]] = None
    dwell_time_seconds: Optional[float] = None
    explanation: Optional[Any] = None
    graph: Optional[Dict[str, Any]] = None

    created_at: datetime

class AttributionListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: List[AttributionResponse]
