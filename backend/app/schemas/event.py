from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, ConfigDict, Field

class EventEntity(BaseModel):
    entity_type: str = Field(..., example="host")
    identifier: str = Field(..., example="workstation-01.corp.internal")

class EventCreate(BaseModel):
    event_id: Optional[str] = Field(None, example="evt-1001")
    tenant_id: str = Field(..., example="tenant-01")
    source_layer: str = Field(..., example="endpoint")
    event_type: str = Field(..., example="process_execution")
    observed_at: datetime
    severity: str = Field("info", example="medium")
    entities: Optional[List[EventEntity]] = Field(default_factory=list)
    payload: Dict[str, Any] = Field(default_factory=dict)
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)

class EventIngestResponse(BaseModel):
    id: str
    status: str = "ingested"
    created_at: datetime

class EventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    source_layer: str
    event_type: str
    observed_at: datetime
    severity: str
    payload: Dict[str, Any]
    created_at: datetime

class EventListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: List[EventResponse]
