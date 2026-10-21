from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator

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
    entities: Optional[List[Dict[str, Any]]] = None
    metadata: Optional[Dict[str, Any]] = None
    created_at: datetime

    @model_validator(mode="before")
    @classmethod
    def resolve_orm_metadata(cls, data: Any) -> Any:
        # SQLAlchemy ORM objects have a .metadata attr (MetaData registry), so we must
        # always convert to dict when event_metadata is present on the ORM instance.
        if hasattr(data, "event_metadata"):
            return {
                "id": getattr(data, "id", None),
                "tenant_id": getattr(data, "tenant_id", None),
                "source_layer": getattr(data, "source_layer", None),
                "event_type": getattr(data, "event_type", None),
                "observed_at": getattr(data, "observed_at", None),
                "severity": getattr(data, "severity", None),
                "payload": getattr(data, "payload", {}),
                "entities": getattr(data, "entities", []),
                "metadata": getattr(data, "event_metadata", {}),
                "created_at": getattr(data, "created_at", None),
            }
        return data

class EventListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: List[EventResponse]
