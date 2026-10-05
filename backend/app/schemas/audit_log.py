from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, ConfigDict, Field

class AuditLogCreate(BaseModel):
    tenant_id: str = Field(..., example="tenant-01")
    user_id: Optional[str] = Field(None, example="usr-1001")
    action: str = Field(..., example="CLOSE_INCIDENT")
    resource: str = Field(..., example="inc-9001")
    details: Dict[str, Any] = Field(default_factory=dict)

class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    user_id: Optional[str] = None
    action: str
    resource: str
    details: Dict[str, Any]
    created_at: datetime
