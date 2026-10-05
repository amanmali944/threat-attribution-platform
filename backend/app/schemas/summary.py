from datetime import datetime, timezone
from typing import List
from pydantic import BaseModel, Field

class SummaryResponse(BaseModel):
    tenant_id: str = Field(..., example="tenant-01")
    total_events: int = Field(..., example=14500)
    total_alerts: int = Field(..., example=23)
    total_incidents: int = Field(..., example=2)
    open_incidents: int = Field(..., example=1)
    critical_alerts: int = Field(..., example=4)
    top_threat_actors: List[str] = Field(default_factory=list, example=["APT29", "FIN7"])
    last_updated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
