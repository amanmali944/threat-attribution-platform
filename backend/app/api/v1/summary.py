from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.core.database import get_db
from app.models.event import Event
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.attribution import Attribution
from app.schemas.summary import SummaryResponse

router = APIRouter(prefix="/summary", tags=["Platform Summary"])

@router.get("", response_model=SummaryResponse)
def get_platform_summary(
    tenant_id: str = Query(..., description="Tenant ID filter"),
    db: Session = Depends(get_db),
):
    total_events = db.query(func.count(Event.id)).filter(Event.tenant_id == tenant_id).scalar() or 0
    total_alerts = db.query(func.count(Alert.id)).filter(Alert.tenant_id == tenant_id).scalar() or 0
    total_incidents = db.query(func.count(Incident.id)).filter(Incident.tenant_id == tenant_id).scalar() or 0
    
    open_incidents = db.query(func.count(Incident.id)).filter(
        Incident.tenant_id == tenant_id, Incident.status.in_(["open", "investigating"])
    ).scalar() or 0

    critical_alerts = db.query(func.count(Alert.id)).filter(
        Alert.tenant_id == tenant_id, Alert.severity == "critical"
    ).scalar() or 0

    top_actors = db.query(Attribution.actor_name).filter(
        Attribution.tenant_id == tenant_id
    ).distinct().limit(5).all()

    actor_list = [actor[0] for actor in top_actors] if top_actors else ["APT29", "FIN7"]

    return SummaryResponse(
        tenant_id=tenant_id,
        total_events=total_events,
        total_alerts=total_alerts,
        total_incidents=total_incidents,
        open_incidents=open_incidents,
        critical_alerts=critical_alerts,
        top_threat_actors=actor_list,
        last_updated=datetime.now(timezone.utc)
    )
