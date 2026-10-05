from typing import Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.incident import Incident
from app.schemas.incident import IncidentCreate, IncidentListResponse, IncidentResponse

router = APIRouter(prefix="/incidents", tags=["Incidents"])

@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
def create_incident(incident_in: IncidentCreate, db: Session = Depends(get_db)):
    db_incident = Incident(
        tenant_id=incident_in.tenant_id,
        title=incident_in.title,
        description=incident_in.description,
        severity=incident_in.severity,
        status=incident_in.status,
        assigned_to=incident_in.assigned_to,
    )
    db.add(db_incident)
    db.commit()
    db.refresh(db_incident)
    return db_incident

@router.get("", response_model=IncidentListResponse)
def list_incidents(
    tenant_id: str = Query(..., description="Tenant ID filter"),
    severity: Optional[str] = Query(None, description="Severity filter"),
    status: Optional[str] = Query(None, description="Status filter"),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    query = db.query(Incident).filter(Incident.tenant_id == tenant_id)
    if severity:
        query = query.filter(Incident.severity == severity)
    if status:
        query = query.filter(Incident.status == status)

    total = query.count()
    items = query.order_by(Incident.created_at.desc()).offset(offset).limit(limit).all()
    return IncidentListResponse(total=total, limit=limit, offset=offset, items=items)
