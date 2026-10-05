from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.event import Event
from app.schemas.event import EventCreate, EventIngestResponse, EventListResponse, EventResponse

router = APIRouter(prefix="/events", tags=["Events"])

@router.post("", response_model=EventIngestResponse, status_code=status.HTTP_201_CREATED)
def create_event(event_in: EventCreate, db: Session = Depends(get_db)):
    event_id = event_in.event_id or f"evt-{event_in.tenant_id[:4]}-{int(datetime.now().timestamp())}"
    db_event = Event(
        id=event_id,
        tenant_id=event_in.tenant_id,
        source_layer=event_in.source_layer,
        event_type=event_in.event_type,
        observed_at=event_in.observed_at,
        severity=event_in.severity,
        payload=event_in.payload,
    )
    db.add(db_event)
    db.commit()
    db.refresh(db_event)
    return EventIngestResponse(
        id=db_event.id,
        status="ingested",
        created_at=db_event.created_at or datetime.now(timezone.utc),
    )

@router.get("", response_model=EventListResponse)
def list_events(
    tenant_id: str = Query(..., description="Tenant ID filter"),
    source_layer: Optional[str] = Query(None, description="Source layer filter"),
    event_type: Optional[str] = Query(None, description="Event type filter"),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    query = db.query(Event).filter(Event.tenant_id == tenant_id)
    if source_layer:
        query = query.filter(Event.source_layer == source_layer)
    if event_type:
        query = query.filter(Event.event_type == event_type)
    
    total = query.count()
    items = query.order_by(Event.observed_at.desc()).offset(offset).limit(limit).all()
    return EventListResponse(total=total, limit=limit, offset=offset, items=items)
