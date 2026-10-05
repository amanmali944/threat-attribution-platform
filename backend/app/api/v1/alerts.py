from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.alert import Alert
from app.schemas.alert import AlertCreate, AlertListResponse, AlertResponse

router = APIRouter(prefix="/alerts", tags=["Alerts"])

@router.post("", response_model=AlertResponse, status_code=status.HTTP_201_CREATED)
def create_alert(alert_in: AlertCreate, db: Session = Depends(get_db)):
    db_alert = Alert(
        tenant_id=alert_in.tenant_id,
        rule_id=alert_in.rule_id,
        title=alert_in.title,
        description=alert_in.description,
        severity=alert_in.severity,
        status=alert_in.status,
        observed_at=alert_in.observed_at,
    )
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)
    return db_alert

@router.get("", response_model=AlertListResponse)
def list_alerts(
    tenant_id: str = Query(..., description="Tenant ID filter"),
    severity: Optional[str] = Query(None, description="Severity filter"),
    status: Optional[str] = Query(None, description="Status filter"),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    query = db.query(Alert).filter(Alert.tenant_id == tenant_id)
    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)

    total = query.count()
    items = query.order_by(Alert.observed_at.desc()).offset(offset).limit(limit).all()
    return AlertListResponse(total=total, limit=limit, offset=offset, items=items)
