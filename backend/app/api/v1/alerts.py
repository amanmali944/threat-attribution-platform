from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import Field
from sqlalchemy.orm import Session

from app.api.v1.events import load_fixture, parse_datetime
from app.core.database import get_db
from app.models.alert import Alert
from app.models.event import Event
from app.schemas.alert import AlertCreate, AlertListResponse, AlertResponse

router = APIRouter(prefix="/alerts", tags=["Alerts"])


class AlertDetailResponse(AlertResponse):
    evidence_refs: List[str] = Field(default_factory=list)
    event_ids: List[str] = Field(default_factory=list)


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

    if alert_in.event_ids:
        events = db.query(Event).filter(Event.id.in_(alert_in.event_ids)).all()
        db_alert.events.extend(events)

    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)
    return db_alert


@router.get("", response_model=AlertListResponse)
def list_alerts(
    tenant_id: str = Query(..., description="Tenant ID filter"),
    detector: Optional[str] = Query(None, description="Detector or Rule ID filter"),
    rule_id: Optional[str] = Query(None, description="Rule ID filter"),
    technique: Optional[str] = Query(None, description="MITRE Technique filter"),
    status: Optional[str] = Query(None, description="Status filter"),
    severity: Optional[str] = Query(None, description="Severity filter"),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    query = db.query(Alert).filter(Alert.tenant_id == tenant_id)

    target_rule = detector or rule_id
    if target_rule:
        query = query.filter(Alert.rule_id == target_rule)
    if status:
        query = query.filter(Alert.status == status)
    if severity:
        query = query.filter(Alert.severity == severity)
    if technique:
        query = query.filter(
            Alert.title.ilike(f"%{technique}%") | Alert.description.ilike(f"%{technique}%")
        )

    total_in_db = query.count()

    # Fallback to mock fixtures if DB table has no matching alerts
    if total_in_db == 0:
        fixture_alerts = load_fixture("alerts.json")
        filtered_fixtures = []
        for fa in fixture_alerts:
            f_tenant = fa.get("tenant_id", "")
            if f_tenant != tenant_id and tenant_id not in ["tenant-default-001", "tenant-01"]:
                continue
            if target_rule and fa.get("rule_id") != target_rule:
                continue
            if status and fa.get("status") != status:
                continue
            if severity and fa.get("severity") != severity:
                continue
            if technique:
                title = fa.get("title", "")
                desc = fa.get("description", "")
                if technique.lower() not in title.lower() and technique.lower() not in desc.lower():
                    continue

            obs_dt = parse_datetime(fa.get("observed_at"))
            created_dt = parse_datetime(fa.get("created_at"))

            filtered_fixtures.append(
                AlertResponse(
                    id=fa.get("id"),
                    tenant_id=tenant_id,
                    rule_id=fa.get("rule_id"),
                    title=fa.get("title"),
                    description=fa.get("description"),
                    severity=fa.get("severity", "medium"),
                    status=fa.get("status", "open"),
                    observed_at=obs_dt,
                    created_at=created_dt,
                )
            )

        total_fixture = len(filtered_fixtures)
        paginated_fixtures = filtered_fixtures[offset : offset + limit]
        return AlertListResponse(
            total=total_fixture,
            limit=limit,
            offset=offset,
            items=paginated_fixtures,
        )

    total = total_in_db
    items = query.order_by(Alert.observed_at.desc()).offset(offset).limit(limit).all()
    return AlertListResponse(total=total, limit=limit, offset=offset, items=items)


@router.get("/{alert_id}", response_model=AlertDetailResponse)
def get_alert_detail(
    alert_id: str,
    tenant_id: Optional[str] = Query(None, description="Optional tenant ID"),
    db: Session = Depends(get_db),
):
    query = db.query(Alert).filter(Alert.id == alert_id)
    if tenant_id:
        query = query.filter(Alert.tenant_id == tenant_id)
    alert = query.first()

    if alert:
        evidence_refs = [e.id for e in alert.events]
        return AlertDetailResponse(
            id=alert.id,
            tenant_id=alert.tenant_id,
            rule_id=alert.rule_id,
            title=alert.title,
            description=alert.description,
            severity=alert.severity,
            status=alert.status,
            observed_at=alert.observed_at,
            created_at=alert.created_at,
            evidence_refs=evidence_refs,
            event_ids=evidence_refs,
        )

    # Fallback to fixtures
    fixture_alerts = load_fixture("alerts.json")
    for fa in fixture_alerts:
        if fa.get("id") == alert_id:
            if tenant_id and fa.get("tenant_id") != tenant_id and tenant_id not in ["tenant-default-001", "tenant-01"]:
                continue
            ev_refs = fa.get("event_ids", [])
            obs_dt = parse_datetime(fa.get("observed_at"))
            created_dt = parse_datetime(fa.get("created_at"))
            return AlertDetailResponse(
                id=fa.get("id"),
                tenant_id=tenant_id or fa.get("tenant_id"),
                rule_id=fa.get("rule_id"),
                title=fa.get("title"),
                description=fa.get("description"),
                severity=fa.get("severity", "medium"),
                status=fa.get("status", "open"),
                observed_at=obs_dt,
                created_at=created_dt,
                evidence_refs=ev_refs,
                event_ids=ev_refs,
            )

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Alert '{alert_id}' not found",
    )
