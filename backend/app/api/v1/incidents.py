from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.v1.events import load_fixture, parse_datetime
from app.core.database import get_db
from app.models.alert import Alert
from app.models.attribution import Attribution
from app.models.audit_log import AuditLog
from app.models.entity import Entity
from app.models.incident import Incident
from app.schemas.graph import GraphEdge, GraphNode
from app.schemas.incident import (
    IncidentCreate,
    IncidentListResponse,
    IncidentResponse,
)

router = APIRouter(prefix="/incidents", tags=["Incidents"])

ALLOWED_STATUSES = {"open", "reviewed", "dismissed", "confirmed", "investigating", "closed"}


class IncidentStatusUpdate(BaseModel):
    status: str = Field(..., description="Target status: open, reviewed, dismissed, confirmed, investigating, closed")
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    user_id: Optional[str] = None


class TimelineItem(BaseModel):
    timestamp: datetime
    type: str
    title: str
    description: Optional[str] = None
    severity: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class IncidentTimelineResponse(BaseModel):
    incident_id: str
    total: int
    timeline: List[TimelineItem]


class IncidentGraphResponse(BaseModel):
    incident_id: str
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    patient_zero: Optional[Dict[str, Any]] = None
    blast_radius: Optional[Dict[str, Any]] = None


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

    if incident_in.alert_ids:
        alerts = db.query(Alert).filter(Alert.id.in_(incident_in.alert_ids)).all()
        db_incident.alerts.extend(alerts)

    db.add(db_incident)
    db.commit()
    db.refresh(db_incident)
    return db_incident


@router.get("", response_model=IncidentListResponse)
def list_incidents(
    tenant_id: str = Query(..., description="Tenant ID filter"),
    status: Optional[str] = Query(None, description="Status filter"),
    severity: Optional[str] = Query(None, description="Severity filter"),
    risk_score: Optional[float] = Query(None, description="Minimum risk / confidence score filter"),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    query = db.query(Incident).filter(Incident.tenant_id == tenant_id)
    if status:
        query = query.filter(Incident.status == status)
    if severity:
        query = query.filter(Incident.severity == severity)
    if risk_score is not None:
        query = query.join(Incident.attributions).filter(Attribution.confidence_score >= risk_score)

    total_in_db = query.count()

    # Fallback to mock fixtures if DB table has no matching incidents
    if total_in_db == 0:
        fixture_incidents = load_fixture("incidents.json")
        fixture_attributions = load_fixture("attribution.json")

        attr_by_incident: Dict[str, List[Dict[str, Any]]] = {}
        for fa in fixture_attributions:
            inc_id = fa.get("incident_id")
            if inc_id:
                attr_by_incident.setdefault(inc_id, []).append(fa)

        filtered_fixtures = []
        for fi in fixture_incidents:
            f_tenant = fi.get("tenant_id", "")
            if f_tenant != tenant_id and tenant_id not in ["tenant-default-001", "tenant-01"]:
                continue
            if status and fi.get("status") != status:
                continue
            if severity and fi.get("severity") != severity:
                continue
            if risk_score is not None:
                inc_attrs = attr_by_incident.get(fi.get("id"), [])
                max_score = max([a.get("confidence_score", 0.0) for a in inc_attrs], default=0.0)
                if max_score < risk_score:
                    continue

            created_dt = parse_datetime(fi.get("created_at"))
            updated_dt = parse_datetime(fi.get("updated_at"))

            filtered_fixtures.append(
                IncidentResponse(
                    id=fi.get("id"),
                    tenant_id=tenant_id,
                    title=fi.get("title"),
                    description=fi.get("description"),
                    severity=fi.get("severity", "high"),
                    status=fi.get("status", "open"),
                    assigned_to=fi.get("assigned_to"),
                    created_at=created_dt,
                    updated_at=updated_dt,
                )
            )

        total_fixture = len(filtered_fixtures)
        paginated_fixtures = filtered_fixtures[offset : offset + limit]
        return IncidentListResponse(
            total=total_fixture,
            limit=limit,
            offset=offset,
            items=paginated_fixtures,
        )

    total = total_in_db
    items = query.order_by(Incident.created_at.desc()).offset(offset).limit(limit).all()
    return IncidentListResponse(total=total, limit=limit, offset=offset, items=items)


@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(
    incident_id: str,
    tenant_id: Optional[str] = Query(None, description="Optional tenant ID filter"),
    db: Session = Depends(get_db),
):
    query = db.query(Incident).filter(Incident.id == incident_id)
    if tenant_id:
        query = query.filter(Incident.tenant_id == tenant_id)
    incident = query.first()

    if incident:
        return incident

    # Fallback to fixtures
    fixture_incidents = load_fixture("incidents.json")
    for fi in fixture_incidents:
        if fi.get("id") == incident_id:
            if tenant_id and fi.get("tenant_id") != tenant_id and tenant_id not in ["tenant-default-001", "tenant-01"]:
                continue
            return IncidentResponse(
                id=fi.get("id"),
                tenant_id=tenant_id or fi.get("tenant_id"),
                title=fi.get("title"),
                description=fi.get("description"),
                severity=fi.get("severity", "high"),
                status=fi.get("status", "open"),
                assigned_to=fi.get("assigned_to"),
                created_at=parse_datetime(fi.get("created_at")),
                updated_at=parse_datetime(fi.get("updated_at")),
            )

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Incident '{incident_id}' not found",
    )


@router.patch("/{incident_id}", response_model=IncidentResponse)
def update_incident_status(
    incident_id: str,
    update_in: IncidentStatusUpdate,
    db: Session = Depends(get_db),
):
    target_status = update_in.status.lower()
    if target_status not in ALLOWED_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid status '{update_in.status}'. Allowed values: {sorted(ALLOWED_STATUSES)}",
        )

    db_incident = db.query(Incident).filter(Incident.id == incident_id).first()

    # If DB is fresh and incident only exists in fixture, persist it so it can be updated
    if not db_incident:
        fixture_incidents = load_fixture("incidents.json")
        for fi in fixture_incidents:
            if fi.get("id") == incident_id:
                db_incident = Incident(
                    id=fi.get("id"),
                    tenant_id=fi.get("tenant_id", "tenant-01"),
                    title=fi.get("title"),
                    description=fi.get("description"),
                    severity=fi.get("severity", "high"),
                    status=fi.get("status", "open"),
                    assigned_to=fi.get("assigned_to"),
                    created_at=parse_datetime(fi.get("created_at")),
                    updated_at=parse_datetime(fi.get("updated_at")),
                )
                db.add(db_incident)
                db.commit()
                db.refresh(db_incident)
                break

    if not db_incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    old_status = db_incident.status
    db_incident.status = target_status
    if update_in.assigned_to is not None:
        db_incident.assigned_to = update_in.assigned_to
    db_incident.updated_at = datetime.now(timezone.utc)

    # Append entry to AuditLog
    audit_entry = AuditLog(
        tenant_id=db_incident.tenant_id,
        user_id=update_in.user_id,
        action="UPDATE_INCIDENT_STATUS",
        resource=f"incident:{db_incident.id}",
        details={
            "incident_id": db_incident.id,
            "previous_status": old_status,
            "new_status": db_incident.status,
            "assigned_to": db_incident.assigned_to,
            "notes": update_in.notes,
        },
        created_at=datetime.now(timezone.utc),
    )
    db.add(audit_entry)
    db.commit()
    db.refresh(db_incident)

    return db_incident


@router.get("/{incident_id}/timeline", response_model=IncidentTimelineResponse)
def get_incident_timeline(
    incident_id: str,
    tenant_id: Optional[str] = Query(None, description="Optional tenant ID"),
    db: Session = Depends(get_db),
):
    query = db.query(Incident).filter(Incident.id == incident_id)
    if tenant_id:
        query = query.filter(Incident.tenant_id == tenant_id)
    incident = query.first()

    timeline_items: List[TimelineItem] = []

    if incident:
        # Base incident creation
        timeline_items.append(
            TimelineItem(
                timestamp=incident.created_at,
                type="incident_created",
                title=f"Incident Created: {incident.title}",
                description=incident.description,
                severity=incident.severity,
                metadata={"incident_id": incident.id, "status": incident.status},
            )
        )

        # Linked alerts
        for alt in incident.alerts:
            timeline_items.append(
                TimelineItem(
                    timestamp=alt.observed_at,
                    type="alert_triggered",
                    title=f"Alert: {alt.title}",
                    description=alt.description,
                    severity=alt.severity,
                    metadata={"alert_id": alt.id, "rule_id": alt.rule_id},
                )
            )

        # Linked attributions
        for attr in incident.attributions:
            timeline_items.append(
                TimelineItem(
                    timestamp=attr.created_at,
                    type="attribution_detected",
                    title=f"Attribution: {attr.actor_name}",
                    description=f"Campaign: {attr.campaign or 'N/A'}, Confidence: {attr.confidence_score}",
                    severity="high",
                    metadata={"attribution_id": attr.id, "confidence": attr.confidence_score},
                )
            )

        # Audit logs for incident
        audits = (
            db.query(AuditLog)
            .filter(AuditLog.resource == f"incident:{incident.id}")
            .order_by(AuditLog.created_at.asc())
            .all()
        )
        for aud in audits:
            timeline_items.append(
                TimelineItem(
                    timestamp=aud.created_at,
                    type="status_change",
                    title=f"Analyst Action: {aud.action}",
                    description=f"Details: {aud.details.get('notes') or aud.details.get('new_status')}",
                    severity="info",
                    metadata=aud.details,
                )
            )

        # If incident had no alerts in DB yet, check fixtures to augment
        if len(incident.alerts) == 0:
            fixture_incidents = load_fixture("incidents.json")
            matching_fi = next((fi for fi in fixture_incidents if fi.get("id") == incident_id), None)
            if matching_fi:
                alert_ids = matching_fi.get("alert_ids", [])
                fixture_alerts = load_fixture("alerts.json")
                for fa in fixture_alerts:
                    if fa.get("id") in alert_ids:
                        timeline_items.append(
                            TimelineItem(
                                timestamp=parse_datetime(fa.get("observed_at")),
                                type="alert_triggered",
                                title=f"Alert: {fa.get('title')}",
                                description=fa.get("description"),
                                severity=fa.get("severity"),
                                metadata={"alert_id": fa.get("id"), "rule_id": fa.get("rule_id")},
                            )
                        )

    else:
        # Fallback to fixtures entirely
        fixture_incidents = load_fixture("incidents.json")
        matching_fi = next((fi for fi in fixture_incidents if fi.get("id") == incident_id), None)
        if not matching_fi:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident '{incident_id}' not found",
            )

        timeline_items.append(
            TimelineItem(
                timestamp=parse_datetime(matching_fi.get("created_at")),
                type="incident_created",
                title=f"Incident Created: {matching_fi.get('title')}",
                description=matching_fi.get("description"),
                severity=matching_fi.get("severity"),
                metadata={"incident_id": matching_fi.get("id")},
            )
        )

        alert_ids = matching_fi.get("alert_ids", [])
        fixture_alerts = load_fixture("alerts.json")
        for fa in fixture_alerts:
            if fa.get("id") in alert_ids:
                timeline_items.append(
                    TimelineItem(
                        timestamp=parse_datetime(fa.get("observed_at")),
                        type="alert_triggered",
                        title=f"Alert: {fa.get('title')}",
                        description=fa.get("description"),
                        severity=fa.get("severity"),
                        metadata={"alert_id": fa.get("id"), "rule_id": fa.get("rule_id")},
                    )
                )

        fixture_attributions = load_fixture("attribution.json")
        for attr in fixture_attributions:
            if attr.get("incident_id") == incident_id:
                timeline_items.append(
                    TimelineItem(
                        timestamp=parse_datetime(attr.get("created_at")),
                        type="attribution_detected",
                        title=f"Attribution: {attr.get('actor_name')}",
                        description=f"Campaign: {attr.get('campaign')}, Confidence: {attr.get('confidence_score')}",
                        severity="high",
                        metadata={"attribution_id": attr.get("id")},
                    )
                )

    timeline_items.sort(key=lambda item: item.timestamp)
    return IncidentTimelineResponse(
        incident_id=incident_id,
        total=len(timeline_items),
        timeline=timeline_items,
    )


@router.get("/{incident_id}/graph", response_model=IncidentGraphResponse)
def get_incident_graph(
    incident_id: str,
    tenant_id: Optional[str] = Query(None, description="Optional tenant ID"),
    db: Session = Depends(get_db),
):
    query = db.query(Incident).filter(Incident.id == incident_id)
    if tenant_id:
        query = query.filter(Incident.tenant_id == tenant_id)
    incident = query.first()

    nodes: List[GraphNode] = []
    edges: List[GraphEdge] = []
    node_ids = set()

    def add_node(node: GraphNode):
        if node.id not in node_ids:
            nodes.append(node)
            node_ids.add(node.id)

    patient_zero: Optional[Dict[str, Any]] = None
    blast_radius: Optional[Dict[str, Any]] = None

    if incident and incident.alerts:
        # Incident root node
        add_node(
            GraphNode(
                id=incident.id,
                label=incident.title,
                type="incident",
                properties={"severity": incident.severity, "status": incident.status},
            )
        )

        all_entities = []
        earliest_dt = None

        for alt in incident.alerts:
            add_node(
                GraphNode(
                    id=alt.id,
                    label=alt.title,
                    type="alert",
                    properties={"severity": alt.severity, "rule_id": alt.rule_id},
                )
            )
            edges.append(
                GraphEdge(
                    source=alt.id,
                    target=incident.id,
                    relation="PART_OF",
                    weight=1.0,
                )
            )

            # Link events & entities
            for evt in alt.events:
                # Find entities for event
                ent_list = (
                    db.query(Entity)
                    .filter(Entity.tenant_id == incident.tenant_id)
                    .limit(5)
                    .all()
                )
                for ent in ent_list:
                    all_entities.append(ent)
                    add_node(
                        GraphNode(
                            id=ent.id,
                            label=ent.identifier,
                            type=ent.entity_type,
                            properties=ent.properties or {},
                        )
                    )
                    edges.append(
                        GraphEdge(
                            source=ent.id,
                            target=alt.id,
                            relation="TRIGGERED",
                            weight=1.0,
                        )
                    )
                    if earliest_dt is None or (ent.first_seen and ent.first_seen < earliest_dt):
                        earliest_dt = ent.first_seen
                        patient_zero = {
                            "id": ent.id,
                            "label": ent.identifier,
                            "type": ent.entity_type,
                            "first_seen": ent.first_seen.isoformat() if ent.first_seen else None,
                        }

        # Attributions
        for attr in incident.attributions:
            add_node(
                GraphNode(
                    id=attr.id,
                    label=attr.actor_name,
                    type="threat_actor",
                    properties={"confidence": attr.confidence_score, "campaign": attr.campaign},
                )
            )
            edges.append(
                GraphEdge(
                    source=attr.id,
                    target=incident.id,
                    relation="ATTRIBUTED_TO",
                    weight=attr.confidence_score,
                )
            )

        unique_ents = {e.id for e in all_entities}
        blast_radius = {
            "total_entities": len(unique_ents),
            "affected_hosts": sum(1 for e in all_entities if e.entity_type == "host"),
            "affected_users": sum(1 for e in all_entities if e.entity_type == "user"),
            "affected_ips": sum(1 for e in all_entities if e.entity_type == "ip"),
            "score": float(len(unique_ents)),
        }

        return IncidentGraphResponse(
            incident_id=incident_id,
            nodes=nodes,
            edges=edges,
            patient_zero=patient_zero,
            blast_radius=blast_radius,
        )

    # Fallback to fixtures
    fixture_incidents = load_fixture("incidents.json")
    matching_fi = next((fi for fi in fixture_incidents if fi.get("id") == incident_id), None)
    if not matching_fi:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    # Build graph from fixture datasets
    add_node(
        GraphNode(
            id=matching_fi["id"],
            label=matching_fi["title"],
            type="incident",
            properties={"severity": matching_fi.get("severity"), "status": matching_fi.get("status")},
        )
    )

    alert_ids = set(matching_fi.get("alert_ids", []))
    fixture_alerts = load_fixture("alerts.json")
    fixture_events = load_fixture("events.json")
    fixture_attributions = load_fixture("attribution.json")

    event_map = {fe.get("event_id") or fe.get("id"): fe for fe in fixture_events}
    all_fixture_entities: List[Dict[str, Any]] = []
    earliest_seen: Optional[datetime] = None

    for fa in fixture_alerts:
        if fa.get("id") in alert_ids:
            add_node(
                GraphNode(
                    id=fa["id"],
                    label=fa["title"],
                    type="alert",
                    properties={"severity": fa.get("severity"), "rule_id": fa.get("rule_id")},
                )
            )
            edges.append(
                GraphEdge(
                    source=fa["id"],
                    target=matching_fi["id"],
                    relation="PART_OF",
                    weight=1.0,
                )
            )

            # Link events and their entities
            for evt_id in fa.get("event_ids", []):
                evt_data = event_map.get(evt_id)
                if evt_data:
                    evt_time = parse_datetime(evt_data.get("observed_at"))
                    for ent in evt_data.get("entities", []):
                        ent_id = f"ent-{ent.get('entity_type')}-{ent.get('identifier')}"
                        ent_dict = {
                            "id": ent_id,
                            "label": ent.get("identifier"),
                            "type": ent.get("entity_type"),
                            "observed_at": evt_time,
                        }
                        all_fixture_entities.append(ent_dict)
                        add_node(
                            GraphNode(
                                id=ent_id,
                                label=ent.get("identifier"),
                                type=ent.get("entity_type"),
                                properties={"source_layer": evt_data.get("source_layer")},
                            )
                        )
                        edges.append(
                            GraphEdge(
                                source=ent_id,
                                target=fa["id"],
                                relation="TRIGGERED",
                                weight=1.0,
                            )
                        )

                        if earliest_seen is None or evt_time < earliest_seen:
                            earliest_seen = evt_time
                            patient_zero = {
                                "id": ent_id,
                                "label": ent.get("identifier"),
                                "type": ent.get("entity_type"),
                                "first_seen": evt_time.isoformat(),
                            }

    # Attributions
    for attr in fixture_attributions:
        if attr.get("incident_id") == incident_id:
            add_node(
                GraphNode(
                    id=attr["id"],
                    label=attr["actor_name"],
                    type="threat_actor",
                    properties={
                        "confidence": attr.get("confidence_score"),
                        "campaign": attr.get("campaign"),
                    },
                )
            )
            edges.append(
                GraphEdge(
                    source=attr["id"],
                    target=matching_fi["id"],
                    relation="ATTRIBUTED_TO",
                    weight=float(attr.get("confidence_score", 1.0)),
                )
            )

    unique_ent_ids = {e["id"] for e in all_fixture_entities}
    blast_radius = {
        "total_entities": len(unique_ent_ids),
        "affected_hosts": sum(1 for e in all_fixture_entities if e["type"] == "host"),
        "affected_users": sum(1 for e in all_fixture_entities if e["type"] == "user"),
        "affected_ips": sum(1 for e in all_fixture_entities if e["type"] == "ip"),
        "score": float(len(unique_ent_ids)),
    }

    return IncidentGraphResponse(
        incident_id=incident_id,
        nodes=nodes,
        edges=edges,
        patient_zero=patient_zero,
        blast_radius=blast_radius,
    )
