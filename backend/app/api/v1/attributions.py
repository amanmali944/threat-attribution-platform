from datetime import datetime, timezone
import uuid
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.v1.events import load_fixture, parse_datetime
from app.core.database import get_db
from app.models.attribution import Attribution
from app.schemas.attribution import (
    AttributionCreate,
    AttributionListResponse,
    AttributionResponse,
)

router = APIRouter(prefix="/attributions", tags=["Attributions"])


@router.post("", response_model=AttributionResponse, status_code=status.HTTP_201_CREATED)
def create_attribution(attribution_in: AttributionCreate, db: Session = Depends(get_db)):
    attr_id = attribution_in.attribution_id or attribution_in.id or f"att-{uuid.uuid4().hex[:12]}"
    
    # Extract confidence (support both confidence and confidence_score)
    conf = (
        attribution_in.confidence
        if attribution_in.confidence is not None
        else (attribution_in.confidence_score if attribution_in.confidence_score is not None else 0.0)
    )

    # Normalize tactics/techniques
    ttps = attribution_in.tactics_techniques or attribution_in.techniques or []

    db_attribution = Attribution(
        id=attr_id,
        tenant_id=attribution_in.tenant_id,
        incident_id=attribution_in.incident_id,
        actor_name=attribution_in.actor_name,
        campaign=attribution_in.campaign,
        confidence_score=conf,
        tactics_techniques=ttps,
        entry_point=attribution_in.entry_point,
        attack_path=attribution_in.attack_path or [],
        reached_assets=attribution_in.reached_assets or [],
        blast_radius=attribution_in.blast_radius,
        dwell_time_seconds=attribution_in.dwell_time_seconds,
        explanation=attribution_in.explanation,
        graph=attribution_in.graph,
    )

    db.add(db_attribution)
    db.commit()
    db.refresh(db_attribution)

    return AttributionResponse(
        id=db_attribution.id,
        attribution_id=db_attribution.id,
        tenant_id=db_attribution.tenant_id,
        incident_id=db_attribution.incident_id,
        actor_name=db_attribution.actor_name,
        campaign=db_attribution.campaign,
        confidence_score=db_attribution.confidence_score,
        confidence=db_attribution.confidence_score,
        tactics_techniques=db_attribution.tactics_techniques or [],
        techniques=db_attribution.tactics_techniques or [],
        entry_point=db_attribution.entry_point,
        attack_path=db_attribution.attack_path or [],
        reached_assets=db_attribution.reached_assets or [],
        blast_radius=db_attribution.blast_radius,
        dwell_time_seconds=db_attribution.dwell_time_seconds,
        explanation=db_attribution.explanation,
        graph=db_attribution.graph,
        created_at=db_attribution.created_at or datetime.now(timezone.utc),
    )


@router.get("", response_model=AttributionListResponse)
def list_attributions(
    tenant_id: str = Query(..., description="Tenant ID filter"),
    incident_id: Optional[str] = Query(None, description="Incident ID filter"),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    query = db.query(Attribution).filter(Attribution.tenant_id == tenant_id)
    if incident_id:
        query = query.filter(Attribution.incident_id == incident_id)

    total_in_db = query.count()

    if total_in_db == 0:
        fixture_attributions = load_fixture("attribution.json")
        filtered_fixtures = []
        for fa in fixture_attributions:
            f_tenant = fa.get("tenant_id", "")
            if f_tenant != tenant_id and tenant_id not in ["tenant-default-001", "tenant-01"]:
                continue
            if incident_id and fa.get("incident_id") != incident_id:
                continue

            created_dt = parse_datetime(fa.get("created_at"))
            conf = fa.get("confidence_score") or fa.get("confidence", 0.0)

            filtered_fixtures.append(
                AttributionResponse(
                    id=fa.get("id") or fa.get("attribution_id"),
                    attribution_id=fa.get("attribution_id") or fa.get("id"),
                    tenant_id=tenant_id,
                    incident_id=fa.get("incident_id"),
                    actor_name=fa.get("actor_name"),
                    campaign=fa.get("campaign"),
                    confidence_score=conf,
                    confidence=conf,
                    tactics_techniques=fa.get("tactics_techniques", []),
                    techniques=fa.get("techniques", []),
                    entry_point=fa.get("entry_point"),
                    attack_path=fa.get("attack_path", []),
                    reached_assets=fa.get("reached_assets", []),
                    blast_radius=fa.get("blast_radius"),
                    dwell_time_seconds=fa.get("dwell_time_seconds"),
                    explanation=fa.get("explanation"),
                    graph=fa.get("graph"),
                    created_at=created_dt,
                )
            )

        total_fixture = len(filtered_fixtures)
        paginated_fixtures = filtered_fixtures[offset : offset + limit]
        return AttributionListResponse(
            total=total_fixture,
            limit=limit,
            offset=offset,
            items=paginated_fixtures,
        )

    total = total_in_db
    items = query.order_by(Attribution.created_at.desc()).offset(offset).limit(limit).all()
    resp_items = [
        AttributionResponse(
            id=item.id,
            attribution_id=item.id,
            tenant_id=item.tenant_id,
            incident_id=item.incident_id,
            actor_name=item.actor_name,
            campaign=item.campaign,
            confidence_score=item.confidence_score,
            confidence=item.confidence_score,
            tactics_techniques=item.tactics_techniques or [],
            techniques=item.tactics_techniques or [],
            entry_point=item.entry_point,
            attack_path=item.attack_path or [],
            reached_assets=item.reached_assets or [],
            blast_radius=item.blast_radius,
            dwell_time_seconds=item.dwell_time_seconds,
            explanation=item.explanation,
            graph=item.graph,
            created_at=item.created_at,
        )
        for item in items
    ]
    return AttributionListResponse(total=total, limit=limit, offset=offset, items=resp_items)


@router.get("/{attribution_id}", response_model=AttributionResponse)
def get_attribution(
    attribution_id: str,
    tenant_id: Optional[str] = Query(None, description="Optional tenant ID"),
    db: Session = Depends(get_db),
):
    query = db.query(Attribution).filter(Attribution.id == attribution_id)
    if tenant_id:
        query = query.filter(Attribution.tenant_id == tenant_id)
    attr = query.first()

    if attr:
        return AttributionResponse(
            id=attr.id,
            attribution_id=attr.id,
            tenant_id=attr.tenant_id,
            incident_id=attr.incident_id,
            actor_name=attr.actor_name,
            campaign=attr.campaign,
            confidence_score=attr.confidence_score,
            confidence=attr.confidence_score,
            tactics_techniques=attr.tactics_techniques or [],
            techniques=attr.tactics_techniques or [],
            entry_point=attr.entry_point,
            attack_path=attr.attack_path or [],
            reached_assets=attr.reached_assets or [],
            blast_radius=attr.blast_radius,
            dwell_time_seconds=attr.dwell_time_seconds,
            explanation=attr.explanation,
            graph=attr.graph,
            created_at=attr.created_at,
        )

    fixture_attributions = load_fixture("attribution.json")
    for fa in fixture_attributions:
        if fa.get("id") == attribution_id or fa.get("attribution_id") == attribution_id:
            if tenant_id and fa.get("tenant_id") != tenant_id and tenant_id not in ["tenant-default-001", "tenant-01"]:
                continue
            conf = fa.get("confidence_score") or fa.get("confidence", 0.0)
            return AttributionResponse(
                id=fa.get("id") or fa.get("attribution_id"),
                attribution_id=fa.get("attribution_id") or fa.get("id"),
                tenant_id=tenant_id or fa.get("tenant_id"),
                incident_id=fa.get("incident_id"),
                actor_name=fa.get("actor_name"),
                campaign=fa.get("campaign"),
                confidence_score=conf,
                confidence=conf,
                tactics_techniques=fa.get("tactics_techniques", []),
                techniques=fa.get("techniques", []),
                entry_point=fa.get("entry_point"),
                attack_path=fa.get("attack_path", []),
                reached_assets=fa.get("reached_assets", []),
                blast_radius=fa.get("blast_radius"),
                dwell_time_seconds=fa.get("dwell_time_seconds"),
                explanation=fa.get("explanation"),
                graph=fa.get("graph"),
                created_at=parse_datetime(fa.get("created_at")),
            )

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Attribution '{attribution_id}' not found",
    )
