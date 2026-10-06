from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.api.v1.events import load_fixture, parse_datetime
from app.core.database import get_db
from app.models.entity import Entity

router = APIRouter(prefix="/entities", tags=["Entities"])


class EntityCreate(BaseModel):
    tenant_id: str = Field(..., example="tenant-01")
    entity_type: str = Field(..., example="host")
    identifier: str = Field(..., example="workstation-01.corp.internal")
    properties: Dict[str, Any] = Field(default_factory=dict)


class EntityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    entity_type: str
    identifier: str
    properties: Dict[str, Any]
    first_seen: datetime
    last_seen: datetime


class EntityListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: List[EntityResponse]


@router.post("", response_model=EntityResponse, status_code=status.HTTP_201_CREATED)
def create_entity(entity_in: EntityCreate, db: Session = Depends(get_db)):
    db_entity = Entity(
        tenant_id=entity_in.tenant_id,
        entity_type=entity_in.entity_type,
        identifier=entity_in.identifier,
        properties=entity_in.properties,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    db.add(db_entity)
    db.commit()
    db.refresh(db_entity)
    return db_entity


@router.get("", response_model=EntityListResponse)
def list_entities(
    tenant_id: str = Query(..., description="Tenant ID filter"),
    entity_type: Optional[str] = Query(None, description="Entity type filter (host, user, ip, domain)"),
    identifier: Optional[str] = Query(None, description="Identifier substring filter"),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    query = db.query(Entity).filter(Entity.tenant_id == tenant_id)
    if entity_type:
        query = query.filter(Entity.entity_type == entity_type)
    if identifier:
        query = query.filter(Entity.identifier.ilike(f"%{identifier}%"))

    total_in_db = query.count()

    # Fallback to extracting entities from fixture events if DB has none
    if total_in_db == 0:
        fixture_events = load_fixture("events.json")
        seen_entities: Dict[str, Dict[str, Any]] = {}
        for fe in fixture_events:
            f_tenant = fe.get("tenant_id", "")
            if f_tenant != tenant_id and tenant_id not in ["tenant-default-001", "tenant-01"]:
                continue
            obs_dt = parse_datetime(fe.get("observed_at"))
            for ent in fe.get("entities", []):
                e_type = ent.get("entity_type")
                e_ident = ent.get("identifier")
                key = f"{e_type}:{e_ident}"
                if key not in seen_entities:
                    seen_entities[key] = {
                        "id": f"ent-{abs(hash(key)) % 10000}",
                        "tenant_id": tenant_id,
                        "entity_type": e_type,
                        "identifier": e_ident,
                        "properties": {"source_layer": fe.get("source_layer")},
                        "first_seen": obs_dt,
                        "last_seen": obs_dt,
                    }
                else:
                    if obs_dt > seen_entities[key]["last_seen"]:
                        seen_entities[key]["last_seen"] = obs_dt
                    if obs_dt < seen_entities[key]["first_seen"]:
                        seen_entities[key]["first_seen"] = obs_dt

        filtered_entities = list(seen_entities.values())
        if entity_type:
            filtered_entities = [e for e in filtered_entities if e["entity_type"] == entity_type]
        if identifier:
            filtered_entities = [e for e in filtered_entities if identifier.lower() in e["identifier"].lower()]

        total_fixture = len(filtered_entities)
        paginated_items = [
            EntityResponse(**e) for e in filtered_entities[offset : offset + limit]
        ]
        return EntityListResponse(
            total=total_fixture,
            limit=limit,
            offset=offset,
            items=paginated_items,
        )

    total = total_in_db
    items = query.order_by(Entity.first_seen.desc()).offset(offset).limit(limit).all()
    return EntityListResponse(total=total, limit=limit, offset=offset, items=items)


@router.get("/{entity_id}", response_model=EntityResponse)
def get_entity(
    entity_id: str,
    tenant_id: Optional[str] = Query(None, description="Optional tenant ID"),
    db: Session = Depends(get_db),
):
    query = db.query(Entity).filter(Entity.id == entity_id)
    if tenant_id:
        query = query.filter(Entity.tenant_id == tenant_id)
    entity = query.first()

    if entity:
        return entity

    # Fallback to fixture
    fixture_events = load_fixture("events.json")
    for fe in fixture_events:
        for ent in fe.get("entities", []):
            candidate_id = f"ent-{ent.get('entity_type')}-{ent.get('identifier')}"
            hash_id = f"ent-{abs(hash(f'{ent.get('entity_type')}:{ent.get('identifier')}')) % 10000}"
            if entity_id in [candidate_id, hash_id]:
                obs_dt = parse_datetime(fe.get("observed_at"))
                return EntityResponse(
                    id=entity_id,
                    tenant_id=tenant_id or fe.get("tenant_id"),
                    entity_type=ent.get("entity_type"),
                    identifier=ent.get("identifier"),
                    properties={"source_layer": fe.get("source_layer")},
                    first_seen=obs_dt,
                    last_seen=obs_dt,
                )

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Entity '{entity_id}' not found",
    )
