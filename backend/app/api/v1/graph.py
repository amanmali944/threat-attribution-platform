from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.entity import Entity
from app.models.alert import Alert
from app.schemas.graph import GraphNode, GraphEdge, GraphResponse

router = APIRouter(prefix="/graph", tags=["Graph Topology"])

@router.get("", response_model=GraphResponse)
def get_entity_graph(
    tenant_id: str = Query(..., description="Tenant ID filter"),
    incident_id: Optional[str] = Query(None, description="Optional incident correlation ID"),
    db: Session = Depends(get_db),
):
    # Retrieve tenant entities and alerts to build graph visualization model
    entities = db.query(Entity).filter(Entity.tenant_id == tenant_id).limit(100).all()
    alerts = db.query(Alert).filter(Alert.tenant_id == tenant_id).limit(50).all()

    nodes = []
    edges = []

    for ent in entities:
        nodes.append(GraphNode(
            id=ent.id,
            label=ent.identifier,
            type=ent.entity_type,
            properties=ent.properties or {}
        ))

    for alt in alerts:
        nodes.append(GraphNode(
            id=alt.id,
            label=alt.title,
            type="alert",
            properties={"severity": alt.severity, "rule_id": alt.rule_id}
        ))
        # If there are entities, link first entity to this alert as example connection
        if entities:
            edges.append(GraphEdge(
                source=entities[0].id,
                target=alt.id,
                relation="TRIGGERED",
                weight=1.0
            ))

    return GraphResponse(nodes=nodes, edges=edges)
