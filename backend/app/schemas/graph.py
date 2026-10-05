from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class GraphNode(BaseModel):
    id: str = Field(..., example="ent-1")
    label: str = Field(..., example="workstation-01")
    type: str = Field(..., example="host")
    properties: Dict[str, Any] = Field(default_factory=dict)

class GraphEdge(BaseModel):
    source: str = Field(..., example="ent-2")
    target: str = Field(..., example="ent-1")
    relation: str = Field(..., example="LOGGED_INTO")
    weight: float = Field(1.0, example=1.0)

class GraphResponse(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]
