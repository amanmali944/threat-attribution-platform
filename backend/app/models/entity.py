from datetime import datetime, timezone
import hashlib
import uuid
from sqlalchemy import Column, String, DateTime, JSON

from app.models.base import Base


def generate_entity_id(entity_type: str, tenant_id: str, identifier: str) -> str:
    """Standardized deterministic entity ID generation matching seed.py (CR-06):
    ent-{type}-{sha256(tenant_id:identifier)[:8]}
    """
    ent_hash = hashlib.sha256(f"{tenant_id}:{identifier}".encode("utf-8")).hexdigest()[:8]
    return f"ent-{entity_type}-{ent_hash}"


class Entity(Base):
    __tablename__ = "entities"

    id = Column(String(64), primary_key=True, default=lambda: f"ent-{uuid.uuid4().hex[:12]}")
    tenant_id = Column(String(64), nullable=False, index=True)
    entity_type = Column(String(32), nullable=False)  # host, user, ip, process, file, domain, cloud_identity, application, database, device (CR-02)
    identifier = Column(String(255), nullable=False, index=True)
    properties = Column(JSON, nullable=False, default=dict)
    first_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    last_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)

    def __init__(self, **kwargs):
        if "id" not in kwargs and "entity_type" in kwargs and "tenant_id" in kwargs and "identifier" in kwargs:
            kwargs["id"] = generate_entity_id(kwargs["entity_type"], kwargs["tenant_id"], kwargs["identifier"])
        super().__init__(**kwargs)

    def __repr__(self):
        return f"<Entity {self.id} tenant={self.tenant_id} type={self.entity_type} id={self.identifier}>"
