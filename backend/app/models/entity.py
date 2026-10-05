from datetime import datetime, timezone
import uuid
from sqlalchemy import Column, String, DateTime, JSON

from app.models.base import Base

class Entity(Base):
    __tablename__ = "entities"

    id = Column(String(64), primary_key=True, default=lambda: f"ent-{uuid.uuid4().hex[:12]}")
    tenant_id = Column(String(64), nullable=False, index=True)
    entity_type = Column(String(32), nullable=False)  # host, user, ip, process, file
    identifier = Column(String(255), nullable=False, index=True)
    properties = Column(JSON, nullable=False, default=dict)
    first_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    last_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)

    def __repr__(self):
        return f"<Entity {self.id} tenant={self.tenant_id} type={self.entity_type} id={self.identifier}>"
