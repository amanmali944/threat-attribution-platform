from datetime import datetime, timezone
import uuid
from sqlalchemy import Column, String, DateTime, Text
from sqlalchemy.orm import relationship

from app.models.base import Base

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String(64), primary_key=True, default=lambda: f"inc-{uuid.uuid4().hex[:12]}")
    tenant_id = Column(String(64), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(16), nullable=False, default="high")
    status = Column(String(32), nullable=False, default="investigating")
    assigned_to = Column(String(128), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    alerts = relationship("Alert", secondary="incident_alerts", back_populates="incidents")
    attributions = relationship("Attribution", back_populates="incident", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Incident {self.id} tenant={self.tenant_id} title={self.title}>"
