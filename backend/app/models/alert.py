from datetime import datetime, timezone
import uuid
from sqlalchemy import Column, String, DateTime, Text, Table, ForeignKey
from sqlalchemy.orm import relationship

from app.models.base import Base

# Association table for Incidents <-> Alerts
incident_alerts = Table(
    "incident_alerts",
    Base.metadata,
    Column("incident_id", String(64), ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    Column("alert_id", String(64), ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True),
)

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String(64), primary_key=True, default=lambda: f"alt-{uuid.uuid4().hex[:12]}")
    tenant_id = Column(String(64), nullable=False, index=True)
    rule_id = Column(String(64), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(16), nullable=False, default="medium")
    status = Column(String(32), nullable=False, default="open")
    observed_at = Column(DateTime(timezone=True), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)

    events = relationship("Event", secondary="event_alerts", back_populates="alerts")
    incidents = relationship("Incident", secondary=incident_alerts, back_populates="alerts")

    def __repr__(self):
        return f"<Alert {self.id} tenant={self.tenant_id} title={self.title}>"
