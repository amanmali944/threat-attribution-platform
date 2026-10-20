from datetime import datetime, timezone
import uuid
from sqlalchemy import Column, String, DateTime, JSON, Table, ForeignKey
from sqlalchemy.orm import relationship

from app.models.base import Base

# Association table for Events <-> Alerts
event_alerts = Table(
    "event_alerts",
    Base.metadata,
    Column("event_id", String(64), ForeignKey("events.id", ondelete="CASCADE"), primary_key=True),
    Column("alert_id", String(64), ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True),
)

class Event(Base):
    __tablename__ = "events"

    id = Column(String(64), primary_key=True, default=lambda: f"evt-{uuid.uuid4().hex[:12]}")
    tenant_id = Column(String(64), nullable=False, index=True)
    source_layer = Column(String(32), nullable=False)  # endpoint, network, cloud, identity, application, database
    event_type = Column(String(64), nullable=False)
    observed_at = Column(DateTime(timezone=True), nullable=False, index=True)
    payload = Column(JSON, nullable=False, default=dict)
    entities = Column(JSON, nullable=True, default=list)  # Associated entities (CR-07)
    event_metadata = Column("metadata", JSON, nullable=True, default=dict)  # Telemetry metadata (CR-07)
    severity = Column(String(16), nullable=False, default="info")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)

    alerts = relationship("Alert", secondary=event_alerts, back_populates="events")

    def __init__(self, **kwargs):
        if "metadata" in kwargs:
            kwargs["event_metadata"] = kwargs.pop("metadata")
        super().__init__(**kwargs)

    def __repr__(self):
        return f"<Event {self.id} tenant={self.tenant_id} layer={self.source_layer} type={self.event_type}>"
