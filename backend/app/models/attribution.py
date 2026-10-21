from datetime import datetime, timezone
import uuid
from sqlalchemy import Column, String, DateTime, Float, JSON, ForeignKey
from sqlalchemy.orm import relationship

from app.models.base import Base

class Attribution(Base):
    __tablename__ = "attributions"

    id = Column(String(64), primary_key=True, default=lambda: f"att-{uuid.uuid4().hex[:12]}")
    tenant_id = Column(String(64), nullable=False, index=True)
    incident_id = Column(String(64), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    actor_name = Column(String(128), nullable=True)  # Nullable for causal reconstruction v1 (CR-05)
    campaign = Column(String(128), nullable=True)
    confidence_score = Column(Float, nullable=False, default=0.0)
    tactics_techniques = Column(JSON, nullable=False, default=list)

    # Developer A Analytical Graph Attribution Fields (CR-04)
    entry_point = Column(JSON, nullable=True)  # Earliest anomalous root node dict
    attack_path = Column(JSON, nullable=True, default=list)  # Ordered causal path edges
    reached_assets = Column(JSON, nullable=True, default=list)  # Assets touched after entry
    blast_radius = Column(JSON, nullable=True)  # reached_count, potential_reach_count dict
    dwell_time_seconds = Column(Float, nullable=True)
    explanation = Column(JSON, nullable=True)  # Natural language or structured explanation
    graph = Column(JSON, nullable=True)  # Stored node & edge topology graph

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)

    incident = relationship("Incident", back_populates="attributions")

    def __repr__(self):
        return f"<Attribution {self.id} tenant={self.tenant_id} actor={self.actor_name} score={self.confidence_score}>"
