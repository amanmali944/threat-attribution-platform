import os
import sys
import unittest
from pathlib import Path
from datetime import datetime, timezone

backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

os.environ["TESTING"] = "1"

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models.base import Base
from app.models.event import Event
from app.models.entity import Entity
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.attribution import Attribution
from app.models.user import User
from app.models.audit_log import AuditLog

class TestModels(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=cls.engine)
        cls.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=cls.engine)

    def test_models_instantiation(self):
        session = self.SessionLocal()

        now = datetime.now(timezone.utc)
        evt = Event(
            id="evt-test-1",
            tenant_id="tenant-01",
            source_layer="endpoint",
            event_type="process_execution",
            observed_at=now,
            payload={"cmd": "whoami"},
            severity="low"
        )
        ent = Entity(
            id="ent-test-1",
            tenant_id="tenant-01",
            entity_type="host",
            identifier="host-01",
            properties={"os": "windows"}
        )
        alt = Alert(
            id="alt-test-1",
            tenant_id="tenant-01",
            rule_id="RULE-01",
            title="Test Alert",
            severity="medium",
            observed_at=now
        )
        inc = Incident(
            id="inc-test-1",
            tenant_id="tenant-01",
            title="Test Incident",
            severity="high"
        )
        att = Attribution(
            id="att-test-1",
            tenant_id="tenant-01",
            incident_id="inc-test-1",
            actor_name="APT29",
            confidence_score=0.9
        )
        usr = User(
            id="usr-test-1",
            tenant_id="tenant-01",
            username="testuser",
            email="test@corp.com",
            hashed_password="hashed"
        )
        log = AuditLog(
            id="aud-test-1",
            tenant_id="tenant-01",
            user_id="usr-test-1",
            action="LOGIN",
            resource="portal"
        )

        session.add_all([evt, ent, alt, inc, att, usr, log])
        session.commit()

        self.assertIsNotNone(session.query(Event).filter_by(id="evt-test-1").first())
        self.assertIsNotNone(session.query(Entity).filter_by(id="ent-test-1").first())
        self.assertIsNotNone(session.query(Alert).filter_by(id="alt-test-1").first())
        self.assertIsNotNone(session.query(Incident).filter_by(id="inc-test-1").first())
        self.assertIsNotNone(session.query(Attribution).filter_by(id="att-test-1").first())
        self.assertIsNotNone(session.query(User).filter_by(id="usr-test-1").first())
        self.assertIsNotNone(session.query(AuditLog).filter_by(id="aud-test-1").first())

        session.close()

if __name__ == "__main__":
    unittest.main()
