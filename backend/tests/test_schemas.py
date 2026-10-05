import sys
import unittest
from pathlib import Path
from datetime import datetime, timezone

backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.schemas.event import EventCreate, EventResponse
from app.schemas.alert import AlertCreate, AlertResponse
from app.schemas.incident import IncidentCreate, IncidentResponse
from app.schemas.attribution import AttributionCreate, AttributionResponse
from app.schemas.graph import GraphResponse, GraphNode, GraphEdge
from app.schemas.summary import SummaryResponse

class TestSchemas(unittest.TestCase):
    def test_pydantic_schemas_validation(self):
        now = datetime.now(timezone.utc)

        evt_create = EventCreate(
            tenant_id="tenant-01",
            source_layer="network",
            event_type="dns_query",
            observed_at=now,
            severity="info",
            payload={"domain": "malicious.com"}
        )
        self.assertEqual(evt_create.source_layer, "network")

        alt_create = AlertCreate(
            tenant_id="tenant-01",
            rule_id="RULE-NET-01",
            title="Suspicious DNS Query",
            observed_at=now
        )
        self.assertEqual(alt_create.rule_id, "RULE-NET-01")

        inc_create = IncidentCreate(
            tenant_id="tenant-01",
            title="C2 Communication",
            severity="critical"
        )
        self.assertEqual(inc_create.severity, "critical")

        att_create = AttributionCreate(
            tenant_id="tenant-01",
            incident_id="inc-9001",
            actor_name="FIN7",
            confidence_score=0.85,
            tactics_techniques=[{"tactic": "Command and Control", "technique_id": "T1071"}]
        )
        self.assertEqual(att_create.confidence_score, 0.85)

        graph_res = GraphResponse(
            nodes=[GraphNode(id="n1", label="host-1", type="host")],
            edges=[GraphEdge(source="n1", target="n2", relation="CONNECTED_TO")]
        )
        self.assertEqual(len(graph_res.nodes), 1)

        summary_res = SummaryResponse(
            tenant_id="tenant-01",
            total_events=100,
            total_alerts=5,
            total_incidents=1,
            open_incidents=1,
            critical_alerts=2,
            top_threat_actors=["FIN7"]
        )
        self.assertEqual(summary_res.total_events, 100)

if __name__ == "__main__":
    unittest.main()
