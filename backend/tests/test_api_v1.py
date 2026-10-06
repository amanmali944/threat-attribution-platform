import os
import sys
from pathlib import Path

# Add backend directory to path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

os.environ["TESTING"] = "1"

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.database import SessionLocal, init_db
from app.models.audit_log import AuditLog
from app.models.incident import Incident
from app.models.alert import Alert
from app.models.event import Event


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    init_db()


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ======================================================================
# 1. Fresh DB / Mock Fixtures Fallback Tests
# ======================================================================
def test_fixture_fallback_alerts(client: TestClient):
    response = client.get("/api/v1/alerts?tenant_id=tenant-default-001")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "items" in data
    assert len(data["items"]) >= 3
    assert data["items"][0]["rule_id"] in ["RULE-WIN-001", "RULE-NET-004", "RULE-IDP-009"]


def test_fixture_fallback_alert_detail(client: TestClient):
    response = client.get("/api/v1/alerts/alt-5001")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "alt-5001"
    assert "event_ids" in data
    assert "evt-1001" in data["event_ids"]
    assert "evidence_refs" in data
    assert "evt-1001" in data["evidence_refs"]


def test_fixture_fallback_incidents(client: TestClient):
    response = client.get("/api/v1/incidents?tenant_id=tenant-default-001")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert len(data["items"]) >= 2
    assert any(i["id"] == "inc-9001" for i in data["items"])


def test_fixture_fallback_incident_detail(client: TestClient):
    response = client.get("/api/v1/incidents/inc-9001")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "inc-9001"
    assert "Cross-Layer" in data["title"]


def test_fixture_fallback_incident_timeline(client: TestClient):
    response = client.get("/api/v1/incidents/inc-9001/timeline")
    assert response.status_code == 200
    data = response.json()
    assert data["incident_id"] == "inc-9001"
    assert data["total"] > 0
    assert len(data["timeline"]) > 0
    # Items should be chronologically ordered
    timestamps = [item["timestamp"] for item in data["timeline"]]
    assert timestamps == sorted(timestamps)


def test_fixture_fallback_incident_graph(client: TestClient):
    response = client.get("/api/v1/incidents/inc-9001/graph")
    assert response.status_code == 200
    data = response.json()
    assert data["incident_id"] == "inc-9001"
    assert len(data["nodes"]) > 0
    assert len(data["edges"]) > 0
    assert data["patient_zero"] is not None
    assert "workstation-01.corp.internal" in data["patient_zero"]["label"]
    assert data["blast_radius"] is not None
    assert data["blast_radius"]["total_entities"] > 0


def test_fixture_fallback_dashboard_summary(client: TestClient):
    response = client.get("/api/v1/dashboard/summary?tenant_id=tenant-default-001")
    assert response.status_code == 200
    data = response.json()
    assert data["tenant_id"] == "tenant-default-001"
    assert data["total_incidents"] >= 2
    assert data["risk_distribution"]["critical"] >= 1
    assert data["alert_volume"]["total"] >= 3


def test_fixture_fallback_entities(client: TestClient):
    response = client.get("/api/v1/entities?tenant_id=tenant-default-001")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] > 0
    assert len(data["items"]) > 0


# ======================================================================
# 2. Telemetry Ingestion API Tests
# ======================================================================
def test_create_event_valid(client: TestClient):
    payload = {
        "event_id": "evt-test-custom-01",
        "tenant_id": "tenant-corp-x",
        "source_layer": "endpoint",
        "event_type": "process_execution",
        "observed_at": "2026-10-06T11:00:00Z",
        "severity": "medium",
        "entities": [
            {"entity_type": "host", "identifier": "laptop-44.corp.local"},
            {"entity_type": "user", "identifier": "corp\\alice"},
        ],
        "payload": {
            "process_name": "cmd.exe",
            "command_line": "whoami /all",
        },
        "metadata": {"sensor": "test-agent"},
    }
    response = client.post("/api/v1/events", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["id"] == "evt-test-custom-01"
    assert data["status"] == "ingested"
    assert "created_at" in data


def test_create_event_invalid_payload(client: TestClient):
    # Missing required tenant_id, source_layer, event_type, observed_at
    bad_payload = {"severity": "low"}
    response = client.post("/api/v1/events", json=bad_payload)
    assert response.status_code == 422


def test_list_events_with_tenant_and_filters(client: TestClient):
    response = client.get(
        "/api/v1/events?tenant_id=tenant-corp-x&source_layer=endpoint&limit=10&offset=0"
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1
    assert data["items"][0]["source_layer"] == "endpoint"


def test_list_events_missing_tenant_returns_422(client: TestClient):
    response = client.get("/api/v1/events")
    assert response.status_code == 422


# ======================================================================
# 3. Alerts & Triage API Tests
# ======================================================================
def test_create_and_list_alert(client: TestClient):
    alert_payload = {
        "tenant_id": "tenant-corp-x",
        "rule_id": "RULE-TEST-001",
        "title": "Suspicious Privilege Query",
        "description": "User queried whoami /all in unusual context",
        "severity": "medium",
        "status": "open",
        "observed_at": "2026-10-06T11:00:05Z",
        "event_ids": ["evt-test-custom-01"],
    }
    create_resp = client.post("/api/v1/alerts", json=alert_payload)
    assert create_resp.status_code == 201
    alert_data = create_resp.json()
    alert_id = alert_data["id"]

    # List alerts filtering by detector / rule_id
    list_resp = client.get(
        f"/api/v1/alerts?tenant_id=tenant-corp-x&detector=RULE-TEST-001&status=open"
    )
    assert list_resp.status_code == 200
    list_data = list_resp.json()
    assert list_data["total"] >= 1
    assert any(a["id"] == alert_id for a in list_data["items"])

    # Fetch alert detail with evidence refs
    detail_resp = client.get(f"/api/v1/alerts/{alert_id}")
    assert detail_resp.status_code == 200
    detail_data = detail_resp.json()
    assert detail_data["id"] == alert_id
    assert "evt-test-custom-01" in detail_data["evidence_refs"]


def test_get_alert_not_found(client: TestClient):
    response = client.get("/api/v1/alerts/nonexistent-alert-99999")
    assert response.status_code == 404


# ======================================================================
# 4. Incidents & Attribution Routing Tests
# ======================================================================
def test_create_and_list_incidents(client: TestClient):
    incident_payload = {
        "tenant_id": "tenant-corp-x",
        "title": "Reconnaissance Activity Cluster",
        "description": "Multiple discovery commands executed",
        "severity": "medium",
        "status": "open",
        "assigned_to": "analyst_bob@corp.com",
    }
    create_resp = client.post("/api/v1/incidents", json=incident_payload)
    assert create_resp.status_code == 201
    inc_data = create_resp.json()
    inc_id = inc_data["id"]

    # List incidents
    list_resp = client.get(
        f"/api/v1/incidents?tenant_id=tenant-corp-x&status=open&limit=10&offset=0"
    )
    assert list_resp.status_code == 200
    list_data = list_resp.json()
    assert list_data["total"] >= 1
    assert any(i["id"] == inc_id for i in list_data["items"])


def test_get_incident_not_found(client: TestClient):
    response = client.get("/api/v1/incidents/nonexistent-incident-99999")
    assert response.status_code == 404


def test_patch_incident_status_and_audit_log(client: TestClient, db_session):
    # 1. Create a fresh incident
    incident_payload = {
        "tenant_id": "tenant-corp-x",
        "title": "Triage Test Incident",
        "severity": "high",
        "status": "open",
    }
    create_resp = client.post("/api/v1/incidents", json=incident_payload)
    assert create_resp.status_code == 201
    incident_id = create_resp.json()["id"]

    # 2. PATCH status to reviewed
    patch_payload = {
        "status": "reviewed",
        "assigned_to": "senior_analyst@corp.com",
        "notes": "Verified initial telemetry; escalating severity.",
        "user_id": "usr-analyst-42",
    }
    patch_resp = client.patch(f"/api/v1/incidents/{incident_id}", json=patch_payload)
    assert patch_resp.status_code == 200
    updated_data = patch_resp.json()
    assert updated_data["status"] == "reviewed"
    assert updated_data["assigned_to"] == "senior_analyst@corp.com"

    # 3. Verify AuditLog entry was appended in DB
    audit_entry = (
        db_session.query(AuditLog)
        .filter(AuditLog.resource == f"incident:{incident_id}")
        .order_by(AuditLog.created_at.desc())
        .first()
    )
    assert audit_entry is not None
    assert audit_entry.action == "UPDATE_INCIDENT_STATUS"
    assert audit_entry.details["previous_status"] == "open"
    assert audit_entry.details["new_status"] == "reviewed"
    assert audit_entry.details["notes"] == "Verified initial telemetry; escalating severity."

    # 4. PATCH status to confirmed
    patch_resp2 = client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "confirmed", "notes": "Confirmed true positive."},
    )
    assert patch_resp2.status_code == 200
    assert patch_resp2.json()["status"] == "confirmed"


def test_patch_incident_invalid_status_returns_422(client: TestClient):
    response = client.patch(
        "/api/v1/incidents/inc-9001",
        json={"status": "completely_invalid_status"},
    )
    assert response.status_code == 422


def test_incident_timeline_endpoint(client: TestClient):
    response = client.get("/api/v1/incidents/inc-9001/timeline")
    assert response.status_code == 200
    data = response.json()
    assert "timeline" in data
    assert isinstance(data["timeline"], list)


def test_incident_graph_endpoint(client: TestClient):
    response = client.get("/api/v1/incidents/inc-9001/graph")
    assert response.status_code == 200
    data = response.json()
    assert "nodes" in data
    assert "edges" in data
    assert "patient_zero" in data
    assert "blast_radius" in data


# ======================================================================
# 5. Dashboard & Evaluation Routers Tests
# ======================================================================
def test_dashboard_summary_route(client: TestClient):
    response = client.get("/api/v1/dashboard/summary?tenant_id=tenant-corp-x")
    assert response.status_code == 200
    data = response.json()
    assert data["tenant_id"] == "tenant-corp-x"
    assert "open_incidents" in data
    assert "risk_distribution" in data
    assert "alert_volume" in data
    assert "total_events" in data


def test_evaluation_summary_route(client: TestClient):
    response = client.get("/api/v1/evaluation/summary")
    assert response.status_code == 200
    data = response.json()
    assert "model_version" in data
    assert "overall_precision" in data
    assert "overall_recall" in data
    assert "overall_f1" in data
    assert "per_class_metrics" in data
    assert "endpoint_execution" in data["per_class_metrics"]
    assert "calibration" in data
    assert "brier_score" in data["calibration"]


# ======================================================================
# 6. Entities Router Tests
# ======================================================================
def test_create_and_get_entity(client: TestClient):
    entity_payload = {
        "tenant_id": "tenant-corp-x",
        "entity_type": "host",
        "identifier": "srv-finance-01.corp.internal",
        "properties": {"os": "Linux Ubuntu 22.04", "ip": "10.0.8.20"},
    }
    create_resp = client.post("/api/v1/entities", json=entity_payload)
    assert create_resp.status_code == 201
    ent_data = create_resp.json()
    ent_id = ent_data["id"]

    # List entities
    list_resp = client.get(
        "/api/v1/entities?tenant_id=tenant-corp-x&entity_type=host&identifier=finance"
    )
    assert list_resp.status_code == 200
    list_data = list_resp.json()
    assert list_data["total"] >= 1

    # Fetch entity detail
    detail_resp = client.get(f"/api/v1/entities/{ent_id}")
    assert detail_resp.status_code == 200
    assert detail_resp.json()["identifier"] == "srv-finance-01.corp.internal"


def test_get_entity_not_found(client: TestClient):
    response = client.get("/api/v1/entities/nonexistent-ent-99999")
    assert response.status_code == 404
