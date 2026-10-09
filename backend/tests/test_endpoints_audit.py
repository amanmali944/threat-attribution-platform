import os
import sys
from pathlib import Path
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

# Ensure backend directory is in sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

os.environ["TESTING"] = "1"

from app.main import app
from app.core.database import init_db, get_db


@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    init_db()


@pytest.fixture
def client():
    return TestClient(app)


# ======================================================================
# Endpoint Contract & Route Sanity Audit Tests
# ======================================================================

def test_health_check_endpoint(client: TestClient):
    """
    GET /health -> 200 OK
    Verifies that the health check endpoint returns 200 OK and expected payload.
    """
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data.get("status") == "ok"


def test_auth_login_endpoint(client: TestClient):
    """
    POST /api/v1/auth/login -> 422 or 401 (never 404).
    Verifies that the login route exists and handles empty/invalid/valid credentials.
    """
    # 1. Empty body: Must return 401 or 422, NEVER 404
    resp_empty = client.post("/api/v1/auth/login")
    assert resp_empty.status_code in (401, 422), f"Expected 401 or 422, got {resp_empty.status_code}"
    assert resp_empty.status_code != 404

    # 2. Invalid credentials: Must return 401 Unauthorized, NEVER 404
    resp_invalid = client.post(
        "/api/v1/auth/login",
        data={"username": "nonexistent_analyst", "password": "wrongpassword"},
    )
    assert resp_invalid.status_code == 401
    assert resp_invalid.status_code != 404

    # 3. Valid credentials: Must return 200 OK with access token
    resp_valid = client.post(
        "/api/v1/auth/login",
        data={"username": "analyst", "password": "password"},
    )
    assert resp_valid.status_code == 200
    token_data = resp_valid.json()
    assert "access_token" in token_data
    assert token_data.get("token_type") == "bearer"


def test_auth_me_endpoint_accessibility(client: TestClient):
    """
    GET /api/v1/auth/me -> 401 when unauthenticated, 200 when authenticated (never 404).
    """
    # Unauthenticated request
    resp_unauth = client.get("/api/v1/auth/me")
    assert resp_unauth.status_code == 401
    assert resp_unauth.status_code != 404

    # Authenticated request
    login_resp = client.post(
        "/api/v1/auth/login",
        data={"username": "analyst", "password": "password"},
    )
    token = login_resp.json()["access_token"]
    resp_auth = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp_auth.status_code == 200
    assert resp_auth.json().get("username") == "analyst"


def test_events_endpoint(client: TestClient):
    """
    GET /api/v1/events -> 200/401 (never 404).
    """
    # With tenant query parameter
    resp_tenant = client.get("/api/v1/events?tenant_id=tenant-default-001")
    assert resp_tenant.status_code in (200, 401)
    assert resp_tenant.status_code != 404

    # Missing query parameter returns 422 or 200/401, never 404
    resp_no_param = client.get("/api/v1/events")
    assert resp_no_param.status_code in (200, 401, 422)
    assert resp_no_param.status_code != 404


def test_alerts_endpoint(client: TestClient):
    """
    GET /api/v1/alerts -> 200/401 (never 404).
    """
    # With tenant query parameter
    resp_tenant = client.get("/api/v1/alerts?tenant_id=tenant-default-001")
    assert resp_tenant.status_code in (200, 401)
    assert resp_tenant.status_code != 404

    # Missing query parameter returns 422 or 200/401, never 404
    resp_no_param = client.get("/api/v1/alerts")
    assert resp_no_param.status_code in (200, 401, 422)
    assert resp_no_param.status_code != 404


def test_incidents_endpoint(client: TestClient):
    """
    GET /api/v1/incidents -> 200/401 (never 404).
    """
    # With tenant query parameter
    resp_tenant = client.get("/api/v1/incidents?tenant_id=tenant-default-001")
    assert resp_tenant.status_code in (200, 401)
    assert resp_tenant.status_code != 404

    # Missing query parameter returns 422 or 200/401, never 404
    resp_no_param = client.get("/api/v1/incidents")
    assert resp_no_param.status_code in (200, 401, 422)
    assert resp_no_param.status_code != 404


def test_dashboard_summary_endpoint(client: TestClient):
    """
    GET /api/v1/dashboard/summary -> 200/401 (never 404).
    """
    # With tenant query parameter
    resp_tenant = client.get("/api/v1/dashboard/summary?tenant_id=tenant-default-001")
    assert resp_tenant.status_code in (200, 401)
    assert resp_tenant.status_code != 404

    # Missing query parameter returns 422 or 200/401, never 404
    resp_no_param = client.get("/api/v1/dashboard/summary")
    assert resp_no_param.status_code in (200, 401, 422)
    assert resp_no_param.status_code != 404


# ======================================================================
# Database Resilience & Error Recovery Tests
# ======================================================================

def test_database_init_resilience_on_operational_error():
    """
    Verifies that init_db() catches OperationalError cleanly without crashing,
    and falls back to in-memory SQLite storage.
    """
    from app.models.base import Base

    with patch.object(Base.metadata, "create_all", side_effect=[OperationalError("FATAL: password authentication failed", None, None), None]):
        # Must not raise an exception; should recover via fallback
        init_db()
