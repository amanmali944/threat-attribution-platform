import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
import jwt
import pytest
from fastapi.testclient import TestClient

# Ensure backend directory is in sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

os.environ["TESTING"] = "1"

from app.main import app
from app.core.config import settings
from app.core.database import SessionLocal, init_db
from app.core.security import (
    create_access_token,
    decode_access_token,
    get_password_hash,
    verify_password,
    SECRET_KEY,
    ALGORITHM,
)
from app.models.user import User
from app.api.deps import require_role, get_current_tenant


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
# 1. Security Utilities Unit Tests (app.core.security)
# ======================================================================

def test_password_hashing_and_verification():
    plain_password = "SuperSecretPassword123!"
    hashed = get_password_hash(plain_password)

    # Hash must be distinct from plaintext and non-empty
    assert hashed != plain_password
    assert hashed.startswith("$2")  # bcrypt hash identifier

    # Verification must succeed for authentic password
    assert verify_password(plain_password, hashed) is True

    # Verification must fail for invalid passwords
    assert verify_password("WrongPassword123!", hashed) is False
    assert verify_password("", hashed) is False
    assert verify_password(plain_password, "") is False


def test_jwt_create_and_decode_valid():
    payload_data = {
        "sub": "soc_analyst_01",
        "role": "analyst",
        "tenant_id": "tenant-001",
    }
    token = create_access_token(data=payload_data, expires_delta=timedelta(minutes=30))
    assert isinstance(token, str)

    decoded = decode_access_token(token)
    assert decoded["sub"] == "soc_analyst_01"
    assert decoded["role"] == "analyst"
    assert decoded["tenant_id"] == "tenant-001"
    assert "exp" in decoded
    assert "iat" in decoded


def test_jwt_token_expiration_handling():
    payload_data = {"sub": "expired_user", "role": "analyst"}
    # Token expired 10 minutes ago
    expired_token = create_access_token(data=payload_data, expires_delta=timedelta(minutes=-10))

    with pytest.raises(jwt.ExpiredSignatureError):
        decode_access_token(expired_token)

    # Can decode without verification if needed
    decoded_unverified = decode_access_token(expired_token, verify_exp=False)
    assert decoded_unverified["sub"] == "expired_user"


def test_jwt_invalid_and_tampered_token():
    tampered_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalidpayload.invalidsignature"

    with pytest.raises(jwt.InvalidTokenError):
        decode_access_token(tampered_token)


# ======================================================================
# 2. Authentication Endpoints Integration Tests (app.api.v1.auth)
# ======================================================================

def test_login_success_form_data(client: TestClient):
    """
    Verifies OAuth2 standard password form login returns 200 with access_token and bearer type.
    """
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "analyst", "password": "password"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["role"] == "analyst"

    # Validate that generated token decodes properly
    claims = decode_access_token(data["access_token"])
    assert claims["sub"] == "analyst"
    assert claims["role"] == "analyst"


def test_login_success_json_data(client: TestClient):
    """
    Verifies flexible login accepting JSON payloads for developer ergonomics.
    """
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "password"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["role"] == "admin"


def test_login_invalid_password(client: TestClient):
    """
    Verifies HTTP 401 Unauthorized when password does not match.
    """
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "analyst", "password": "WrongPassword!"},
    )
    assert response.status_code == 401
    assert "Incorrect username or password" in response.json()["detail"]
    assert response.headers.get("www-authenticate") == "Bearer"


def test_login_unknown_user(client: TestClient):
    """
    Verifies HTTP 401 Unauthorized for non-existent username.
    """
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "non_existent_user_999", "password": "any_password"},
    )
    assert response.status_code == 401
    assert "Incorrect username or password" in response.json()["detail"]


def test_login_inactive_user(client: TestClient, db_session):
    """
    Verifies HTTP 400 Bad Request when an account is disabled/inactive.
    """
    inactive_username = "disabled_analyst"
    existing = db_session.query(User).filter(User.username == inactive_username).first()
    if not existing:
        disabled_user = User(
            id="usr-test-inactive",
            tenant_id="tenant-default-001",
            username=inactive_username,
            email="inactive@corp.internal",
            hashed_password=get_password_hash("password123"),
            role="analyst",
            is_active=False,
        )
        db_session.add(disabled_user)
        db_session.commit()

    response = client.post(
        "/api/v1/auth/login",
        data={"username": inactive_username, "password": "password123"},
    )
    assert response.status_code == 400
    assert "Inactive user account" in response.json()["detail"]


# ======================================================================
# 3. GET /api/v1/auth/me Endpoint Tests
# ======================================================================

def test_auth_me_unauthenticated(client: TestClient):
    """
    Verifies GET /auth/me returns 401 Unauthorized when Bearer header is missing.
    """
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401


def test_auth_me_invalid_token(client: TestClient):
    """
    Verifies GET /auth/me returns 401 Unauthorized for corrupted/invalid token.
    """
    headers = {"Authorization": "Bearer invalid.token.payload"}
    response = client.get("/api/v1/auth/me", headers=headers)
    assert response.status_code == 401
    assert "Could not validate credentials" in response.json()["detail"]


def test_auth_me_expired_token(client: TestClient):
    """
    Verifies GET /auth/me returns 401 Unauthorized for expired token.
    """
    expired_token = create_access_token(
        data={"sub": "analyst", "role": "analyst"},
        expires_delta=timedelta(minutes=-5),
    )
    headers = {"Authorization": f"Bearer {expired_token}"}
    response = client.get("/api/v1/auth/me", headers=headers)
    assert response.status_code == 401
    assert "Token has expired" in response.json()["detail"]


def test_auth_me_authenticated_success(client: TestClient):
    """
    Verifies GET /auth/me returns authenticated user's profile details.
    """
    # 1. Login
    login_resp = client.post(
        "/api/v1/auth/login",
        data={"username": "analyst", "password": "password"},
    )
    token = login_resp.json()["access_token"]

    # 2. Query /auth/me
    headers = {"Authorization": f"Bearer {token}"}
    me_resp = client.get("/api/v1/auth/me", headers=headers)
    assert me_resp.status_code == 200
    data = me_resp.json()
    assert data["username"] == "analyst"
    assert data["role"] == "analyst"
    assert data["tenant_id"] == "tenant-default-001"
    assert data["is_active"] is True
    assert "created_at" in data


# ======================================================================
# 4. Role-Based Access Control (RBAC) & Tenant Scoping Tests
# ======================================================================

def test_rbac_admin_allowed_on_admin_endpoint(client: TestClient):
    """
    Verifies that a user with 'admin' role can access an admin-protected endpoint.
    """
    login_resp = client.post(
        "/api/v1/auth/login",
        data={"username": "admin", "password": "password"},
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.get("/api/v1/auth/admin-only", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "authorized"
    assert resp.json()["role"] == "admin"


def test_rbac_analyst_forbidden_on_admin_endpoint(client: TestClient):
    """
    Verifies that a user with 'analyst' role receives HTTP 403 Forbidden
    when accessing an admin-protected endpoint.
    """
    login_resp = client.post(
        "/api/v1/auth/login",
        data={"username": "analyst", "password": "password"},
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.get("/api/v1/auth/admin-only", headers=headers)
    assert resp.status_code == 403
    assert "Operation not permitted" in resp.json()["detail"]


def test_rbac_viewer_forbidden_on_admin_endpoint(client: TestClient):
    """
    Verifies that a user with 'read_only' role receives HTTP 403 Forbidden.
    """
    login_resp = client.post(
        "/api/v1/auth/login",
        data={"username": "viewer", "password": "password"},
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.get("/api/v1/auth/admin-only", headers=headers)
    assert resp.status_code == 403


def test_require_role_dependency_factory_direct():
    """
    Unit test directly evaluating require_role dependency callable logic.
    """
    admin_user = User(username="adm", role="admin", tenant_id="t-1", is_active=True)
    analyst_user = User(username="ana", role="analyst", tenant_id="t-1", is_active=True)

    admin_checker = require_role(["admin"])
    # Passing admin user to checker succeeds
    assert admin_checker(admin_user) == admin_user

    # Passing analyst user to admin checker raises 403
    with pytest.raises(Exception) as exc_info:
        admin_checker(analyst_user)
    assert exc_info.value.status_code == 403

    multi_checker = require_role(["admin", "analyst"])
    assert multi_checker(admin_user) == admin_user
    assert multi_checker(analyst_user) == analyst_user


def test_tenant_scoping_dependency(client: TestClient):
    """
    Verifies tenant scoping extraction from authenticated user context.
    """
    login_resp = client.post(
        "/api/v1/auth/login",
        data={"username": "analyst", "password": "password"},
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.get("/api/v1/auth/tenant", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["tenant_id"] == "tenant-default-001"


# ======================================================================
# 5. Full End-to-End Registration & Verification Flow
# ======================================================================

def test_custom_user_end_to_end(client: TestClient, db_session):
    """
    Integration test creating a new user directly in DB with hashed password,
    authenticating through /api/v1/auth/login, and verifying RBAC permissions.
    """
    username = "custom_soc_lead"
    password = "SecOpsPassword#2026!"
    role = "admin"
    tenant_id = "tenant-custom-999"

    # Clean up if previously exists
    db_session.query(User).filter(User.username == username).delete()
    db_session.commit()

    # Create user with bcrypt-hashed password
    custom_user = User(
        id="usr-custom-lead-999",
        tenant_id=tenant_id,
        username=username,
        email="soclead@enterprise.sec",
        hashed_password=get_password_hash(password),
        role=role,
        is_active=True,
    )
    db_session.add(custom_user)
    db_session.commit()

    # 1. Login with correct credentials
    login_resp = client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": password},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]

    # 2. Access /auth/me with Bearer token
    headers = {"Authorization": f"Bearer {token}"}
    me_resp = client.get("/api/v1/auth/me", headers=headers)
    assert me_resp.status_code == 200
    assert me_resp.json()["username"] == username
    assert me_resp.json()["role"] == role
    assert me_resp.json()["tenant_id"] == tenant_id

    # 3. Access admin-restricted endpoint
    admin_resp = client.get("/api/v1/auth/admin-only", headers=headers)
    assert admin_resp.status_code == 200
    assert admin_resp.json()["status"] == "authorized"

    # 4. Access tenant scoping endpoint
    tenant_resp = client.get("/api/v1/auth/tenant", headers=headers)
    assert tenant_resp.status_code == 200
    assert tenant_resp.json()["tenant_id"] == tenant_id
