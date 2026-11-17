from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.db.database import Base, get_db

engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base.metadata.create_all(bind=engine)

def override_db():
    db = TestingSession()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_db
client = TestClient(app)

def register_and_auth(email="tester@example.org"):
    response = client.post("/api/v1/auth/register",
        json={"email": email, "password": "a-strong-test-password-123"})
    assert response.status_code == 201
    login = client.post("/api/v1/auth/login",
        json={"email": email, "password": "a-strong-test-password-123"})
    assert login.status_code == 200
    return {"Authorization": f"Bearer {login.json()['access_token']}"}

def test_auth_and_project_authorization_target_audit_flow():
    headers = register_and_auth()
    me = client.get("/api/v1/auth/me", headers=headers)
    assert me.status_code == 200
    project_response = client.post("/api/v1/projects",
        json={"name": "Authorized Lab", "description": "test"}, headers=headers)
    assert project_response.status_code == 201
    project = project_response.json()
    auth = client.post(f"/api/v1/projects/{project['id']}/authorizations",
        json={"reference": "https://example.org/program", "notes": "Pending verification"},
        headers=headers).json()
    assert auth["status"] == "pending"
    target_response = client.post(f"/api/v1/projects/{project['id']}/targets",
        json={"value": "https://example.org", "target_type": "url"}, headers=headers)
    assert target_response.status_code == 201
    events = client.get("/api/v1/audit", headers=headers).json()
    assert [e["action"] for e in events][:3] == [
        "target.registered", "authorization.recorded", "project.created"]

def test_project_api_requires_authentication():
    response = client.get("/api/v1/projects")
    assert response.status_code == 401

def test_users_cannot_access_each_others_projects():
    owner_headers = register_and_auth("owner@example.org")
    other_headers = register_and_auth("other@example.org")
    created = client.post("/api/v1/projects", json={"name": "Private Lab"}, headers=owner_headers)
    project_id = created.json()["id"]
    assert client.get("/api/v1/projects", headers=other_headers).json() == []
    denied = client.post(f"/api/v1/projects/{project_id}/targets",
        json={"value": "https://example.org", "target_type": "url"}, headers=other_headers)
    assert denied.status_code == 404

def test_missing_project_returns_404():
    headers = register_and_auth("missing@example.org")
    response = client.post("/api/v1/projects/99999/targets",
        json={"value": "https://example.org", "target_type": "url"}, headers=headers)
    assert response.status_code == 404

def test_duplicate_registration_and_bad_password_are_rejected():
    payload = {"email": "auth-edge@example.org", "password": "a-strong-test-password-123"}
    assert client.post("/api/v1/auth/register", json=payload).status_code == 201
    assert client.post("/api/v1/auth/register", json=payload).status_code == 409
    bad_login = client.post("/api/v1/auth/login",
        json={"email": payload["email"], "password": "wrong-password"})
    assert bad_login.status_code == 401

def test_only_admin_can_review_authorization_records():
    user_headers = register_and_auth("submitter@example.org")
    project = client.post("/api/v1/projects", json={"name": "Review Lab"}, headers=user_headers).json()
    record = client.post(f"/api/v1/projects/{project['id']}/authorizations",
        json={"reference": "https://example.org/security", "notes": "Program scope evidence"},
        headers=user_headers).json()
    denied = client.post(f"/api/v1/admin/authorizations/{record['id']}/review",
        json={"decision": "approved", "review_notes": "Looks good"}, headers=user_headers)
    assert denied.status_code == 403

    admin_headers = register_and_auth("reviewer@example.org")
    db = TestingSession()
    try:
        from app.db.models import User
        admin_user = db.query(User).filter_by(email="reviewer@example.org").one()
        admin_user.role = "admin"
        db.commit()
    finally:
        db.close()

    pending = client.get("/api/v1/admin/authorizations/pending", headers=admin_headers)
    assert pending.status_code == 200
    assert any(item["id"] == record["id"] for item in pending.json())

    approved = client.post(f"/api/v1/admin/authorizations/{record['id']}/review",
        json={"decision": "approved", "review_notes": "Authorization evidence reviewed manually", "scope_rules": ["example.org"]},
        headers=admin_headers)
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"
    duplicate_review = client.post(f"/api/v1/admin/authorizations/{record['id']}/review",
        json={"decision": "rejected", "review_notes": "Second decision attempt"},
        headers=admin_headers)
    assert duplicate_review.status_code == 409

def test_scope_snapshot_requires_approved_matching_authorization():
    from app.db.models import User
    headers = register_and_auth("scope-owner@example.org")
    project = client.post("/api/v1/projects", json={"name": "Scope Project"}, headers=headers).json()
    target = client.post(f"/api/v1/projects/{project['id']}/targets",
        json={"value": "https://app.example.org/login", "target_type": "url"}, headers=headers).json()
    auth = client.post(f"/api/v1/projects/{project['id']}/authorizations",
        json={"reference": "https://program.example.org", "notes": "Evidence submitted"},
        headers=headers).json()
    endpoint = f"/api/v1/projects/{project['id']}/targets/{target['id']}/scope-snapshots"
    assert client.post(endpoint, headers=headers).status_code == 403

    admin_headers = register_and_auth("scope-admin@example.org")
    db = TestingSession()
    try:
        admin_user = db.query(User).filter_by(email="scope-admin@example.org").one()
        admin_user.role = "admin"
        db.commit()
    finally:
        db.close()

    approved = client.post(f"/api/v1/admin/authorizations/{auth['id']}/review",
        json={"decision": "approved", "review_notes": "Reviewed scope evidence",
              "scope_rules": ["*.example.org"]}, headers=admin_headers)
    assert approved.status_code == 200
    snapshot_response = client.post(endpoint, headers=headers)
    assert snapshot_response.status_code == 201
    snapshot = snapshot_response.json()
    assert snapshot["snapshot"]["hostname"] == "app.example.org"
    assert snapshot["snapshot"]["execution_enabled"] is False
    assert len(snapshot["sha256"]) == 64

def test_scope_snapshot_rejects_out_of_scope_target():
    from app.db.models import User
    headers = register_and_auth("scope-denied@example.org")
    project = client.post("/api/v1/projects", json={"name": "Out of Scope"}, headers=headers).json()
    target = client.post(f"/api/v1/projects/{project['id']}/targets",
        json={"value": "https://evil.invalid", "target_type": "url"}, headers=headers).json()
    auth = client.post(f"/api/v1/projects/{project['id']}/authorizations",
        json={"reference": "https://program.example.org"}, headers=headers).json()
    admin_headers = register_and_auth("scope-denied-admin@example.org")
    db = TestingSession()
    try:
        db.query(User).filter_by(email="scope-denied-admin@example.org").one().role = "admin"
        db.commit()
    finally:
        db.close()
    assert client.post(f"/api/v1/admin/authorizations/{auth['id']}/review",
        json={"decision": "approved", "review_notes": "Only example.org is in scope",
              "scope_rules": ["example.org"]}, headers=admin_headers).status_code == 200
    denied = client.post(f"/api/v1/projects/{project['id']}/targets/{target['id']}/scope-snapshots",
        headers=headers)
    assert denied.status_code == 403
