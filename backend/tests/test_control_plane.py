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
