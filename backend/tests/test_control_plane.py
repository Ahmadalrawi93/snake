import os
import tempfile
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

def test_project_authorization_target_and_audit_flow():
    project = client.post("/api/v1/projects", json={"name": "Authorized Lab", "description": "test"}).json()
    assert project["id"] > 0
    auth = client.post(f"/api/v1/projects/{project['id']}/authorizations",
        json={"reference": "https://example.org/program", "notes": "Pending verification"}).json()
    assert auth["status"] == "pending"
    target = client.post(f"/api/v1/projects/{project['id']}/targets",
        json={"value": "https://example.org", "target_type": "url"}).json()
    assert target["status"] == "registered"
    events = client.get("/api/v1/audit").json()
    assert [e["action"] for e in events][:3] == ["target.registered", "authorization.recorded", "project.created"]

def test_missing_project_returns_404():
    response = client.post("/api/v1/projects/99999/targets",
        json={"value": "https://example.org", "target_type": "url"})
    assert response.status_code == 404
