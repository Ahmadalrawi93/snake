import json
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
    login = client.post("/api/v1/auth/token",
        json={"email": email, "password": "a-strong-test-password-123"})
    assert login.status_code == 200
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    client.cookies.clear()
    return headers

def test_api_tokens_are_revocable_individually_and_in_bulk():
    email = "api-token-revoke@example.org"
    payload = {"email": email, "password": "a-strong-test-password-123"}
    assert client.post("/api/v1/auth/register", json=payload).status_code == 201
    first = client.post("/api/v1/auth/token", json=payload)
    second = client.post("/api/v1/auth/token", json=payload)
    assert first.status_code == second.status_code == 200
    first_headers = {"Authorization": f"Bearer {first.json()['access_token']}"}
    second_headers = {"Authorization": f"Bearer {second.json()['access_token']}"}
    client.cookies.clear()

    assert client.get("/api/v1/auth/me", headers=first_headers).status_code == 200
    assert client.post("/api/v1/auth/api-tokens/revoke", headers=first_headers).status_code == 204
    assert client.get("/api/v1/auth/me", headers=first_headers).status_code == 401
    assert client.get("/api/v1/auth/me", headers=second_headers).status_code == 200

    third = client.post("/api/v1/auth/token", json=payload)
    third_headers = {"Authorization": f"Bearer {third.json()['access_token']}"}
    assert client.post("/api/v1/auth/api-tokens/revoke-all", headers=third_headers).status_code == 204
    assert client.get("/api/v1/auth/me", headers=third_headers).status_code == 401
    assert client.get("/api/v1/auth/me", headers=second_headers).status_code == 401


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

def test_expired_browser_and_api_credentials_are_rejected():
    from datetime import datetime, timedelta, timezone
    from app.core.config import get_settings
    from app.core.security import decode_access_token_claims, token_id_digest
    from app.db.models import UserSession, ApiAccessToken

    payload = {"email": "expired-credentials@example.org", "password": "a-strong-test-password-123"}
    assert client.post("/api/v1/auth/register", json=payload).status_code == 201
    settings = get_settings()

    browser_login = client.post("/api/v1/auth/login", json=payload)
    browser_cookie = browser_login.cookies.get(settings.session_cookie_name)
    browser_claims = decode_access_token_claims(browser_cookie)
    assert browser_claims and isinstance(browser_claims.get("jti"), str)
    browser_digest = token_id_digest(browser_claims["jti"])
    client.cookies.clear()

    api_login = client.post("/api/v1/auth/token", json=payload)
    api_claims = decode_access_token_claims(api_login.json()["access_token"])
    assert api_claims and isinstance(api_claims.get("jti"), str)
    api_digest = token_id_digest(api_claims["jti"])

    db = TestingSession()
    try:
        expired_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        browser_record = db.query(UserSession).filter_by(token_id_sha256=browser_digest).one()
        api_record = db.query(ApiAccessToken).filter_by(token_id_sha256=api_digest).one()
        browser_record.expires_at = expired_at
        api_record.expires_at = expired_at
        db.commit()
    finally:
        db.close()

    client.cookies.set(settings.session_cookie_name, browser_cookie)
    assert client.get("/api/v1/auth/me").status_code == 401
    client.cookies.clear()
    assert client.get("/api/v1/auth/me", headers={
        "Authorization": f"Bearer {api_login.json()['access_token']}"
    }).status_code == 401


def test_legacy_stateless_jwt_is_rejected_after_token_registry_cutover():
    from app.core.security import create_access_token

    legacy = create_access_token("1")
    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {legacy}"})
    assert response.status_code == 401


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
    validation = client.get(f"/api/v1/scope-snapshots/{snapshot['id']}/validate", headers=headers)
    assert validation.status_code == 200
    assert validation.json()["valid"] is True
    assert validation.json()["execution_enabled"] is False

    # A later change to the authorization allowlist invalidates the old snapshot.
    db = TestingSession()
    try:
        from app.db.models import Authorization
        authorization_row = db.query(Authorization).filter_by(id=auth["id"]).one()
        authorization_row.scope_rules = '["different.example.org"]'
        db.commit()
    finally:
        db.close()
    changed_rules = client.get(
        f"/api/v1/scope-snapshots/{snapshot['id']}/validate", headers=headers
    )
    assert changed_rules.status_code == 200
    assert changed_rules.json()["valid"] is False
    assert "authorization_scope_rules_changed" in changed_rules.json()["reasons"]

    revoked = client.post(f"/api/v1/admin/scope-snapshots/{snapshot['id']}/revoke",
        headers=admin_headers)
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"
    invalidated = client.get(f"/api/v1/scope-snapshots/{snapshot['id']}/validate", headers=headers)
    assert invalidated.json()["valid"] is False
    assert "snapshot_not_active" in invalidated.json()["reasons"]

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

def test_domain_target_rejects_path_suffix():
    headers = register_and_auth("bad-domain-target@example.org")
    project = client.post("/api/v1/projects", json={"name": "Bad Domain"}, headers=headers).json()
    target = client.post(f"/api/v1/projects/{project['id']}/targets",
        json={"value": "example.org/extra", "target_type": "domain"}, headers=headers).json()
    response = client.post(
        f"/api/v1/projects/{project['id']}/targets/{target['id']}/scope-snapshots",
        headers=headers,
    )
    assert response.status_code == 422


def test_scan_job_requires_valid_snapshot_and_never_enables_execution():
    from app.db.models import User

    owner_headers = register_and_auth("job-owner@example.org")
    project = client.post("/api/v1/projects", json={"name": "Job Project"}, headers=owner_headers).json()
    target = client.post(
        f"/api/v1/projects/{project['id']}/targets",
        json={"value": "https://app.example.org", "target_type": "url"},
        headers=owner_headers,
    ).json()
    auth = client.post(
        f"/api/v1/projects/{project['id']}/authorizations",
        json={"reference": "https://program.example.org"},
        headers=owner_headers,
    ).json()

    admin_headers = register_and_auth("job-admin@example.org")
    db = TestingSession()
    try:
        db.query(User).filter_by(email="job-admin@example.org").one().role = "admin"
        db.commit()
    finally:
        db.close()

    reviewed = client.post(
        f"/api/v1/admin/authorizations/{auth['id']}/review",
        json={"decision": "approved", "review_notes": "Verified",
              "scope_rules": ["app.example.org"]},
        headers=admin_headers,
    )
    assert reviewed.status_code == 200

    snapshot_response = client.post(
        f"/api/v1/projects/{project['id']}/targets/{target['id']}/scope-snapshots",
        headers=owner_headers,
    )
    assert snapshot_response.status_code == 201
    snapshot_id = snapshot_response.json()["id"]

    created = client.post(
        f"/api/v1/scope-snapshots/{snapshot_id}/scan-jobs",
        json={"profile": "passive_recon"},
        headers=owner_headers,
    )
    assert created.status_code == 201
    job = created.json()
    assert job["status"] == "queued"
    assert job["execution_enabled"] is False

    listed = client.get(f"/api/v1/projects/{project['id']}/scan-jobs", headers=owner_headers)
    assert listed.status_code == 200
    assert any(item["id"] == job["id"] for item in listed.json())

    cancelled = client.post(f"/api/v1/scan-jobs/{job['id']}/cancel", headers=owner_headers)
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelled"
    assert cancelled.json()["execution_enabled"] is False

    revoked = client.post(
        f"/api/v1/admin/scope-snapshots/{snapshot_id}/revoke",
        headers=admin_headers,
    )
    assert revoked.status_code == 200
    denied = client.post(
        f"/api/v1/scope-snapshots/{snapshot_id}/scan-jobs",
        json={"profile": "passive_recon"},
        headers=owner_headers,
    )
    assert denied.status_code == 409


def test_scan_job_rejects_unsupported_profile():
    headers = register_and_auth("job-profile@example.org")
    response = client.post(
        "/api/v1/scope-snapshots/1/scan-jobs",
        json={"profile": "active_exploit"},
        headers=headers,
    )
    assert response.status_code == 422


def test_admin_can_register_list_and_revoke_worker_public_keys():
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from app.db.models import User

    user_headers = register_and_auth("worker-key-nonadmin@example.org")
    denied = client.post(
        "/api/v1/admin/workers/validator-01/keys",
        json={"key_id": "validator-01-v1", "public_key_b64": "not-a-key"},
        headers=user_headers,
    )
    assert denied.status_code == 403

    admin_headers = register_and_auth("worker-key-admin@example.org")
    db = TestingSession()
    try:
        db.query(User).filter_by(email="worker-key-admin@example.org").one().role = "admin"
        db.commit()
    finally:
        db.close()

    private = Ed25519PrivateKey.generate()
    public_b64 = base64.b64encode(private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )).decode()
    endpoint = "/api/v1/admin/workers/validator-01/keys"
    registered = client.post(
        endpoint,
        json={"key_id": "validator-01-v1", "public_key_b64": public_b64},
        headers=admin_headers,
    )
    assert registered.status_code == 201
    assert registered.json()["status"] == "active"
    fingerprint = registered.json()["fingerprint_sha256"]
    assert len(fingerprint) == 64

    duplicate = client.post(
        endpoint,
        json={"key_id": "validator-01-v1", "public_key_b64": public_b64},
        headers=admin_headers,
    )
    assert duplicate.status_code == 409

    forbidden_private = client.post(
        endpoint,
        json={"key_id": "validator-02-v1", "public_key_b64": public_b64,
              "private_key_b64": "must-not-be-accepted"},
        headers=admin_headers,
    )
    assert forbidden_private.status_code == 422

    listed = client.get("/api/v1/admin/workers/keys", headers=admin_headers)
    assert listed.status_code == 200
    assert any(row["fingerprint_sha256"] == fingerprint for row in listed.json())

    revoked = client.post(
        "/api/v1/admin/workers/validator-01/keys/validator-01-v1/revoke",
        headers=admin_headers,
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"

    duplicate_revoke = client.post(
        "/api/v1/admin/workers/validator-01/keys/validator-01-v1/revoke",
        headers=admin_headers,
    )
    assert duplicate_revoke.status_code == 409



def test_admin_reconciles_late_signed_worker_ack_once():
    import base64
    from datetime import datetime, timedelta, timezone
    from uuid import uuid4
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from app.core.worker_signing import sign_worker_validation_result
    from app.core.worker_protocol import WorkerValidationResult
    from app.db.models import (
        AuditEvent, ScanJob, User, WorkerDispatchAttempt, WorkerKey, WorkerTaskReceipt,
    )

    admin_headers = register_and_auth("reconcile-admin@example.org")
    now = datetime.now(timezone.utc)
    task_id = uuid4()
    worker_id, key_id = "reconcile-worker-01", "reconcile-key-v1"
    private = Ed25519PrivateKey.generate()
    private_b64 = base64.b64encode(private.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )).decode()
    public_b64 = base64.b64encode(private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )).decode()
    digest = "f" * 64
    db = TestingSession()
    try:
        db.query(User).filter_by(email="reconcile-admin@example.org").one().role = "admin"
        db.add(ScanJob(
            id=991, project_id=1, target_id=1, scope_snapshot_id=1,
            created_by=1, profile="passive_recon", status="dispatch_reserved",
            execution_enabled=False,
        ))
        db.add(WorkerKey(
            worker_id=worker_id, key_id=key_id, public_key_b64=public_b64,
            fingerprint_sha256=__import__(
                "app.core.worker_signing", fromlist=["ed25519_public_key_fingerprint"]
            ).ed25519_public_key_fingerprint(public_b64),
            status="active", created_by=None,
        ))
        db.add(WorkerTaskReceipt(
            task_id=str(task_id), job_id=991, envelope_sha256=digest,
            worker_id=worker_id, key_id=key_id,
            created_at=now - timedelta(seconds=20),
            expires_at=now - timedelta(seconds=2), consumed_at=None,
        ))
        db.add(WorkerDispatchAttempt(
            task_id=str(task_id), attempt_number=1, worker_id=worker_id,
            key_id=key_id, envelope_sha256=digest, status="unknown",
            error_code="transport_exception",
            started_at=now - timedelta(seconds=15),
            completed_at=now - timedelta(seconds=10),
        ))
        db.commit()
    finally:
        db.close()

    result = WorkerValidationResult(
        task_id=task_id, envelope_sha256=digest, worker_id=worker_id,
        outcome="accepted", validated_at=now - timedelta(seconds=5),
        execution_enabled=False,
    )
    signed = sign_worker_validation_result(result, private_b64, key_id=key_id)
    endpoint = f"/api/v1/admin/workers/tasks/{task_id}/reconcile"
    response = client.post(
        endpoint, json={"acknowledgement": signed.model_dump(mode="json")},
        headers=admin_headers,
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "delivered"
    assert response.json()["execution_enabled"] is False

    duplicate = client.post(
        endpoint, json={"acknowledgement": signed.model_dump(mode="json")},
        headers=admin_headers,
    )
    assert duplicate.status_code == 409

    db = TestingSession()
    try:
        attempt = db.query(WorkerDispatchAttempt).filter_by(task_id=str(task_id)).one()
        assert attempt.status == "delivered"
        assert db.query(AuditEvent).filter_by(
            action="worker_task.reconciled", resource_id=str(task_id)
        ).count() == 1
    finally:
        db.close()



def test_worker_observations_are_visible_only_to_owning_project_user():
    from datetime import datetime, timedelta, timezone
    from uuid import uuid4
    from app.db.models import (
        Authorization, Project, ScanJob, ScopeSnapshot, Target, User,
        WorkerObservationRecord, WorkerTaskReceipt,
    )

    owner_headers = register_and_auth("evidence-owner@example.org")
    other_headers = register_and_auth("evidence-other@example.org")
    db = TestingSession()
    try:
        owner = db.query(User).filter_by(email="evidence-owner@example.org").one()
        project = Project(owner_id=owner.id, name="Evidence Project", description="")
        db.add(project)
        db.flush()
        target = Target(project_id=project.id, value="https://example.test", target_type="url")
        authorization = Authorization(
            project_id=project.id, reference="https://example.test/program",
            status="approved", scope_rules='["example.test"]',
        )
        db.add_all([target, authorization])
        db.flush()
        snapshot = ScopeSnapshot(
            project_id=project.id, target_id=target.id,
            authorization_id=authorization.id, created_by=owner.id,
            snapshot_json="{}", sha256="a" * 64, status="active",
        )
        db.add(snapshot)
        db.flush()
        job = ScanJob(
            project_id=project.id, target_id=target.id,
            scope_snapshot_id=snapshot.id, created_by=owner.id,
            profile="passive_recon", status="queued", execution_enabled=False,
        )
        db.add(job)
        db.flush()
        task_id = str(uuid4())
        now = datetime.now(timezone.utc)
        receipt = WorkerTaskReceipt(
            task_id=task_id, job_id=job.id, envelope_sha256="b" * 64,
            worker_id="recon-worker-01", key_id="key-v1",
            expires_at=now + timedelta(minutes=2), consumed_at=now,
            created_at=now - timedelta(seconds=5),
        )
        db.add(receipt)
        db.flush()
        db.add(WorkerObservationRecord(
            observation_id=str(uuid4()), task_id=task_id,
            worker_id="recon-worker-01", key_id="key-v1",
            envelope_sha256="b" * 64, batch_sha256="c" * 64,
            kind="hostname", value="api.example.test",
            evidence="passive source evidence", source="passive_dns",
            observed_at=now, collected_at=now, received_at=now,
            classification="unconfirmed_observation",
        ))
        db.commit()
        job_id = job.id
    finally:
        db.close()

    visible = client.get(f"/api/v1/scan-jobs/{job_id}/observations", headers=owner_headers)
    assert visible.status_code == 200
    payload = visible.json()
    assert payload["total"] == 1
    assert payload["items"][0]["value"] == "api.example.test"
    assert payload["items"][0]["classification"] == "unconfirmed_observation"

    hidden = client.get(f"/api/v1/scan-jobs/{job_id}/observations", headers=other_headers)
    assert hidden.status_code == 404


def test_analysis_evaluation_api_is_owner_scoped_and_human_only():
    from app.db.models import AIAnalysisRun, Project

    owner_headers = register_and_auth("evaluation-owner@example.org")
    other_headers = register_and_auth("evaluation-other@example.org")
    project_response = client.post(
        "/api/v1/projects", json={"name": "Evaluation project"}, headers=owner_headers
    )
    project_id = project_response.json()["id"]
    db = TestingSession()
    try:
        owner = db.query(Project).filter_by(id=project_id).one()
        run = AIAnalysisRun(
            project_id=project_id, created_by=owner.owner_id,
            context_sha256="a" * 64, correlations_sha256="b" * 64,
            provider="deepseek", model="test-model", status="completed",
            disposition="requires_independent_validation", result_json="{}",
            execution_enabled=False,
        )
        db.add(run)
        db.commit()
        run_id = run.id
    finally:
        db.close()

    denied = client.post(
        f"/api/v1/analysis-runs/{run_id}/evaluations",
        json={"outcome": "confirmed", "evidence_sha256": "c" * 64,
              "validation_method": "manual_reproduction"},
        headers=other_headers,
    )
    assert denied.status_code == 404

    invalid = client.post(
        f"/api/v1/analysis-runs/{run_id}/evaluations",
        json={"outcome": "confirmed", "validation_method": "manual_reproduction"},
        headers=owner_headers,
    )
    assert invalid.status_code == 422

    created = client.post(
        f"/api/v1/analysis-runs/{run_id}/evaluations",
        json={"outcome": "confirmed", "evidence_sha256": "c" * 64,
              "validation_method": "manual_reproduction", "notes": "Verified independently"},
        headers=owner_headers,
    )
    assert created.status_code == 201
    assert created.json()["outcome"] == "confirmed"
    repeated = client.post(
        f"/api/v1/analysis-runs/{run_id}/evaluations",
        json={"outcome": "inconclusive", "validation_method": "second_review"},
        headers=owner_headers,
    )
    assert repeated.status_code == 409

    metrics = client.get(
        f"/api/v1/projects/{project_id}/analysis-evaluation-metrics", headers=owner_headers
    )
    assert metrics.status_code == 200
    assert metrics.json()["confirmed"] == 1
    assert metrics.json()["resolved_precision"] == 1.0
    assert client.get(
        f"/api/v1/projects/{project_id}/analysis-evaluation-metrics", headers=other_headers
    ).status_code == 404


def test_human_finding_decisions_are_owner_scoped_and_append_only():
    from app.db.models import AIAnalysisRun, FindingCandidateRecord, HumanFindingDecision, Project

    owner_headers = register_and_auth("finding-decision-owner@example.org")
    other_headers = register_and_auth("finding-decision-other@example.org")
    project_data = client.post(
        "/api/v1/projects", json={"name": "Finding Decision Project"}, headers=owner_headers
    ).json()
    db = TestingSession()
    try:
        project = db.query(Project).filter_by(id=project_data["id"]).one()
        run = AIAnalysisRun(
            project_id=project.id, created_by=project.owner_id,
            context_sha256="1" * 64, correlations_sha256="2" * 64,
            provider="deepseek", model="test-model", status="completed",
            disposition="requires_independent_validation", result_json="{}",
            execution_enabled=False,
        )
        db.add(run)
        db.flush()
        db.add(FindingCandidateRecord(
            analysis_run_id=run.id, project_id=project.id, created_by=project.owner_id,
            candidate_fingerprint="a" * 64, qualification="human_review_candidate",
            finding_status="unconfirmed", evidence_bundle_sha256="c" * 64,
            evidence_bundle_json="{}", qualification_json="{}", execution_enabled=False,
        ))
        db.commit()
        run_id = run.id
    finally:
        db.close()

    fingerprint = "a" * 64
    endpoint = f"/api/v1/analysis-runs/{run_id}/finding-decisions"
    payload = {
        "candidate_fingerprint": fingerprint,
        "outcome": "confirmed",
        "evidence_sha256": "b" * 64,
        "validation_method": "manual_reproduction",
        "notes": "Independently reproduced with authorized test accounts",
        "reviewer_attested": True,
    }
    assert client.post(endpoint, json=payload, headers=other_headers).status_code == 404
    missing_attestation = dict(payload)
    missing_attestation.pop("reviewer_attested")
    assert client.post(endpoint, json=missing_attestation, headers=owner_headers).status_code == 422

    arbitrary_payload = dict(payload)
    arbitrary_payload["candidate_fingerprint"] = "d" * 64
    assert client.post(endpoint, json=arbitrary_payload, headers=owner_headers).status_code == 404

    created = client.post(endpoint, json=payload, headers=owner_headers)
    assert created.status_code == 201, created.text
    assert created.json()["evaluator_id"] > 0
    assert created.json()["reviewer_attested"] is True
    assert client.post(endpoint, json=payload, headers=owner_headers).status_code == 409

    listed = client.get(
        endpoint, params={"candidate_fingerprint": fingerprint}, headers=owner_headers
    )
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    assert listed.json()[0]["outcome"] == "confirmed"

    audit = client.get("/api/v1/audit", headers=owner_headers)
    assert audit.status_code == 200
    assert any(
        item["action"] == "human_finding_decision.recorded"
        for item in audit.json()
    )



def test_finding_candidate_persistence_binds_run_context_and_exact_evidence_bundle():
    import pytest
    from datetime import datetime, timezone
    from uuid import uuid4
    from app.db.models import AIAnalysisRun, Project, User, FindingCandidateRecord
    from app.core.finding_candidates import persist_finding_candidate
    from app.schemas.finding_candidates import FindingCandidateCreate
    from app.schemas.finding_qualification import FindingQualification
    from app.schemas.validation_evidence import ValidationEvidenceBundle, ValidationEvidenceItem

    headers = register_and_auth("candidate-persistence-owner@example.org")
    project_data = client.post(
        "/api/v1/projects", json={"name": "Candidate Persistence"}, headers=headers
    ).json()
    context_digest = "e" * 64
    db = TestingSession()
    try:
        project = db.query(Project).filter_by(id=project_data["id"]).one()
        actor = db.query(User).filter_by(id=project.owner_id).one()
        run = AIAnalysisRun(
            project_id=project.id, created_by=actor.id, context_sha256=context_digest,
            correlations_sha256="f" * 64, provider="deepseek", model="test",
            status="completed", disposition="requires_independent_validation",
            result_json="{}", execution_enabled=False,
        )
        db.add(run)
        db.flush()
        now = datetime.now(timezone.utc)
        observation_id = uuid4()
        items = [
            ValidationEvidenceItem(
                evidence_id=uuid4(), evidence_type=kind, relationship="supports",
                statement="Evidence statement recorded for human review",
                source_label="review_record", observation_ids=ids,
                recorded_at=now, human_attested=True,
            )
            for kind, ids in [
                ("program_policy", []),
                ("expected_behavior", [observation_id]),
                ("observed_behavior", [observation_id]),
                ("impact_context", [observation_id]),
            ]
        ]
        bundle = ValidationEvidenceBundle(
            strategy_id="object_access_review", analysis_context_sha256=context_digest,
            items=items, reviewed_at=now,
        )
        qualification = FindingQualification(
            candidate_fingerprint="9" * 64, category="object_authorization",
            title="Possible cross-account invoice access", qualification="human_review_candidate",
            evidence_quality="documented_consistent",
            impact_quality="documented_not_independently_verified",
            blockers=[], evidence_ids=[str(item.evidence_id) for item in items],
            observation_ids=[str(observation_id)],
        )
        payload = FindingCandidateCreate(qualification=qualification, evidence_bundle=bundle)
        record = persist_finding_candidate(
            db, analysis_run_id=run.id, actor=actor, payload=payload
        )
        db.commit()
        assert record.evidence_bundle_sha256
        assert record.finding_status == "unconfirmed"
        assert record.execution_enabled is False
        stored = db.query(FindingCandidateRecord).filter_by(id=record.id).one()
        assert stored.evidence_bundle_json
        assert stored.qualification_json
        with pytest.raises(ValueError, match="different evidence"):
            changed = bundle.model_copy(update={"reviewer_note": "changed evidence context"})
            persist_finding_candidate(
                db, analysis_run_id=run.id, actor=actor,
                payload=FindingCandidateCreate(qualification=qualification, evidence_bundle=changed),
            )
    finally:
        db.close()


def test_persisted_candidate_similarity_is_project_scoped_and_non_destructive():
    from app.db.models import AIAnalysisRun, FindingCandidateRecord, Project, User

    headers = register_and_auth("similarity-owner@example.org")
    project_data = client.post(
        "/api/v1/projects", json={"name": "Similarity Project"}, headers=headers
    ).json()
    db = TestingSession()
    try:
        project = db.query(Project).filter_by(id=project_data["id"]).one()
        actor = db.query(User).filter_by(id=project.owner_id).one()
        run = AIAnalysisRun(
            project_id=project.id, created_by=actor.id, context_sha256="a" * 64,
            correlations_sha256="b" * 64, provider="deepseek", model="test",
            status="completed", disposition="requires_independent_validation",
            result_json="{}", execution_enabled=False,
        )
        db.add(run)
        db.flush()
        first = FindingCandidateRecord(
            analysis_run_id=run.id, project_id=project.id, created_by=actor.id,
            candidate_fingerprint="1" * 64, qualification="human_review_candidate",
            finding_status="unconfirmed", evidence_bundle_sha256="c" * 64,
            evidence_bundle_json="{}", qualification_json=json.dumps({
                "category": "object_authorization",
                "title": "User can access another account invoice",
                "observation_ids": ["obs-1", "obs-2"],
            }), execution_enabled=False,
        )
        second = FindingCandidateRecord(
            analysis_run_id=run.id, project_id=project.id, created_by=actor.id,
            candidate_fingerprint="2" * 64, qualification="human_review_candidate",
            finding_status="unconfirmed", evidence_bundle_sha256="d" * 64,
            evidence_bundle_json="{}", qualification_json=json.dumps({
                "category": "object_authorization",
                "title": "User can access another account invoice record",
                "observation_ids": ["obs-9"],
            }), execution_enabled=False,
        )
        db.add_all([first, second])
        db.commit()
        project_id, candidate_id = project.id, first.id
    finally:
        db.close()

    response = client.get(
        f"/api/v1/projects/{project_id}/finding-candidates/{candidate_id}/similarity",
        headers=headers,
    )
    # This legacy fixture intentionally stores malformed, digest-unbound records.
    # Similarity must fail closed instead of trusting the unvalidated JSON.
    assert response.status_code == 409
    denied = client.get(
        f"/api/v1/projects/{project_id + 999}/finding-candidates/{candidate_id}/similarity",
        headers=headers,
    )
    assert denied.status_code == 404


def test_revoked_browser_session_cannot_be_reused_and_logout_all_revokes_sessions():
    from app.core.config import get_settings

    client.cookies.clear()
    payload = {"email": "revocable-session@example.org", "password": "a-strong-test-password-123"}
    assert client.post("/api/v1/auth/register", json=payload).status_code == 201
    settings = get_settings()

    first = client.post("/api/v1/auth/login", json=payload)
    assert first.status_code == 200
    first_cookie = first.cookies.get(settings.session_cookie_name)
    first_csrf = first.json()["csrf_token"]
    assert client.get("/api/v1/auth/me").status_code == 200
    logout = client.post("/api/v1/auth/logout", headers={
        "Origin": settings.allowed_origin_list[0],
        settings.csrf_header_name: first_csrf,
    })
    assert logout.status_code == 204
    client.cookies.set(settings.session_cookie_name, first_cookie)
    assert client.get("/api/v1/auth/me").status_code == 401
    client.cookies.clear()

    second = client.post("/api/v1/auth/login", json=payload)
    assert second.status_code == 200
    second_cookie = second.cookies.get(settings.session_cookie_name)
    second_csrf = second.json()["csrf_token"]
    assert client.get("/api/v1/auth/me").status_code == 200
    revoke_all = client.post("/api/v1/auth/logout-all", headers={
        "Origin": settings.allowed_origin_list[0],
        settings.csrf_header_name: second_csrf,
    })
    assert revoke_all.status_code == 204
    client.cookies.set(settings.session_cookie_name, second_cookie)
    assert client.get("/api/v1/auth/me").status_code == 401
    client.cookies.clear()


def test_cookie_session_requires_csrf_for_state_changes_and_supports_logout():
    from app.core.config import get_settings

    client.cookies.clear()
    payload = {"email": "cookie-session@example.org", "password": "a-strong-test-password-123"}
    assert client.post("/api/v1/auth/register", json=payload).status_code == 201
    login = client.post("/api/v1/auth/login", json=payload)
    assert login.status_code == 200
    assert "access_token" not in login.json()
    assert "csrf_token" in login.json()
    settings = get_settings()
    session_cookie = login.cookies.get(settings.session_cookie_name)
    csrf_cookie = login.cookies.get(settings.csrf_cookie_name)
    assert session_cookie
    assert csrf_cookie
    assert settings.session_cookie_name in login.headers.get("set-cookie", "")
    csrf_bootstrap = client.get("/api/v1/auth/csrf")
    assert csrf_bootstrap.status_code == 200
    assert csrf_bootstrap.headers["cache-control"] == "no-store"
    assert csrf_bootstrap.json()["csrf_token"] == csrf_cookie
    assert client.get("/api/v1/auth/me").status_code == 200

    denied = client.post("/api/v1/projects", json={"name": "Cookie Project"})
    assert denied.status_code == 403
    assert denied.json()["detail"] == "CSRF validation failed"

    created = client.post(
        "/api/v1/projects",
        json={"name": "Cookie Project"},
        headers={
            "Origin": settings.allowed_origin_list[0],
            settings.csrf_header_name: csrf_cookie,
        },
    )
    assert created.status_code == 201

    rejected_origin = client.post(
        "/api/v1/projects",
        json={"name": "Bad Origin"},
        headers={
            "Origin": "https://attacker.invalid",
            settings.csrf_header_name: csrf_cookie,
        },
    )
    assert rejected_origin.status_code == 403

    logout = client.post(
        "/api/v1/auth/logout",
        headers={
            "Origin": settings.allowed_origin_list[0],
            settings.csrf_header_name: csrf_cookie,
        },
    )
    assert logout.status_code == 204
    assert client.get("/api/v1/auth/me").status_code == 401
    client.cookies.clear()
