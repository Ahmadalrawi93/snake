import io
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.core.worker_protocol import WorkerTaskEnvelope
from worker_entrypoint import main


def _envelope():
    now = datetime.now(timezone.utc)
    return {
        "task_id": str(uuid4()),
        "job_id": 1,
        "scope_snapshot_id": 2,
        "scope_snapshot_sha256": "a" * 64,
        "profile": "passive_recon",
        "target_url": "https://example.com/",
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=2)).isoformat(),
        "execution_enabled": False,
    }


def test_worker_entrypoint_only_acknowledges_validation(monkeypatch, capsys):
    raw = json.dumps(_envelope()).encode()
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(raw)))
    assert main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["accepted"] is True
    assert result["execution_enabled"] is False
    assert result["mode"] == "validation_only"


def test_worker_envelope_rejects_command_fields():
    payload = _envelope()
    payload["command"] = "id"
    try:
        WorkerTaskEnvelope.model_validate(payload)
    except Exception:
        pass
    else:
        raise AssertionError("unexpected command field was accepted")
