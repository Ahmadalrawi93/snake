import os
import sqlite3
import stat

import pytest

from export_worker_ack import read_acknowledgement


def create_ledger(path, task_id="123e4567-e89b-12d3-a456-426614174000", ack=b'{"signed":"ack"}'):
    with sqlite3.connect(path) as db:
        db.execute("""
            CREATE TABLE worker_task_ledger (
                task_id TEXT PRIMARY KEY,
                envelope_sha256 TEXT NOT NULL,
                worker_id TEXT NOT NULL,
                key_id TEXT NOT NULL,
                acknowledgement BLOB NOT NULL,
                accepted_at TEXT NOT NULL
            )
        """)
        db.execute(
            "INSERT INTO worker_task_ledger VALUES (?, ?, ?, ?, ?, ?)",
            (task_id, "a" * 64, "worker-1", "key-1", ack, "2026-11-17T00:00:00Z"),
        )
    path.chmod(0o600)


def test_export_returns_exact_persisted_ack_without_mutation(tmp_path):
    path = tmp_path / "ledger.sqlite3"
    create_ledger(path)
    before = path.read_bytes()
    assert read_acknowledgement(
        path, "123e4567-e89b-12d3-a456-426614174000"
    ) == b'{"signed":"ack"}'
    assert path.read_bytes() == before


def test_export_rejects_unknown_or_malformed_task(tmp_path):
    path = tmp_path / "ledger.sqlite3"
    create_ledger(path)
    with pytest.raises(ValueError, match="not_found"):
        read_acknowledgement(path, "123e4567-e89b-12d3-a456-426614174001")
    with pytest.raises(ValueError, match="invalid_task_id"):
        read_acknowledgement(path, "not-a-uuid")


def test_export_rejects_insecure_permissions(tmp_path):
    path = tmp_path / "ledger.sqlite3"
    create_ledger(path)
    path.chmod(0o644)
    with pytest.raises(ValueError, match="permissions_must_be_private"):
        read_acknowledgement(path, "123e4567-e89b-12d3-a456-426614174000")


def test_export_rejects_symlink(tmp_path):
    real = tmp_path / "real.sqlite3"
    create_ledger(real)
    link = tmp_path / "link.sqlite3"
    link.symlink_to(real)
    with pytest.raises(ValueError, match="must_not_be_a_symlink"):
        read_acknowledgement(link, "123e4567-e89b-12d3-a456-426614174000")
