"""Durable, atomic worker-side replay ledger (SQLite, standard library only)."""
from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Callable


class ReplayConflict(ValueError):
    """A task ID was reused with different authenticated content or identity."""


class WorkerReplayLedger:
    def __init__(self, database_path: str | Path):
        self.database_path = str(database_path)
        if self.database_path != ":memory:":
            path = Path(self.database_path)
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if path.is_symlink():
                raise ValueError("worker_replay_database_must_not_be_a_symlink")
        with closing(self._connect()) as db:
            if self.database_path != ":memory:":
                db.execute("PRAGMA journal_mode = WAL")
            db.execute("""
                CREATE TABLE IF NOT EXISTS worker_task_ledger (
                    task_id TEXT PRIMARY KEY,
                    envelope_sha256 TEXT NOT NULL,
                    worker_id TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    acknowledgement BLOB NOT NULL,
                    accepted_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                )
            """)
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version > 1:
                raise ValueError("worker_replay_database_schema_is_newer_than_runtime")
            if version == 0:
                db.execute("PRAGMA user_version = 1")
        if self.database_path != ":memory:":
            Path(self.database_path).chmod(0o600)

    def _connect(self):
        db = sqlite3.connect(self.database_path, timeout=10.0, isolation_level=None)
        db.execute("PRAGMA busy_timeout = 10000")
        db.execute("PRAGMA trusted_schema = OFF")
        db.execute("PRAGMA synchronous = FULL")
        return db

    def get_or_create(
        self, *, task_id: str, envelope_sha256: str, worker_id: str, key_id: str,
        create_acknowledgement: Callable[[], bytes],
        validate_first_acceptance: Callable[[], None],
    ) -> tuple[bytes, bool]:
        """Return (ack bytes, was_duplicate); serialize competing deliveries."""
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT envelope_sha256, worker_id, key_id, acknowledgement "
                "FROM worker_task_ledger WHERE task_id = ?", (task_id,)
            ).fetchone()
            if row:
                old_digest, old_worker, old_key, acknowledgement = row
                if (old_digest, old_worker, old_key) != (
                    envelope_sha256, worker_id, key_id
                ):
                    raise ReplayConflict("task_id_reused_with_different_content_or_identity")
                db.commit()
                return bytes(acknowledgement), True

            validate_first_acceptance()
            acknowledgement = create_acknowledgement()
            if not isinstance(acknowledgement, bytes) or not acknowledgement:
                raise ValueError("acknowledgement_must_be_non_empty_bytes")
            db.execute(
                "INSERT INTO worker_task_ledger "
                "(task_id, envelope_sha256, worker_id, key_id, acknowledgement) "
                "VALUES (?, ?, ?, ?, ?)",
                (task_id, envelope_sha256, worker_id, key_id, acknowledgement),
            )
            db.commit()
            return acknowledgement, False
