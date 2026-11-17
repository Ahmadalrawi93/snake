"""SQLite-backed passive asset history and snapshot-to-snapshot change detection."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_HISTORY_RECORDS = 100_000


def _canonical_record(record: dict[str, Any]) -> tuple[str, str]:
    required = {"hostname", "kind", "value", "source", "observed_at"}
    if not isinstance(record, dict) or not required.issubset(record):
        raise ValueError("feed record is missing required history fields")
    host = record["hostname"]
    kind = record["kind"]
    value = record["value"]
    source = record["source"]
    if not all(isinstance(x, str) and x and len(x) <= 4096 for x in (host, kind, value, source)):
        raise ValueError("feed record contains invalid history fields")
    identity = json.dumps([host, kind, value, source], separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return digest, identity


def update_history(
    db_path: str | os.PathLike[str],
    records: list[dict[str, Any]],
    *,
    collected_at: datetime | None = None,
) -> list[dict[str, str]]:
    """Commit one successful feed snapshot and return new/changed/missing events.

    A missing event is emitted only after a complete, successfully collected
    snapshot. This function must never be called for a partial/failed provider run.
    """
    if not isinstance(records, list) or len(records) > 500:
        raise ValueError("history snapshot must contain at most 500 records")
    now = collected_at or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("collection timestamp must be timezone-aware")
    stamp = now.astimezone(timezone.utc).isoformat()
    normalized: dict[str, tuple[str, str, str, str]] = {}
    for record in records:
        digest, identity = _canonical_record(record)
        normalized[digest] = (identity, record["hostname"], record["kind"], record["source"])

    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("history database path must not be a symlink")
    fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    os.close(fd)
    os.chmod(path, 0o600)
    connection = sqlite3.connect(path, timeout=10, isolation_level=None)
    events: list[dict[str, str]] = []
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("""CREATE TABLE IF NOT EXISTS asset_history (
            record_hash TEXT PRIMARY KEY,
            identity_json TEXT NOT NULL,
            hostname TEXT NOT NULL,
            kind TEXT NOT NULL,
            source TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            active INTEGER NOT NULL CHECK(active IN (0,1))
        )""")
        connection.execute("""CREATE TABLE IF NOT EXISTS asset_change_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            record_hash TEXT NOT NULL,
            event_type TEXT NOT NULL CHECK(event_type IN ('new','returned','missing')),
            hostname TEXT NOT NULL,
            kind TEXT NOT NULL,
            source TEXT NOT NULL,
            occurred_at TEXT NOT NULL
        )""")
        connection.execute("BEGIN IMMEDIATE")
        count = connection.execute("SELECT COUNT(*) FROM asset_history").fetchone()[0]
        if count > MAX_HISTORY_RECORDS:
            raise ValueError("asset history exceeds configured record limit")
        existing = {
            row[0]: row[1:]
            for row in connection.execute(
                "SELECT record_hash, identity_json, hostname, kind, source, active FROM asset_history"
            )
        }
        for digest, (identity, host, kind, source) in normalized.items():
            prior = existing.get(digest)
            if prior is None:
                event = "new"
                connection.execute(
                    "INSERT INTO asset_history VALUES (?,?,?,?,?,?,?,1)",
                    (digest, identity, host, kind, source, stamp, stamp),
                )
            else:
                event = "returned" if prior[4] == 0 else None
                connection.execute(
                    "UPDATE asset_history SET identity_json=?, hostname=?, kind=?, source=?, last_seen=?, active=1 WHERE record_hash=?",
                    (identity, host, kind, source, stamp, digest),
                )
            if event:
                connection.execute(
                    "INSERT INTO asset_change_events(record_hash,event_type,hostname,kind,source,occurred_at) VALUES (?,?,?,?,?,?)",
                    (digest, event, host, kind, source, stamp),
                )
                events.append({"event": event, "hostname": host, "kind": kind, "source": source, "record_hash": digest})
        for digest, prior in existing.items():
            if digest not in normalized and prior[4] == 1:
                _, host, kind, source = prior[:4]
                connection.execute(
                    "UPDATE asset_history SET active=0 WHERE record_hash=?", (digest,)
                )
                connection.execute(
                    "INSERT INTO asset_change_events(record_hash,event_type,hostname,kind,source,occurred_at) VALUES (?,?,?,?,?,?)",
                    (digest, "missing", host, kind, source, stamp),
                )
                events.append({"event": "missing", "hostname": host, "kind": kind, "source": source, "record_hash": digest})
        connection.commit()
        return events
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
