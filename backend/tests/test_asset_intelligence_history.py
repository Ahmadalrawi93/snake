from datetime import datetime, timezone
import os
import sqlite3

import pytest

from asset_intelligence_history import update_history


def rec(host="api.example.org", value="A 192.0.2.1", source="dnsdb"):
    return {"hostname": host, "kind": "dns_record", "value": value,
            "source": source, "observed_at": "2026-11-17T00:00:00+00:00"}


def test_first_snapshot_marks_new_and_second_marks_unchanged(tmp_path):
    db = tmp_path / "history.sqlite"
    first = update_history(db, [rec()])
    second = update_history(db, [rec()], collected_at=datetime(2026, 11, 17, 1, tzinfo=timezone.utc))
    assert [event["event"] for event in first] == ["new"]
    assert second == []
    assert db.stat().st_mode & 0o777 == 0o600


def test_missing_only_after_successful_snapshot_and_returned_on_reappearance(tmp_path):
    db = tmp_path / "history.sqlite"
    update_history(db, [rec()])
    missing = update_history(db, [])
    returned = update_history(db, [rec()])
    assert [event["event"] for event in missing] == ["missing"]
    assert [event["event"] for event in returned] == ["returned"]


def test_changed_value_is_new_record_and_old_value_becomes_missing(tmp_path):
    db = tmp_path / "history.sqlite"
    update_history(db, [rec(value="A 192.0.2.1")])
    changes = update_history(db, [rec(value="A 192.0.2.2")])
    assert {event["event"] for event in changes} == {"new", "missing"}


def test_invalid_snapshot_does_not_modify_history(tmp_path):
    db = tmp_path / "history.sqlite"
    update_history(db, [rec()])
    with pytest.raises(ValueError):
        update_history(db, [{"hostname": "bad"}])
    connection = sqlite3.connect(db)
    assert connection.execute("SELECT COUNT(*) FROM asset_change_events").fetchone()[0] == 1
    connection.close()


def test_rejects_symlink_database(tmp_path):
    target = tmp_path / "real.sqlite"
    link = tmp_path / "link.sqlite"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        update_history(link, [rec()])
