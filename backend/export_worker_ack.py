"""Export an already-persisted signed acknowledgement for manual backend reconciliation.

This utility is read-only: it never contacts the backend, changes the ledger,
re-signs acknowledgements, or executes tasks. Pipe stdout directly to a secure
operator-controlled transfer mechanism.
"""
from __future__ import annotations

import argparse
import os
import re
import sqlite3
import stat
import sys
from pathlib import Path
from uuid import UUID


def read_acknowledgement(database: str | Path, task_id: str) -> bytes:
    try:
        canonical_task_id = str(UUID(task_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("invalid_task_id") from exc
    path = Path(database)
    if path.is_symlink():
        raise ValueError("ledger_path_must_not_be_a_symlink")
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("ledger_path_must_be_a_regular_file")
    if metadata.st_mode & 0o077:
        raise ValueError("ledger_permissions_must_be_private")
    uri = path.resolve().as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=5.0)
    try:
        connection.execute("PRAGMA query_only = ON")
        row = connection.execute(
            "SELECT acknowledgement FROM worker_task_ledger WHERE task_id = ?",
            (canonical_task_id,),
        ).fetchone()
    except sqlite3.Error as exc:
        raise ValueError("ledger_read_failed") from exc
    finally:
        connection.close()
    if row is None:
        raise ValueError("task_acknowledgement_not_found")
    acknowledgement = row[0]
    if not isinstance(acknowledgement, bytes) or not acknowledgement:
        raise ValueError("stored_acknowledgement_is_invalid")
    return acknowledgement


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", default=os.environ.get("SNAKE_WORKER_REPLAY_DB_PATH"))
    parser.add_argument("--task-id", required=True)
    args = parser.parse_args(argv)
    if not args.database:
        parser.error("--database or SNAKE_WORKER_REPLAY_DB_PATH is required")
    try:
        payload = read_acknowledgement(args.database, args.task_id)
        sys.stdout.buffer.write(payload)
        sys.stdout.buffer.flush()
        return 0
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
