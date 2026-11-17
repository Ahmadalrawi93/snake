"""Create the legacy core schema expected by the incremental Alembic chain in CI."""
import os
import sqlite3
from pathlib import Path

url = os.environ.get("SNAKE_DATABASE_URL", "")
prefix = "sqlite:///"
if not url.startswith(prefix) or url.endswith(":memory:"):
    raise SystemExit("migration CI bootstrap requires a file-backed SQLite SNAKE_DATABASE_URL")

raw_path = url[len(prefix):].split("?", 1)[0]
db_path = Path(raw_path)
if not db_path.is_absolute():
    db_path = Path.cwd() / db_path
db_path.parent.mkdir(parents=True, exist_ok=True)

schema = """
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY,
    name VARCHAR(120) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS authorizations (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL,
    reference VARCHAR(500) NOT NULL,
    starts_at VARCHAR(40),
    expires_at VARCHAR(40),
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    notes TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL,
    FOREIGN KEY(project_id) REFERENCES projects(id)
);
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL,
    value VARCHAR(2048) NOT NULL,
    target_type VARCHAR(30) NOT NULL DEFAULT 'url',
    status VARCHAR(20) NOT NULL DEFAULT 'registered',
    created_at DATETIME NOT NULL,
    FOREIGN KEY(project_id) REFERENCES projects(id)
);
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id VARCHAR(80) NOT NULL,
    details TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL
);
"""
with sqlite3.connect(db_path) as connection:
    connection.executescript(schema)
