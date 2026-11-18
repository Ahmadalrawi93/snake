"""Database-backed throttling for failed password authentication attempts."""

import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from math import ceil

from fastapi import HTTPException, status
from sqlalchemy import case, delete
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.models import AuthFailedAttemptBucket

MAX_FAILED_ATTEMPTS = 8
WINDOW = timedelta(minutes=15)
BLOCK_DURATION = timedelta(minutes=15)
RETENTION = timedelta(days=7)


def auth_attempt_key(email: str, client_host: str) -> str:
    """Return an HMAC digest; neither email nor client address is persisted."""
    secret = get_settings().jwt_secret_key.encode("utf-8")
    message = f"auth-failed:{email.strip().lower()}:{client_host}".encode("utf-8")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def assert_auth_not_blocked(db: Session, email: str, client_host: str) -> None:
    key = auth_attempt_key(email, client_host)
    record = db.get(AuthFailedAttemptBucket, key)
    if record is None or record.blocked_until is None:
        return
    retry_at = _utc(record.blocked_until)
    now = datetime.now(timezone.utc)
    if retry_at > now:
        retry_seconds = max(1, ceil((retry_at - now).total_seconds()))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed authentication attempts. Try again later.",
            headers={"Retry-After": str(retry_seconds)},
        )


def record_failed_auth_attempt(db: Session, email: str, client_host: str) -> None:
    now = datetime.now(timezone.utc)
    cutoff = now - WINDOW
    key = auth_attempt_key(email, client_host)
    dialect = db.get_bind().dialect.name
    if dialect == "sqlite":
        insert_statement = sqlite_insert(AuthFailedAttemptBucket)
    elif dialect == "postgresql":
        insert_statement = postgresql_insert(AuthFailedAttemptBucket)
    else:
        raise RuntimeError(f"Unsupported database dialect for atomic auth throttling: {dialect}")

    expired_window = AuthFailedAttemptBucket.window_started_at <= cutoff
    statement = insert_statement.values(
        key_sha256=key,
        window_started_at=now,
        attempts=1,
        blocked_until=None,
        updated_at=now,
    ).on_conflict_do_update(
        index_elements=[AuthFailedAttemptBucket.key_sha256],
        set_={
            "window_started_at": case(
                (expired_window, now),
                else_=AuthFailedAttemptBucket.window_started_at,
            ),
            "attempts": case(
                (expired_window, 1),
                else_=AuthFailedAttemptBucket.attempts + 1,
            ),
            "blocked_until": case(
                (expired_window, None),
                (AuthFailedAttemptBucket.attempts >= MAX_FAILED_ATTEMPTS - 1,
                 now + BLOCK_DURATION),
                else_=AuthFailedAttemptBucket.blocked_until,
            ),
            "updated_at": now,
        },
    )
    db.execute(statement)
    # Opportunistic bounded retention prevents unbounded growth of hashed identifiers.
    db.execute(delete(AuthFailedAttemptBucket).where(
        AuthFailedAttemptBucket.updated_at < now - RETENTION,
        AuthFailedAttemptBucket.key_sha256 != key,
    ))
    db.commit()


def clear_auth_failures(db: Session, email: str, client_host: str) -> None:
    db.execute(
        delete(AuthFailedAttemptBucket).where(
            AuthFailedAttemptBucket.key_sha256 == auth_attempt_key(email, client_host)
        )
    )
    db.commit()
