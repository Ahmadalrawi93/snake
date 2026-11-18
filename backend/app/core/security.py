from datetime import datetime, timedelta, timezone
import hashlib
import secrets
import jwt
from pwdlib import PasswordHash
from app.core.config import get_settings

_password_hash = PasswordHash.recommended()
ALGORITHM = "HS256"

def hash_password(password: str) -> str:
    return _password_hash.hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    return _password_hash.verify(password, password_hash)

def create_access_token(subject: str) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {"sub": subject, "iat": now, "exp": now + timedelta(minutes=settings.access_token_minutes)}
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=ALGORITHM)

def decode_access_token(token: str) -> str | None:
    try:
        payload = jwt.decode(token, get_settings().jwt_secret_key, algorithms=[ALGORITHM])
        subject = payload.get("sub")
        return subject if isinstance(subject, str) else None
    except jwt.PyJWTError:
        return None


def create_browser_session_token(subject: str) -> tuple[str, str, datetime]:
    """Create a JWT with a unique jti for server-side revocation."""
    settings = get_settings()
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=settings.access_token_minutes)
    token_id = secrets.token_urlsafe(32)
    payload = {
        "sub": subject,
        "iat": now,
        "exp": expires_at,
        "jti": token_id,
        "token_use": "browser_session",
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=ALGORITHM), token_id, expires_at


def decode_access_token_claims(token: str) -> dict | None:
    try:
        payload = jwt.decode(token, get_settings().jwt_secret_key, algorithms=[ALGORITHM])
        if not isinstance(payload, dict):
            return None
        return payload
    except jwt.PyJWTError:
        return None


def token_id_digest(token_id: str) -> str:
    return hashlib.sha256(token_id.encode("utf-8")).hexdigest()


def create_api_access_token(subject: str) -> tuple[str, str, datetime]:
    """Create a revocable bearer token for non-browser API clients."""
    settings = get_settings()
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=settings.access_token_minutes)
    token_id = secrets.token_urlsafe(32)
    payload = {
        "sub": subject,
        "iat": now,
        "exp": expires_at,
        "jti": token_id,
        "token_use": "api_access",
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=ALGORITHM), token_id, expires_at
