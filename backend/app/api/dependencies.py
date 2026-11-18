import secrets
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import decode_access_token_claims, token_id_digest
from app.db.database import get_db
from app.db.models import User, UserSession

bearer = HTTPBearer(auto_error=False)
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    settings = get_settings()
    cookie_token = request.cookies.get(settings.session_cookie_name)
    # Explicit bearer credentials take precedence for API clients and legacy integrations.
    token = credentials.credentials if credentials is not None else cookie_token
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if credentials is None and cookie_token:
        if request.method.upper() in UNSAFE_METHODS:
            origin = request.headers.get("origin")
            allowed_origins = set(settings.allowed_origin_list)
            csrf_cookie = request.cookies.get(settings.csrf_cookie_name)
            csrf_header = request.headers.get(settings.csrf_header_name)
            if (
                not origin
                or origin not in allowed_origins
                or not csrf_cookie
                or not csrf_header
                or not secrets.compare_digest(csrf_cookie, csrf_header)
            ):
                raise HTTPException(status_code=403, detail="CSRF validation failed")

    claims = decode_access_token_claims(token)
    subject = claims.get("sub") if claims else None
    if not isinstance(subject, str) or not subject.isdigit():
        raise HTTPException(status_code=401, detail="Invalid or expired access token", headers={"WWW-Authenticate": "Bearer"})
    token_id = claims.get("jti")
    if token_id is not None:
        if claims.get("token_use") != "browser_session" or not isinstance(token_id, str):
            raise HTTPException(status_code=401, detail="Invalid session token")
        session = db.query(UserSession).filter(
            UserSession.token_id_sha256 == token_id_digest(token_id),
            UserSession.user_id == int(subject),
            UserSession.revoked_at.is_(None),
            UserSession.expires_at > datetime.now(timezone.utc),
        ).first()
        if session is None:
            raise HTTPException(status_code=401, detail="Session expired or revoked")
    user = db.get(User, int(subject))
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="User is unavailable")
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Administrator role required")
    return user
