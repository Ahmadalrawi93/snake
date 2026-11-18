import secrets

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.api.dependencies import get_current_user
from app.core.config import get_settings
from app.core.security import (hash_password, verify_password, create_browser_session_token, create_api_access_token, token_id_digest, decode_access_token_claims)
from app.db.database import get_db
from app.db.models import User, UserSession, ApiAccessToken

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)

class UserResponse(BaseModel):
    id: int
    email: EmailStr
    role: str

class SessionResponse(BaseModel):
    csrf_token: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

@router.post("/register", response_model=UserResponse, status_code=201)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    email = str(payload.email).lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status_code=409, detail="Email already registered")
    user = User(email=email, password_hash=hash_password(payload.password), role="user", is_active=True)
    db.add(user)
    db.commit()
    db.refresh(user)
    return UserResponse(id=user.id, email=user.email, role=user.role)

@router.post("/login", response_model=SessionResponse)
def login(payload: LoginRequest, response: Response, db: Session = Depends(get_db)):
    email = str(payload.email).lower()
    user = db.scalar(select(User).where(User.email == email))
    if user is None or not user.is_active or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect email or password",
                            headers={"WWW-Authenticate": "Bearer"})
    settings = get_settings()
    access_token, token_id, expires_at = create_browser_session_token(str(user.id))
    csrf_token = secrets.token_urlsafe(32)
    db.add(UserSession(user_id=user.id, token_id_sha256=token_id_digest(token_id), expires_at=expires_at))
    db.commit()
    cookie_options = {
        "httponly": True,
        "secure": settings.session_cookie_secure,
        "samesite": settings.session_cookie_samesite.lower(),
        "path": "/",
        "max_age": settings.access_token_minutes * 60,
    }
    response.set_cookie(settings.session_cookie_name, access_token, **cookie_options)
    response.set_cookie(
        settings.csrf_cookie_name,
        csrf_token,
        httponly=False,
        secure=settings.session_cookie_secure,
        samesite=settings.session_cookie_samesite.lower(),
        path="/",
        max_age=settings.access_token_minutes * 60,
    )
    return SessionResponse(csrf_token=csrf_token)

@router.post("/token", response_model=TokenResponse)
def issue_api_token(payload: LoginRequest, db: Session = Depends(get_db)):
    """Issue a bearer token for non-browser API clients; browser login uses HttpOnly cookies."""
    email = str(payload.email).lower()
    user = db.scalar(select(User).where(User.email == email))
    if user is None or not user.is_active or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect email or password",
                            headers={"WWW-Authenticate": "Bearer"})
    access_token, token_id, expires_at = create_api_access_token(str(user.id))
    db.add(ApiAccessToken(
        user_id=user.id,
        token_id_sha256=token_id_digest(token_id),
        expires_at=expires_at,
    ))
    db.commit()
    return TokenResponse(access_token=access_token)


@router.get("/csrf")
def csrf_token(request: Request, response: Response, user: User = Depends(get_current_user)):
    settings = get_settings()
    token = request.cookies.get(settings.csrf_cookie_name)
    if not token:
        raise HTTPException(status_code=401, detail="No active session")
    response.headers["Cache-Control"] = "no-store"
    return {"csrf_token": token}


def _clear_session_cookies(response: Response) -> None:
    settings = get_settings()
    for cookie_name in (settings.session_cookie_name, settings.csrf_cookie_name):
        response.delete_cookie(
            cookie_name,
            path="/",
            secure=settings.session_cookie_secure,
            httponly=(cookie_name == settings.session_cookie_name),
            samesite=settings.session_cookie_samesite.lower(),
        )


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response, user: User = Depends(get_current_user),
           db: Session = Depends(get_db)):
    settings = get_settings()
    token = request.cookies.get(settings.session_cookie_name)
    claims = decode_access_token_claims(token) if token else None
    token_id = claims.get("jti") if claims else None
    if isinstance(token_id, str):
        session = db.query(UserSession).filter(
            UserSession.user_id == user.id,
            UserSession.token_id_sha256 == token_id_digest(token_id),
            UserSession.revoked_at.is_(None),
        ).first()
        if session is not None:
            session.revoked_at = datetime.now(timezone.utc)
            db.commit()
    _clear_session_cookies(response)
    response.status_code = 204
    return response


@router.post("/logout-all", status_code=204)
def logout_all(response: Response, user: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    db.query(UserSession).filter(
        UserSession.user_id == user.id,
        UserSession.revoked_at.is_(None),
    ).update({UserSession.revoked_at: datetime.now(timezone.utc)}, synchronize_session=False)
    db.commit()
    _clear_session_cookies(response)
    response.status_code = 204
    return response

def _current_api_token(request: Request, user: User) -> str:
    authorization = request.headers.get("authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=400, detail="A bearer API token is required")
    claims = decode_access_token_claims(token)
    if not claims or claims.get("token_use") != "api_access" or claims.get("sub") != str(user.id):
        raise HTTPException(status_code=400, detail="Current credential is not an API access token")
    token_id = claims.get("jti")
    if not isinstance(token_id, str):
        raise HTTPException(status_code=400, detail="API token identifier is missing")
    return token_id


@router.post("/api-tokens/revoke", status_code=204)
def revoke_api_token(request: Request, user: User = Depends(get_current_user),
                     db: Session = Depends(get_db)):
    token_id = _current_api_token(request, user)
    record = db.query(ApiAccessToken).filter(
        ApiAccessToken.user_id == user.id,
        ApiAccessToken.token_id_sha256 == token_id_digest(token_id),
        ApiAccessToken.revoked_at.is_(None),
    ).first()
    if record is not None:
        record.revoked_at = datetime.now(timezone.utc)
        db.commit()
    return Response(status_code=204)


@router.post("/api-tokens/revoke-all", status_code=204)
def revoke_all_api_tokens(request: Request, user: User = Depends(get_current_user),
                          db: Session = Depends(get_db)):
    _current_api_token(request, user)
    db.query(ApiAccessToken).filter(
        ApiAccessToken.user_id == user.id,
        ApiAccessToken.revoked_at.is_(None),
    ).update({ApiAccessToken.revoked_at: datetime.now(timezone.utc)}, synchronize_session=False)
    db.commit()
    return Response(status_code=204)


@router.get("/me", response_model=UserResponse)
def me(user: User = Depends(get_current_user)):
    return UserResponse(id=user.id, email=user.email, role=user.role)
