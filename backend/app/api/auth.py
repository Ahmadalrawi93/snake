import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.api.dependencies import get_current_user
from app.core.config import get_settings
from app.core.security import hash_password, verify_password, create_access_token
from app.db.database import get_db
from app.db.models import User

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

@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, response: Response, db: Session = Depends(get_db)):
    email = str(payload.email).lower()
    user = db.scalar(select(User).where(User.email == email))
    if user is None or not user.is_active or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect email or password",
                            headers={"WWW-Authenticate": "Bearer"})
    settings = get_settings()
    access_token = create_access_token(str(user.id))
    csrf_token = secrets.token_urlsafe(32)
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
    # Keep the token response temporarily for existing API clients; the web app will use cookies.
    return TokenResponse(access_token=access_token)

@router.post("/logout", status_code=204)
def logout(response: Response, user: User = Depends(get_current_user)):
    settings = get_settings()
    for cookie_name in (settings.session_cookie_name, settings.csrf_cookie_name):
        response.delete_cookie(
            cookie_name,
            path="/",
            secure=settings.session_cookie_secure,
            httponly=(cookie_name == settings.session_cookie_name),
            samesite=settings.session_cookie_samesite.lower(),
        )
    response.status_code = 204
    return response

@router.get("/me", response_model=UserResponse)
def me(user: User = Depends(get_current_user)):
    return UserResponse(id=user.id, email=user.email, role=user.role)
