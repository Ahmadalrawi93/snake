"""Create or promote an administrator using explicit environment variables.

Run from backend/: SNAKE_BOOTSTRAP_ADMIN_EMAIL=... SNAKE_BOOTSTRAP_ADMIN_PASSWORD=... python scripts/bootstrap_admin.py
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sqlalchemy import select
from app.core.security import hash_password
from app.db.database import Base, SessionLocal, engine
from app.db import models  # noqa: F401
from app.db.models import User

email = os.environ.get("SNAKE_BOOTSTRAP_ADMIN_EMAIL", "").strip().lower()
password = os.environ.get("SNAKE_BOOTSTRAP_ADMIN_PASSWORD", "")
if not email or len(password) < 16:
    raise SystemExit("Set SNAKE_BOOTSTRAP_ADMIN_EMAIL and a SNAKE_BOOTSTRAP_ADMIN_PASSWORD of at least 16 characters.")

Base.metadata.create_all(bind=engine)
db = SessionLocal()
try:
    user = db.scalar(select(User).where(User.email == email))
    if user is None:
        user = User(email=email, password_hash=hash_password(password), role="admin", is_active=True)
        db.add(user)
    else:
        user.role = "admin"
        user.password_hash = hash_password(password)
        user.is_active = True
    db.commit()
    print(f"Administrator account provisioned: {email}")
finally:
    db.close()
