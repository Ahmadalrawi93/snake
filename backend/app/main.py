from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router as scope_router
from app.api.auth import router as auth_router
from app.api.control_plane import router as control_plane_router
from app.core.config import get_settings
from app.db.database import Base, engine
from app.db import models  # noqa: F401

settings = get_settings()
# create_all supports a fresh local database; use Alembic to upgrade existing databases.
Base.metadata.create_all(bind=engine)

app = FastAPI(title=settings.app_name, version="0.3.0",
              description="SNAKE authenticated control plane. Scanning is not enabled.")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origin_list,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)
app.include_router(scope_router)
app.include_router(auth_router)
app.include_router(control_plane_router)

@app.get("/")
def root():
    return {"name": "SNAKE", "version": "0.3.0", "status": "authenticated-control-plane"}

@app.get("/health")
def health():
    return {"status": "ok"}
