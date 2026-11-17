from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.core.config import get_settings

settings = get_settings()
app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="SNAKE foundation API. No active scanning endpoints are exposed.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origin_list,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)

app.include_router(router)


@app.get("/")
def root():
    return {"name": "SNAKE", "version": "0.1.0", "status": "foundation"}


@app.get("/health")
def health():
    return {"status": "ok"}
