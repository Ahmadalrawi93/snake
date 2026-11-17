from functools import lru_cache
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "SNAKE API"
    environment: str = "development"
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    allowed_origins: str = "http://localhost:3000"
    scope_allowlist: str = ""
    database_url: str = "sqlite:///./snake.db"
    jwt_secret_key: str = "CHANGE_ME_FOR_LOCAL_DEVELOPMENT_ONLY"
    access_token_minutes: int = 30

    model_config = SettingsConfigDict(env_prefix="SNAKE_", env_file=".env", extra="ignore")

    @model_validator(mode="after")
    def require_production_secret(self):
        if self.environment.lower() in {"production", "prod"}:
            if self.jwt_secret_key == "CHANGE_ME_FOR_LOCAL_DEVELOPMENT_ONLY" or len(self.jwt_secret_key) < 32:
                raise ValueError("SNAKE_JWT_SECRET_KEY must be a random secret of at least 32 characters in production")
        return self

    @property
    def allowed_origin_list(self) -> list[str]:
        return [item.strip() for item in self.allowed_origins.split(",") if item.strip()]

    @property
    def scope_allowlist_items(self) -> list[str]:
        return [item.strip() for item in self.scope_allowlist.split(",") if item.strip()]

@lru_cache
def get_settings() -> Settings:
    return Settings()
