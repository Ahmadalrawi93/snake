from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SNAKE API"
    environment: str = "development"
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    allowed_origins: str = "http://localhost:3000"
    scope_allowlist: str = ""

    model_config = SettingsConfigDict(
        env_prefix="SNAKE_",
        env_file=".env",
        extra="ignore",
    )

    @property
    def allowed_origin_list(self) -> list[str]:
        return [item.strip() for item in self.allowed_origins.split(",") if item.strip()]

    @property
    def scope_allowlist_items(self) -> list[str]:
        return [item.strip() for item in self.scope_allowlist.split(",") if item.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
