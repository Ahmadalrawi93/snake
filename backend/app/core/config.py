from functools import lru_cache
from urllib.parse import urlsplit
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "SNAKE API"
    environment: str = "development"
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    allowed_origins: str = "http://localhost:3000"
    allowed_hosts: str = "localhost,127.0.0.1,testserver"
    max_request_body_bytes: int = 2097152
    scope_allowlist: str = ""
    database_url: str = "sqlite:///./snake.db"
    jwt_secret_key: str = "CHANGE_ME_FOR_LOCAL_DEVELOPMENT_ONLY"
    jwt_previous_secret_keys: str = ""
    access_token_minutes: int = 30
    session_cookie_name: str = "snake_session"
    csrf_cookie_name: str = "snake_csrf"
    csrf_header_name: str = "X-SNAKE-CSRF"
    session_cookie_secure: bool = False
    session_cookie_samesite: str = "lax"

    model_config = SettingsConfigDict(env_prefix="SNAKE_", env_file=".env", extra="ignore")

    @model_validator(mode="after")
    def require_production_secret(self):
        if self.environment.lower() in {"production", "prod"}:
            if self.jwt_secret_key == "CHANGE_ME_FOR_LOCAL_DEVELOPMENT_ONLY" or len(self.jwt_secret_key) < 32:
                raise ValueError("SNAKE_JWT_SECRET_KEY must be a random secret of at least 32 characters in production")
        return self

    @model_validator(mode="after")
    def validate_jwt_rotation_keys(self):
        previous = self.jwt_previous_secret_list
        if len(previous) != len(set(previous)):
            raise ValueError("SNAKE_JWT_PREVIOUS_SECRET_KEYS must not contain duplicates")
        if self.jwt_secret_key in previous:
            raise ValueError("SNAKE_JWT_PREVIOUS_SECRET_KEYS must not repeat the active key")
        if self.environment.lower() in {"production", "prod"}:
            if any(len(key) < 32 for key in previous):
                raise ValueError("Every previous production JWT secret must be at least 32 characters")
        return self

    @model_validator(mode="after")
    def validate_request_limits(self):
        if self.max_request_body_bytes < 1024 or self.max_request_body_bytes > 10 * 1024 * 1024:
            raise ValueError("SNAKE_MAX_REQUEST_BODY_BYTES must be between 1024 and 10485760")
        return self

    @model_validator(mode="after")
    def validate_production_hosts(self):
        if self.environment.lower() in {"production", "prod"}:
            hosts = self.allowed_host_list
            if not hosts:
                raise ValueError("SNAKE_ALLOWED_HOSTS must contain exact production hostnames")
            for host in hosts:
                if "*" in host:
                    raise ValueError("Wildcard allowed hosts are forbidden in production")
                parsed = urlsplit("//" + host)
                try:
                    parsed.port
                except ValueError as exc:
                    raise ValueError("Production allowed hosts must use valid ports") from exc
                if (
                    not parsed.hostname
                    or parsed.username is not None
                    or parsed.password is not None
                    or parsed.path
                    or parsed.query
                    or parsed.fragment
                    or parsed.hostname in {"localhost", "127.0.0.1", "::1"}
                ):
                    raise ValueError("Production allowed hosts must be exact hostnames without schemes or paths")
        return self

    @model_validator(mode="after")
    def validate_production_origins(self):
        if self.environment.lower() in {"production", "prod"}:
            origins = self.allowed_origin_list
            if not origins:
                raise ValueError("SNAKE_ALLOWED_ORIGINS must contain at least one HTTPS origin in production")
            for origin in origins:
                if origin == "*" or "*" in origin:
                    raise ValueError("Wildcard CORS origins are forbidden in production")
                parsed = urlsplit(origin)
                try:
                    parsed.port
                except ValueError as exc:
                    raise ValueError("Production CORS origins must use a valid port") from exc
                if (
                    parsed.scheme != "https"
                    or not parsed.netloc
                    or parsed.username is not None
                    or parsed.password is not None
                    or parsed.path != ""
                    or parsed.query
                    or parsed.fragment
                    or parsed.hostname in {"localhost", "127.0.0.1", "::1"}
                ):
                    raise ValueError("Production CORS origins must be exact HTTPS origins without paths or localhost")
        return self

    @model_validator(mode="after")
    def validate_session_cookie_settings(self):
        if self.session_cookie_samesite.lower() not in {"lax", "strict", "none"}:
            raise ValueError("SNAKE_SESSION_COOKIE_SAMESITE must be lax, strict, or none")
        if self.session_cookie_samesite.lower() == "none" and not self.session_cookie_secure:
            raise ValueError("SameSite=None requires secure session cookies")
        if self.environment.lower() in {"production", "prod"} and not self.session_cookie_secure:
            raise ValueError("SNAKE_SESSION_COOKIE_SECURE must be true in production")
        return self

    @property
    def jwt_previous_secret_list(self) -> list[str]:
        return [item.strip() for item in self.jwt_previous_secret_keys.split(",") if item.strip()]

    @property
    def allowed_host_list(self) -> list[str]:
        return [item.strip().lower() for item in self.allowed_hosts.split(",") if item.strip()]

    @property
    def allowed_origin_list(self) -> list[str]:
        return [item.strip() for item in self.allowed_origins.split(",") if item.strip()]

    @property
    def scope_allowlist_items(self) -> list[str]:
        return [item.strip() for item in self.scope_allowlist.split(",") if item.strip()]

@lru_cache
def get_settings() -> Settings:
    return Settings()
