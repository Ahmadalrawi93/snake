import pytest
from pydantic import ValidationError

from app.core.config import Settings


def production_settings(**overrides):
    values = {
        "environment": "production",
        "jwt_secret_key": "production-secret-that-is-at-least-32-bytes-long",
        "allowed_origins": "https://app.example.com",
        "session_cookie_secure": True,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def test_production_configuration_accepts_exact_https_origin():
    settings = production_settings()
    assert settings.environment == "production"
    assert settings.allowed_origin_list == ["https://app.example.com"]
    assert settings.session_cookie_secure is True


@pytest.mark.parametrize(
    "origin",
    [
        "",
        "*",
        "https://*",
        "http://app.example.com",
        "http://localhost:3000",
        "https://localhost:3000",
        "https://127.0.0.1",
        "https://app.example.com/path",
        "https://app.example.com?debug=true",
        "https://user:pass@app.example.com",
    ],
)
def test_production_configuration_rejects_unsafe_cors_origins(origin):
    with pytest.raises(ValidationError):
        production_settings(allowed_origins=origin)


def test_production_configuration_requires_secure_session_cookie():
    with pytest.raises(ValidationError, match="SESSION_COOKIE_SECURE"):
        production_settings(session_cookie_secure=False)


def test_production_configuration_requires_secure_cookie_for_samesite_none():
    with pytest.raises(ValidationError, match="SameSite=None"):
        production_settings(session_cookie_samesite="none", session_cookie_secure=False)


def test_production_configuration_rejects_short_jwt_secret():
    with pytest.raises(ValidationError, match="JWT_SECRET_KEY"):
        production_settings(jwt_secret_key="too-short")
