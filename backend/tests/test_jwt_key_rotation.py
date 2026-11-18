from app.core import security
from app.core.config import Settings


OLD_KEY = "old-production-signing-key-material-at-least-32"
NEW_KEY = "new-production-signing-key-material-at-least-32"


def test_existing_jwt_remains_valid_during_staged_key_rotation(monkeypatch):
    old_settings = Settings(_env_file=None, jwt_secret_key=OLD_KEY)
    monkeypatch.setattr(security, "get_settings", lambda: old_settings)
    old_token = security.create_access_token("42")

    rotated_settings = Settings(
        _env_file=None,
        jwt_secret_key=NEW_KEY,
        jwt_previous_secret_keys=OLD_KEY,
    )
    monkeypatch.setattr(security, "get_settings", lambda: rotated_settings)

    claims = security.decode_access_token_claims(old_token)
    assert claims is not None
    assert claims["sub"] == "42"
    assert security.decode_access_token(old_token) == "42"


def test_new_jwts_use_active_key_while_previous_key_is_accepted(monkeypatch):
    rotated_settings = Settings(
        _env_file=None,
        jwt_secret_key=NEW_KEY,
        jwt_previous_secret_keys=OLD_KEY,
    )
    monkeypatch.setattr(security, "get_settings", lambda: rotated_settings)

    token = security.create_access_token("7")
    assert security.decode_access_token(token) == "7"

    import jwt
    from app.core.security import ALGORITHM

    # The token is signed by the new active key, not by the retained old key.
    assert jwt.decode(token, NEW_KEY, algorithms=[ALGORITHM])["sub"] == "7"
    try:
        jwt.decode(token, OLD_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        pass
    else:
        raise AssertionError("New tokens must not be signed with a previous key")


def test_removing_previous_key_ends_old_jwt_acceptance(monkeypatch):
    old_settings = Settings(_env_file=None, jwt_secret_key=OLD_KEY)
    monkeypatch.setattr(security, "get_settings", lambda: old_settings)
    old_token = security.create_access_token("9")

    final_settings = Settings(_env_file=None, jwt_secret_key=NEW_KEY)
    monkeypatch.setattr(security, "get_settings", lambda: final_settings)
    assert security.decode_access_token_claims(old_token) is None
