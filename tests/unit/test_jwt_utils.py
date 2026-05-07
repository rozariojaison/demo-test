"""Unit tests for JWT utilities — both vulnerable and secured paths."""
import os

import pytest
from jose import jwt


def test_vulnerable_token_has_no_expiration(monkeypatch):
    monkeypatch.setenv("APP_MODE", "vulnerable")
    from importlib import reload
    import app.config as cfg
    import app.security.jwt_utils as jwtm

    reload(cfg)
    reload(jwtm)

    token = jwtm._create_token_vulnerable({"sub": "1"})
    payload = jwt.decode(token, "secret", algorithms=["HS256"], options={"verify_exp": False})
    assert "exp" not in payload
    assert payload["sub"] == "1"


def test_vulnerable_token_uses_weak_secret():
    from app.security.jwt_utils import _create_token_vulnerable
    token = _create_token_vulnerable({"sub": "42"})
    # Should be decodable with the string "secret"
    payload = jwt.decode(token, "secret", algorithms=["HS256"], options={"verify_exp": False})
    assert payload["sub"] == "42"


def test_vulnerable_decode_accepts_expired_token():
    from app.security.jwt_utils import _decode_token_vulnerable
    from datetime import datetime, timedelta, timezone
    expired_payload = {"sub": "1", "exp": datetime.now(timezone.utc) - timedelta(hours=1)}
    expired_token = jwt.encode(expired_payload, "secret", algorithm="HS256")
    # Should NOT raise
    result = _decode_token_vulnerable(expired_token)
    assert result["sub"] == "1"


def test_hash_token_is_deterministic():
    from app.security.jwt_utils import hash_token
    raw = "test_refresh_token_value"
    assert hash_token(raw) == hash_token(raw)


def test_hash_token_different_inputs():
    from app.security.jwt_utils import hash_token
    assert hash_token("abc") != hash_token("def")


def test_refresh_token_string_unique():
    from app.security.jwt_utils import create_refresh_token_string
    t1 = create_refresh_token_string()
    t2 = create_refresh_token_string()
    assert t1 != t2
    assert len(t1) > 30
