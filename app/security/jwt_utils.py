"""
JWT creation and validation — dual-mode implementation.

Vulnerable mode:
  - HS256 with the literal secret "secret"
  - No expiration claim
  - No issuer / audience validation
  - decode options set to skip exp verification

Secured mode:
  - RS256 with PEM key pair
  - Full claims: exp, iat, iss, aud, jti
  - Strict decode: raises on expired / wrong issuer / wrong audience
"""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from jose import JWTError, jwt

from app.config import MODE, settings


# ── Vulnerable helpers ────────────────────────────────────────────────────────

def _create_token_vulnerable(data: dict) -> str:
    # Intentionally weak: no exp, static secret, HS256
    payload = dict(data)
    return jwt.encode(payload, "secret", algorithm="HS256")


def _decode_token_vulnerable(token: str) -> dict:
    # Intentionally permissive: skip exp, iss, aud verification
    return jwt.decode(
        token,
        "secret",
        algorithms=["HS256"],
        options={"verify_exp": False, "verify_aud": False, "verify_iss": False},
    )


# ── Secured helpers ───────────────────────────────────────────────────────────

def _create_token_secured(data: dict, expires_delta: timedelta | None = None) -> str:
    from app.security.key_manager import get_private_key
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    payload = {
        **data,
        "exp": expire,
        "iat": now,
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "jti": str(uuid4()),
    }
    return jwt.encode(payload, get_private_key(), algorithm="RS256")


def _decode_token_secured(token: str) -> dict:
    from app.security.key_manager import get_public_key
    return jwt.decode(
        token,
        get_public_key(),
        algorithms=["RS256"],
        audience=settings.JWT_AUDIENCE,
        issuer=settings.JWT_ISSUER,
    )


# ── Public API ────────────────────────────────────────────────────────────────

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    if MODE == "secured":
        return _create_token_secured(data, expires_delta)
    return _create_token_vulnerable(data)


def create_refresh_token_string() -> str:
    """Generate a cryptographically random refresh token string."""
    return secrets.token_urlsafe(64)


def hash_token(raw: str) -> str:
    """SHA-256 hash for safe storage of refresh tokens."""
    return hashlib.sha256(raw.encode()).hexdigest()


def decode_token(token: str) -> dict:
    if MODE == "secured":
        return _decode_token_secured(token)
    return _decode_token_vulnerable(token)
