"""Loads RS256 PEM keys for secured-mode JWT signing."""
from pathlib import Path

from app.config import settings

_private_key: str | None = None
_public_key: str | None = None


def get_private_key() -> str:
    global _private_key
    if _private_key is None:
        path = Path(settings.JWT_PRIVATE_KEY_PATH)
        if not path.exists():
            raise FileNotFoundError(
                f"RS256 private key not found at {path}. "
                "Run: python scripts/generate_keys.py"
            )
        _private_key = path.read_text()
    return _private_key


def get_public_key() -> str:
    global _public_key
    if _public_key is None:
        path = Path(settings.JWT_PUBLIC_KEY_PATH)
        if not path.exists():
            raise FileNotFoundError(
                f"RS256 public key not found at {path}. "
                "Run: python scripts/generate_keys.py"
            )
        _public_key = path.read_text()
    return _public_key
