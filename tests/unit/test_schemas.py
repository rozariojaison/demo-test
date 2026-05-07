"""Unit tests for Pydantic schemas — field inclusion/exclusion."""
import uuid
from datetime import datetime, timezone

import pytest
from app.schemas.user import UserPublic, UserVulnerable


def _make_user_data() -> dict:
    return {
        "id": 1,
        "internal_id": uuid.uuid4(),
        "username": "testuser",
        "email": "test@lab.local",
        "password_hash": "$2b$12$fakehash",
        "is_admin": False,
        "is_active": True,
        "login_count": 5,
        "failed_login_count": 1,
        "last_login": datetime.now(timezone.utc),
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }


def test_user_public_excludes_sensitive_fields():
    data = _make_user_data()
    user = UserPublic(**{k: data[k] for k in ["id", "username", "email", "is_active", "created_at"]})
    serialized = user.model_dump()
    assert "password_hash" not in serialized
    assert "is_admin" not in serialized
    assert "internal_id" not in serialized
    assert "login_count" not in serialized


def test_user_vulnerable_exposes_sensitive_fields():
    data = _make_user_data()
    user = UserVulnerable(**data)
    serialized = user.model_dump()
    assert "password_hash" in serialized
    assert "is_admin" in serialized
    assert "internal_id" in serialized
    assert "login_count" in serialized
    assert "failed_login_count" in serialized
