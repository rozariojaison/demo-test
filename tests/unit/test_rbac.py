"""Unit tests for RBAC helpers."""
import pytest
from unittest.mock import MagicMock
from app.security.rbac import has_role


def _make_user(*role_names: str):
    user = MagicMock()
    roles = [MagicMock(name=n) for n in role_names]
    user.roles = roles
    return user


def test_has_role_match():
    user = _make_user("admin")
    assert has_role(user, "admin") is True


def test_has_role_no_match():
    user = _make_user("user")
    assert has_role(user, "admin") is False


def test_has_role_multiple():
    user = _make_user("manager")
    assert has_role(user, "admin", "manager") is True


def test_has_role_empty_roles():
    user = _make_user()
    assert has_role(user, "admin") is False
