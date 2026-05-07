"""Unit tests for password hashing."""
import pytest
from app.security.password import hash_password, verify_password


def test_hash_produces_bcrypt():
    hashed = hash_password("mysecret")
    assert hashed.startswith("$2b$") or hashed.startswith("$2a$")


def test_verify_correct_password():
    hashed = hash_password("correct_horse")
    assert verify_password("correct_horse", hashed) is True


def test_verify_wrong_password():
    hashed = hash_password("correct_horse")
    assert verify_password("wrong_horse", hashed) is False


def test_hash_is_non_deterministic():
    h1 = hash_password("same")
    h2 = hash_password("same")
    assert h1 != h2  # bcrypt uses random salt
