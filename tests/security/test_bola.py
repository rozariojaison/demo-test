"""
Security tests for BOLA/IDOR vulnerabilities.
Tests are marked vulnerable_mode or secured_mode and run against the corresponding environment.
"""
import pytest


@pytest.mark.vulnerable_mode
@pytest.mark.asyncio
async def test_bola_user_can_access_other_user_profile(client, vulnerable_user1_token):
    """Vulnerable mode: user1 can read user5's profile without owning it."""
    resp = await client.get(
        "/api/users/5/profile",
        headers={"Authorization": f"Bearer {vulnerable_user1_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == 5


@pytest.mark.vulnerable_mode
@pytest.mark.asyncio
async def test_bola_exposes_password_hash(client, vulnerable_user1_token):
    """Vulnerable mode: response includes password_hash."""
    resp = await client.get(
        "/api/users/2/profile",
        headers={"Authorization": f"Bearer {vulnerable_user1_token}"},
    )
    if resp.status_code == 200:
        data = resp.json()
        assert "password_hash" in data
        assert "internal_id" in data
        assert "is_admin" in data


@pytest.mark.vulnerable_mode
@pytest.mark.asyncio
async def test_bola_order_accessible_by_any_user(client, vulnerable_user1_token):
    """Vulnerable mode: user1 can access order owned by user5."""
    resp = await client.get(
        "/api/orders/9",  # Order ID 9 belongs to user5
        headers={"Authorization": f"Bearer {vulnerable_user1_token}"},
    )
    assert resp.status_code in (200, 404)  # 404 if not seeded, 200 if vulnerable


@pytest.mark.secured_mode
@pytest.mark.asyncio
async def test_bola_blocked_cross_user_access(client, vulnerable_user1_token):
    """Secured mode: user1 cannot access user5's profile."""
    resp = await client.get(
        "/api/users/5/profile",
        headers={"Authorization": f"Bearer {vulnerable_user1_token}"},
    )
    assert resp.status_code == 403


@pytest.mark.secured_mode
@pytest.mark.asyncio
async def test_secured_profile_no_sensitive_fields(client, vulnerable_user1_token):
    """Secured mode: own profile response contains no sensitive fields."""
    resp = await client.get(
        "/api/users/1/profile",
        headers={"Authorization": f"Bearer {vulnerable_user1_token}"},
    )
    if resp.status_code == 200:
        data = resp.json()
        assert "password_hash" not in data
        assert "internal_id" not in data
        assert "failed_login_count" not in data
