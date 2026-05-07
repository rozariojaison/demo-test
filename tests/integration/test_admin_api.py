"""Integration tests for the admin API endpoints."""
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_admin_requires_authentication(client: AsyncClient):
    response = await client.get("/admin/users")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_admin_requires_admin_role(client: AsyncClient, user_token: str):
    """Non-admin users must be refused admin endpoints."""
    response = await client.get(
        "/admin/users",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_admin_list_users(client: AsyncClient, admin_token: str):
    response = await client.get(
        "/admin/users",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


@pytest.mark.asyncio
async def test_admin_audit_logs(client: AsyncClient, admin_token: str):
    response = await client.get(
        "/admin/audit-logs",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_admin_stats(client: AsyncClient, admin_token: str):
    response = await client.get(
        "/admin/stats",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "total_users" in data or "users" in data or isinstance(data, dict)


@pytest.mark.asyncio
@pytest.mark.vulnerable_mode
async def test_admin_exposes_password_hashes_vulnerable(
    client: AsyncClient, admin_token: str
):
    """Vulnerable admin endpoint leaks password_hash in user list."""
    response = await client.get(
        "/admin/users",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    users = response.json()
    if users:
        assert "password_hash" in users[0], (
            "Vulnerable admin endpoint should expose password_hash"
        )


@pytest.mark.asyncio
@pytest.mark.secured_mode
async def test_admin_hides_password_hashes_secured(
    client: AsyncClient, admin_token: str
):
    """Secured admin endpoint must not return password_hash."""
    response = await client.get(
        "/admin/users",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    users = response.json()
    for user in users:
        assert "password_hash" not in user, (
            "Secured admin endpoint must not expose password_hash"
        )


@pytest.mark.asyncio
@pytest.mark.secured_mode
async def test_admin_rate_limited_secured(client: AsyncClient, admin_token: str):
    """Admin endpoints should be rate limited to 10 req/min in secured mode."""
    responses = []
    for _ in range(12):
        r = await client.get(
            "/admin/users",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        responses.append(r.status_code)
    assert 429 in responses, "Admin endpoint must return 429 after rate limit exceeded"
