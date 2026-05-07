"""Integration tests for user management API."""
import pytest


@pytest.mark.asyncio
async def test_list_users_requires_auth(client):
    resp = await client.get("/api/users/")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_get_profile_with_valid_token(client):
    reg = await client.post(
        "/auth/register",
        json={"username": "profiletest", "email": "profile@lab.local", "password": "Pass123!"},
    )
    token = reg.json()["access_token"]
    resp = await client.get("/api/users/1/profile", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code in (200, 403, 404)


@pytest.mark.asyncio
async def test_health_endpoint_accessible(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
    assert resp.json()["mode"] in ("vulnerable", "secured")
