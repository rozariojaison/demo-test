"""Integration tests for the full authentication flow."""
import pytest


@pytest.mark.asyncio
async def test_register_and_login(client):
    """Full register → login cycle."""
    reg_resp = await client.post(
        "/auth/register",
        json={"username": "newuser", "email": "new@lab.local", "password": "TestPass123!"},
    )
    assert reg_resp.status_code == 200
    assert "access_token" in reg_resp.json()

    login_resp = await client.post(
        "/auth/login",
        json={"username": "newuser", "password": "TestPass123!"},
    )
    assert login_resp.status_code == 200
    assert "access_token" in login_resp.json()


@pytest.mark.asyncio
async def test_login_wrong_password(client):
    reg = await client.post(
        "/auth/register",
        json={"username": "authtest", "email": "auth@lab.local", "password": "Right1!"},
    )
    assert reg.status_code == 200

    resp = await client.post(
        "/auth/login",
        json={"username": "authtest", "password": "Wrong!"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_authenticated_endpoint_requires_token(client):
    resp = await client.get("/api/users/1/profile")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_duplicate_registration_rejected(client):
    payload = {"username": "dupuser", "email": "dup@lab.local", "password": "Pass123!"}
    await client.post("/auth/register", json=payload)
    resp = await client.post("/auth/register", json=payload)
    assert resp.status_code == 400
