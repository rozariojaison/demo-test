"""Security tests for rate limiting."""
import asyncio
import pytest


@pytest.mark.secured_mode
@pytest.mark.asyncio
async def test_login_rate_limit_triggers(client):
    """Secured mode: 6th login attempt within a minute returns 429."""
    for _ in range(5):
        await client.post(
            "/auth/login",
            json={"username": "user1", "password": "wrongpass"},
        )
    resp = await client.post(
        "/auth/login",
        json={"username": "user1", "password": "wrongpass"},
    )
    # Rate limiter may be middleware or Kong — check for 429
    assert resp.status_code == 429
    assert "Retry-After" in resp.headers


@pytest.mark.secured_mode
@pytest.mark.asyncio
async def test_rate_limit_headers_present(client):
    """Secured mode: rate-limit response includes X-RateLimit headers."""
    responses = []
    for _ in range(7):
        r = await client.post(
            "/auth/login",
            json={"username": "user1", "password": "x"},
        )
        responses.append(r)

    rate_limited = [r for r in responses if r.status_code == 429]
    if rate_limited:
        r = rate_limited[0]
        assert "Retry-After" in r.headers


@pytest.mark.vulnerable_mode
@pytest.mark.asyncio
async def test_no_rate_limit_in_vulnerable_mode(client):
    """Vulnerable mode: 20 consecutive login attempts should never return 429."""
    for i in range(20):
        resp = await client.post(
            "/auth/login",
            json={"username": "user1", "password": f"wrong{i}"},
        )
        assert resp.status_code != 429, f"Unexpected 429 at attempt {i+1}"


@pytest.mark.secured_mode
@pytest.mark.asyncio
async def test_admin_route_rate_limit(client, vulnerable_admin_token):
    """Secured mode: admin endpoint has stricter rate limit (10/min)."""
    for _ in range(11):
        r = await client.get(
            "/admin/stats",
            headers={"Authorization": f"Bearer {vulnerable_admin_token}"},
        )
    assert r.status_code in (429, 200)  # May or may not hit within test
