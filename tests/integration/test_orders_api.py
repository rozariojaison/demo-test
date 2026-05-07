"""Integration tests for the orders API endpoints."""
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_create_order_authenticated(client: AsyncClient, user_token: str):
    payload = {
        "items": [{"product_id": 1, "quantity": 2}],
        "shipping_address": {
            "street": "123 Test St",
            "city": "Testville",
            "country": "US",
            "zip": "12345",
        },
    }
    response = await client.post(
        "/api/orders/",
        json=payload,
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert response.status_code in (200, 201, 422)


@pytest.mark.asyncio
async def test_list_own_orders(client: AsyncClient, user_token: str):
    response = await client.get(
        "/api/orders/",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


@pytest.mark.asyncio
@pytest.mark.vulnerable_mode
async def test_bola_order_access_vulnerable(
    client: AsyncClient, user_token: str
):
    """In vulnerable mode user1 can access user2's orders by guessing sequential IDs."""
    # Try fetching orders belonging to other users
    accessed_foreign = False
    for order_id in range(11, 21):  # orders 11-20 belong to users 6-10
        r = await client.get(
            f"/api/orders/{order_id}",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        if r.status_code == 200:
            accessed_foreign = True
            break
    assert accessed_foreign, "Vulnerable mode should allow cross-user order access (BOLA)"


@pytest.mark.asyncio
@pytest.mark.secured_mode
async def test_bola_order_blocked_secured(
    client: AsyncClient, user_token: str
):
    """In secured mode cross-user order access must be forbidden."""
    for order_id in range(11, 21):
        r = await client.get(
            f"/api/orders/{order_id}",
            headers={"Authorization": f"Bearer {user_token}"},
        )
        assert r.status_code in (403, 404), (
            f"Secured mode must block cross-user order access, got {r.status_code} for order {order_id}"
        )


@pytest.mark.asyncio
async def test_get_nonexistent_order(client: AsyncClient, user_token: str):
    response = await client.get(
        "/api/orders/99999",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert response.status_code in (403, 404)


@pytest.mark.asyncio
async def test_orders_require_auth(client: AsyncClient):
    response = await client.get("/api/orders/")
    assert response.status_code == 401
