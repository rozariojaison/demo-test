"""Security tests for excessive data exposure."""
import pytest

SENSITIVE_FIELDS = ["password_hash", "internal_id", "failed_login_count"]


@pytest.mark.vulnerable_mode
@pytest.mark.asyncio
async def test_vulnerable_profile_exposes_sensitive_fields(client, vulnerable_user1_token):
    """Vulnerable mode: own profile response includes sensitive fields."""
    resp = await client.get(
        "/api/users/1/profile",
        headers={"Authorization": f"Bearer {vulnerable_user1_token}"},
    )
    if resp.status_code == 200:
        data = resp.json()
        exposed = [f for f in SENSITIVE_FIELDS if f in data]
        # At least one sensitive field should be exposed in vulnerable mode
        assert len(exposed) > 0, f"Expected sensitive fields; got keys: {list(data.keys())}"


@pytest.mark.secured_mode
@pytest.mark.asyncio
async def test_secured_profile_hides_sensitive_fields(client, vulnerable_user1_token):
    """Secured mode: own profile response must not include sensitive fields."""
    resp = await client.get(
        "/api/users/1/profile",
        headers={"Authorization": f"Bearer {vulnerable_user1_token}"},
    )
    if resp.status_code == 200:
        data = resp.json()
        for field in SENSITIVE_FIELDS:
            assert field not in data, f"Sensitive field '{field}' leaked in secured mode"


@pytest.mark.vulnerable_mode
@pytest.mark.asyncio
async def test_vulnerable_product_exposes_internal_cost(client, vulnerable_user1_token):
    """Vulnerable mode: product response exposes internal_cost."""
    resp = await client.get(
        "/api/products/1",
        headers={"Authorization": f"Bearer {vulnerable_user1_token}"},
    )
    if resp.status_code == 200:
        data = resp.json()
        assert "internal_cost" in data


@pytest.mark.secured_mode
@pytest.mark.asyncio
async def test_secured_product_hides_internal_cost(client, vulnerable_user1_token):
    """Secured mode: product response must not expose internal_cost."""
    resp = await client.get(
        "/api/products/1",
        headers={"Authorization": f"Bearer {vulnerable_user1_token}"},
    )
    if resp.status_code == 200:
        data = resp.json()
        assert "internal_cost" not in data
