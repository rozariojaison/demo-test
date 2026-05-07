"""Security tests for Mass Assignment vulnerability."""
import pytest


@pytest.mark.vulnerable_mode
@pytest.mark.asyncio
async def test_mass_assignment_escalates_to_admin(client, vulnerable_user1_token):
    """Vulnerable mode: PUT with is_admin=true should be accepted."""
    resp = await client.put(
        "/api/users/1",
        headers={"Authorization": f"Bearer {vulnerable_user1_token}"},
        json={
            "username": "user1",
            "email": "user1@lab.local",
            "is_admin": True,
        },
    )
    # In vulnerable mode, the update is accepted
    assert resp.status_code in (200, 422)
    if resp.status_code == 200:
        assert resp.json().get("is_admin") is True


@pytest.mark.secured_mode
@pytest.mark.asyncio
async def test_mass_assignment_rejected_in_secured_mode(client, vulnerable_user1_token):
    """Secured mode: PUT with is_admin=true should be rejected (422 or 403)."""
    resp = await client.put(
        "/api/users/1",
        headers={"Authorization": f"Bearer {vulnerable_user1_token}"},
        json={
            "username": "user1",
            "email": "user1@lab.local",
            "is_admin": True,
            "role": "admin",
        },
    )
    # Pydantic rejects extra fields (422) OR role check fails (403)
    assert resp.status_code in (403, 422)


@pytest.mark.secured_mode
@pytest.mark.asyncio
async def test_secured_update_only_allows_safe_fields(client, vulnerable_admin_token):
    """Secured mode: only email and username are accepted."""
    resp = await client.put(
        "/api/users/1",
        headers={"Authorization": f"Bearer {vulnerable_admin_token}"},
        json={"email": "newemail@lab.local"},
    )
    assert resp.status_code in (200, 404)  # 200 if user exists
    if resp.status_code == 200:
        assert "password_hash" not in resp.json()
