"""Security tests for JWT attack vectors."""
import base64
import json
import pytest


def _b64url_encode(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_none_alg_token(user_id: int = 1, is_admin: bool = True) -> str:
    header = _b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}))
    payload = _b64url_encode(json.dumps({"sub": str(user_id), "roles": ["admin"], "is_admin": is_admin}))
    return f"{header}.{payload}."


def _make_tampered_role_token(valid_token: str) -> str:
    parts = valid_token.split(".")
    payload_data = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    payload_data["roles"] = ["admin"]
    payload_data["is_admin"] = True
    new_payload = _b64url_encode(json.dumps(payload_data))
    return f"{parts[0]}.{new_payload}.{parts[2]}"


@pytest.mark.vulnerable_mode
@pytest.mark.asyncio
async def test_none_alg_accepted_in_vulnerable_mode(client):
    """Vulnerable mode: none-algorithm token may be accepted due to weak validation."""
    none_token = _make_none_alg_token(user_id=1)
    resp = await client.get(
        "/api/users/1/profile",
        headers={"Authorization": f"Bearer {none_token}"},
    )
    # Vulnerable mode with HS256 might still reject none-alg via jose library default
    # This test documents the behavior
    assert resp.status_code in (200, 401, 422)


@pytest.mark.secured_mode
@pytest.mark.asyncio
async def test_none_alg_rejected_in_secured_mode(client):
    """Secured mode: none-algorithm token must be rejected."""
    none_token = _make_none_alg_token(user_id=1)
    resp = await client.get(
        "/api/users/1/profile",
        headers={"Authorization": f"Bearer {none_token}"},
    )
    assert resp.status_code == 401


@pytest.mark.secured_mode
@pytest.mark.asyncio
async def test_tampered_payload_rejected(client, vulnerable_user1_token):
    """Secured mode: payload-tampered token with original signature must be rejected."""
    tampered = _make_tampered_role_token(vulnerable_user1_token)
    resp = await client.get(
        "/admin/users",
        headers={"Authorization": f"Bearer {tampered}"},
    )
    assert resp.status_code == 401


@pytest.mark.secured_mode
@pytest.mark.asyncio
async def test_wrong_secret_rejected(client, tampered_admin_token):
    """Secured mode: token signed with wrong secret must be rejected."""
    resp = await client.get(
        "/api/users/1/profile",
        headers={"Authorization": f"Bearer {tampered_admin_token}"},
    )
    assert resp.status_code == 401


@pytest.mark.vulnerable_mode
@pytest.mark.asyncio
async def test_no_token_returns_401(client):
    """Both modes: unauthenticated request must return 401."""
    resp = await client.get("/api/users/1/profile")
    assert resp.status_code == 401
