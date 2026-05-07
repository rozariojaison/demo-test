# Security Guide

## OWASP API Security Top 10 — Lab Mapping

### API1:2023 — Broken Object Level Authorization (BOLA/IDOR)

**What it is:** APIs expose endpoints that handle object identifiers. If the server does not verify that the requesting user has access to the requested object, an attacker can read or modify data belonging to other users.

**Vulnerable implementation (`app/routers/users.py`):**
```python
@vulnerable_router.get("/{user_id}/profile")
async def get_profile(user_id: int, current_user=Depends(get_current_user)):
    # No ownership check — user_id taken at face value
    return await db.get(User, user_id)
```

**Why it works:** Sequential integer IDs (1-15) make enumeration trivial. No check that `current_user.id == user_id`.

**Secured fix:**
```python
@secured_router.get("/{user_id}/profile")
async def get_profile(user_id: int, current_user=Depends(get_current_user)):
    if current_user.id != user_id and not current_user.is_admin:
        raise HTTPException(403, "Access denied")
    return await user_service.get_user(user_id, db)
```

**CVSS Score:** 8.1 (High) — Network, Low complexity, No privileges, User interaction required

---

### API2:2023 — Broken Authentication

**What it is:** Weak implementation of authentication allows attackers to compromise authentication tokens or exploit implementation flaws to assume other users' identities.

**Vulnerable implementation (`app/security/jwt_utils.py`):**
```python
# HS256 with literal string "secret"
# No expiration claim
# No issuer/audience validation
token = jwt.encode({"sub": str(user.id)}, "secret", algorithm="HS256")
```

**Attack vectors demonstrated:**
1. JWT signed with `"secret"` — crackable in milliseconds
2. No `exp` claim — tokens valid forever
3. No account lockout — brute force unrestricted
4. No refresh token rotation

**Secured fix:**
- RS256 with 2048-bit key pair
- Full claims: `exp`, `iat`, `iss`, `aud`, `jti`
- Account lockout after 10 failed attempts
- Refresh token rotation with SHA-256 storage

**CVSS Score:** 7.5 (High)

---

### API3:2023 — Broken Object Property Level Authorization (Excessive Data Exposure)

**What it is:** The API returns more data than the client needs, exposing sensitive fields.

**Vulnerable response (`UserVulnerable` schema):**
```json
{
  "id": 1,
  "username": "user1",
  "email": "user1@lab.local",
  "password_hash": "$2b$12$...",
  "is_admin": false,
  "internal_id": "550e8400-...",
  "login_count": 5,
  "failed_login_count": 1,
  "last_login": "2026-05-08T..."
}
```

**Secured fix (`UserPublic` schema):**
```json
{
  "id": 1,
  "username": "user1",
  "email": "user1@lab.local",
  "is_active": true,
  "created_at": "2026-05-08T..."
}
```

**Key principle:** Use Pydantic response models as contracts. Never return ORM objects directly.

---

### API4:2023 — Unrestricted Resource Consumption (Lack of Rate Limiting)

**What it is:** The API does not limit the number of requests a client can make, enabling brute force, credential stuffing, and DoS attacks.

**Vulnerable state:** Unlimited requests to `/auth/login`. No 429 responses. No account lockout.

**Attack demonstrated:** `offensive/brute_force.py` sends 20 requests without ever receiving a 429.

**Secured implementation:**

Kong rate-limiting plugin (`kong/kong.yml`):
```yaml
- name: rate-limiting
  config:
    minute: 5         # 5 attempts per minute per IP on /auth/login
    policy: redis
    redis_host: redis
```

App middleware (`middleware/rate_limit.py`):
- Redis sliding window algorithm
- Returns `Retry-After` and `X-RateLimit-*` headers on 429

---

### API5:2023 — Broken Function Level Authorization

**What it is:** Complex access control policies with different user types are not properly enforced.

**Vulnerable state:** `GET /admin/users` accessible by any authenticated user (no role check in vulnerable mode).

**Secured fix:** `require_role("admin")` dependency enforced on all admin routes.

---

### API6:2023 — Mass Assignment

**What it is:** Binding client-provided data directly to internal objects without filtering allows attackers to modify protected fields.

**Vulnerable endpoint:**
```python
@vulnerable_router.put("/{user_id}")
async def update_user(user_id: int, payload: dict, ...):
    for field, value in payload.items():
        setattr(user, field, value)  # accepts is_admin=true
```

**Attack payload:** `{"username": "user1", "is_admin": true, "role": "admin"}`

**Secured fix:** Pydantic `UserUpdateSecured` model with explicit allowlist:
```python
class UserUpdateSecured(BaseModel):
    email: EmailStr | None = None
    username: str | None = None
    # is_admin, role, password_hash — not present, cannot be set
```

---

## JWT Security

### Vulnerable Mode (HS256)
| Property | Value |
|---|---|
| Algorithm | HS256 |
| Secret | `"secret"` |
| Expiration | None |
| Issuer | Not validated |
| Audience | Not validated |

**Attack impact:** Any attacker who knows the secret (trivially guessable) can forge arbitrary tokens.

### Secured Mode (RS256)
| Property | Value |
|---|---|
| Algorithm | RS256 |
| Key size | 2048-bit |
| Expiration | 30 minutes |
| Issuer | `api-security-lab` |
| Audience | `api-security-lab-users` |
| Refresh rotation | On every refresh |
| Token storage | Hash (SHA-256) |

**Key generation:**
```bash
python scripts/generate_keys.py
# Creates secrets/private.pem (chmod 600) and secrets/public.pem
```

---

## Kong Gateway Security Configuration

### Rate Limiting Tiers
| Endpoint | Limit | Policy | Limit By |
|---|---|---|---|
| `POST /auth/login` | 5/minute | Redis | IP |
| `GET,POST /auth/*` | 30/minute | Redis | IP |
| `/api/*` | 100/minute | Redis | IP |
| `/admin/*` | 10/minute | Redis | IP |

### Additional Protections
- **Request size limiting:** 1MB max body on `/api/*`
- **IP restriction:** `/admin/*` restricted to private IP ranges
- **Response transformer:** Strips `Server` and `X-Powered-By` headers
- **Prometheus metrics:** Enabled for monitoring

### Why Redis policy?
Using `policy: redis` ensures rate limits are enforced correctly across multiple application workers. The `local` policy counts per Kong worker process, which can be bypassed by routing requests to different workers.

---

## API Hardening Checklist

- [ ] Use UUIDs instead of sequential IDs for all resources
- [ ] Enforce object-level ownership on every resource endpoint
- [ ] Use Pydantic response models — never return ORM objects directly
- [ ] Validate JWT: algorithm, expiration, issuer, audience
- [ ] Implement rate limiting on all authentication endpoints
- [ ] Rotate refresh tokens on every use
- [ ] Store refresh tokens as hashes, never plaintext
- [ ] Log all authentication events and failures
- [ ] Restrict admin endpoints to appropriate roles and IP ranges
- [ ] Strip sensitive headers from responses (Server, X-Powered-By)
- [ ] Implement request size limits
