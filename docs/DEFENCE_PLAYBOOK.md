# Defence Playbook

Implementation guide for all security controls in the lab.

---

## Authorization Strategy

### Object-Level Authorization Middleware

The `ObjectLevelAuthMiddleware` (`middleware/authorization.py`) intercepts all requests and:

1. Matches path patterns: `/api/users/{id}` and `/api/orders/{id}`
2. Extracts the requesting user from the JWT
3. Loads the resource owner from the database
4. Returns 403 if owner ≠ requester (admins bypass)

**Pattern to follow for new resources:**

```python
_OWNERSHIP_PATTERNS = [
    (re.compile(r"^/api/orders/(\d+)"), "orders"),
    (re.compile(r"^/api/users/(\d+)"), "users"),
    # Add new resources here:
    (re.compile(r"^/api/documents/(\d+)"), "documents"),
]
```

**Key principle:** Always verify ownership at the **object level**, not just at the route level.

### RBAC

Three roles: `user` → `manager` → `admin`

```python
# Apply to any endpoint
@router.get("/sensitive-data")
async def sensitive(current_user=Depends(require_role("admin", "manager"))):
    ...
```

`require_role()` is a no-op in vulnerable mode (educational toggle), and fully enforced in secured mode.

---

## JWT Security Implementation

### Why RS256 over HS256?

| Property | HS256 | RS256 |
|---|---|---|
| Key type | Symmetric (shared secret) | Asymmetric (public/private pair) |
| Verification | Same secret needed | Public key only needed |
| Secret exposure | Anyone who verifies can forge | Private key never leaves auth server |
| Attack surface | Brute-forceable if weak | 2048-bit — computationally infeasible |

### Key Rotation Procedure

```bash
# Generate new keys
python scripts/generate_keys.py --key-size 4096

# Update .env.secured with new paths
# Restart application (old tokens will fail — issue new ones or extend window)
```

### Refresh Token Security

Refresh tokens in secured mode:
- Generated with `secrets.token_urlsafe(64)` (cryptographically random)
- Stored as `SHA-256(raw_token)` — plaintext never persisted
- **Rotated on every use** — compromise of one token does not enable session replay
- Revoked on logout (all sessions) or explicit single-token revocation

---

## Rate Limiting Design

### Two-Layer Defence

```
Layer 1: Kong Gateway (network layer)
  ↓ blocks excess traffic before it reaches the app
Layer 2: Redis Middleware (app layer)
  ↓ fallback if Kong is bypassed or unavailable
```

### Sliding Window vs Fixed Window

The lab uses a **sliding window** algorithm (Lua script in Redis):

```
Fixed window: Reset at :00, :60, :120...
  → 5 requests at :59 + 5 requests at :01 = 10 in 2 seconds ✗

Sliding window: Look back 60s from NOW
  → 5 requests at :59 + request at :01 → only 4 remain, 6th blocked ✓
```

### Setting Appropriate Limits

| Endpoint type | Recommended limit | Rationale |
|---|---|---|
| Login | 5/minute/IP | Credential stuffing prevention |
| Registration | 3/hour/IP | Account creation abuse |
| Password reset | 3/hour/email | Enumeration + spam prevention |
| General API | 100/minute/user | Normal usage pattern |
| Admin API | 10/minute/user | High-value, low-volume operations |

---

## Secure Coding Practices

### Response Schema Contracts

Never return ORM objects directly. Always define explicit Pydantic response models:

```python
# Bad — returns everything including password_hash
return user  # SQLAlchemy User object

# Good — returns only approved fields
return UserPublic.model_validate(user)
```

### Mass Assignment Prevention

```python
# Bad — accepts any field
class UpdateRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

# Good — explicit allowlist
class UpdateRequest(BaseModel):
    email: EmailStr | None = None
    username: str | None = None
    # is_admin intentionally excluded
```

### Sequential ID Replacement

In secured mode, use UUIDs for resource identifiers in external-facing APIs:

```python
# Vulnerable — enumerable
GET /api/orders/1, /api/orders/2, ...

# Secured — not enumerable
GET /api/orders/550e8400-e29b-41d4-a716-446655440000
```

The lab uses `uuid` columns on all models alongside `id SERIAL` for compatibility.

---

## Kong Gateway Hardening

### Verifying Rate Limits are Active

```bash
# Confirm Kong is applying limits
for i in $(seq 1 7); do
  curl -s -o /dev/null -w "Request $i: HTTP %{http_code}\n" \
    -X POST http://localhost:8080/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"user1","password":"wrong"}'
done
# Should see 429 on or before request 6
```

### Check Active Plugins

```bash
curl http://localhost:8001/plugins | python -m json.tool
# Lists all active Kong plugins with configuration
```

### Rate Limit Headers

In secured mode, all API responses include:
```
X-RateLimit-Limit-Minute: 100
X-RateLimit-Remaining-Minute: 97
RateLimit-Limit: 100
RateLimit-Remaining: 97
RateLimit-Reset: 1715205600
```

---

## Audit Logging

The `AuditMiddleware` logs every request in both modes. Key fields:

| Field | Purpose |
|---|---|
| `user_id` | Who made the request |
| `action` | What operation was attempted |
| `ip_address` | Source IP (consider X-Forwarded-For carefully) |
| `response_status` | HTTP status (403s = authorization violations) |
| `details.duration_ms` | Performance monitoring |

### Querying for Security Events

```sql
-- Failed login attempts
SELECT ip_address, COUNT(*) as attempts, MAX(timestamp) as last_attempt
FROM audit_logs
WHERE request_path = '/auth/login' AND response_status = 401
GROUP BY ip_address
ORDER BY attempts DESC;

-- Authorization violations (BOLA attempts)
SELECT * FROM audit_logs
WHERE action = 'authorization.violation'
ORDER BY timestamp DESC;

-- Unusual activity by user
SELECT user_id, COUNT(*) as requests, MAX(timestamp)
FROM audit_logs
WHERE timestamp > NOW() - INTERVAL '1 hour'
GROUP BY user_id
HAVING COUNT(*) > 50;
```

---

## Security Metrics to Monitor

| Metric | Alert Threshold | Meaning |
|---|---|---|
| Failed logins / IP / minute | > 5 | Credential stuffing |
| 403 rate on `/api/users/*` | > 10/minute | BOLA enumeration |
| 429 rate | Sustained > 20% | DDoS or aggressive scraping |
| Admin endpoint 403s | Any | Unauthorized access attempts |
| JWT validation failures | > 5/minute from same IP | JWT attack |
