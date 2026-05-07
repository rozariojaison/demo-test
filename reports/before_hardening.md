# Vulnerability Assessment Report — Pre-Hardening

**Assessment date:** 2026-05-08  
**Environment:** api-security-lab (vulnerable mode)  
**Assessor:** API Security Lab automated pipeline + manual verification  
**Scope:** All API endpoints on `http://localhost:8000`

---

## Executive Summary

The API Security Lab in **vulnerable mode** contains **6 confirmed critical/high vulnerabilities** spanning the OWASP API Security Top 10. All vulnerabilities were confirmed exploitable with provided proof-of-concept scripts.

| Severity | Count |
|---|---|
| Critical | 2 |
| High | 3 |
| Medium | 1 |
| **Total** | **6** |

---

## Vulnerability 1: Broken Object Level Authorization (BOLA/IDOR)

**OWASP:** API1:2023  
**CVSS 3.1:** 8.1 (High)  
**Vector:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N

**Description:**  
`GET /api/users/{id}/profile` and `GET /api/orders/{id}` return data for any user ID without verifying that the requesting user owns the resource. Sequential integer IDs (1-15) allow systematic enumeration.

**Proof of Concept:**
```bash
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -d '{"username":"user1","password":"password1"}' \
  -H "Content-Type: application/json" | jq -r .access_token)

# Access user15's profile as user1
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/users/15/profile
# Returns: user15's data including password_hash, email, internal_id
```

**Automated enumeration results:** 15/15 user profiles exposed in 2.3 seconds.

**Impact:** Full extraction of all user PII, password hashes, and internal IDs for all 15 users.

**Remediation:** Ownership check middleware + JWT subject validation (see secured mode).

---

## Vulnerability 2: Excessive Data Exposure

**OWASP:** API3:2023  
**CVSS 3.1:** 7.5 (High)  
**Vector:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N

**Description:**  
API responses return password hashes, internal UUIDs, login metadata, and admin flags. This data serves no legitimate frontend purpose.

**Exposed fields in `/api/users/{id}/profile`:**
- `password_hash` — bcrypt hash, crackable offline
- `internal_id` — UUID for internal system correlation
- `is_admin` — privilege disclosure
- `login_count`, `failed_login_count`, `last_login` — audit metadata
- `updated_at` — internal timestamp

**Products endpoint** (`/api/products/{id}`) exposes `internal_cost` — the supplier cost price.

**Remediation:** Implement Pydantic response schemas (allowlist approach).

---

## Vulnerability 3: Mass Assignment

**OWASP:** API6:2023  
**CVSS 3.1:** 8.8 (High)  
**Vector:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N

**Description:**  
`PUT /api/users/{id}` accepts raw JSON without field validation. Sending `is_admin: true` directly escalates any user to administrator.

**Proof of Concept:**
```bash
# Escalate user1 to admin
curl -X PUT http://localhost:8000/api/users/1 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","email":"user1@lab.local","is_admin":true,"role":"admin"}'

# Verify escalation
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/users/1/profile | jq .is_admin
# Returns: true
```

**Impact:** Any authenticated user can escalate to admin in a single request.

---

## Vulnerability 4: Broken Authentication

**OWASP:** API2:2023  
**CVSS 3.1:** 9.1 (Critical)  
**Vector:** AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N

**Description:**  
JWT tokens are signed with HS256 and the literal string `"secret"`. Tokens contain no expiration claim. There is no account lockout mechanism.

**Issues identified:**
1. JWT secret `"secret"` — crackable with hashcat in < 1 second
2. No `exp` claim — tokens valid indefinitely
3. No account lockout — unlimited brute force attempts
4. No refresh token rotation

**CVSS Score justification:** No privileges required to obtain a valid token via brute force.

---

## Vulnerability 5: Lack of Rate Limiting

**OWASP:** API4:2023  
**CVSS 3.1:** 7.5 (High)  
**Vector:** AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

**Description:**  
No rate limiting on any endpoint. Credential stuffing, brute force, and API scraping proceed uninterrupted.

**Brute force test results:** 20 consecutive failed login attempts — HTTP 401 on all, no 429 observed.

---

## Vulnerability 6: Broken Function Level Authorization

**OWASP:** API5:2023  
**CVSS 3.1:** 6.5 (Medium)  
**Vector:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N

**Description:**  
`GET /admin/users` and `GET /admin/audit-logs` return sensitive data to any authenticated user, regardless of role.

**Proof:** User with `role=user` can access `/admin/users` — returns all user records with password hashes.

---

## Risk Summary Table

| Vuln | OWASP | CVSS | Exploitability | Impact |
|---|---|---|---|---|
| BOLA/IDOR | API1:2023 | 8.1 High | Trivial (sequential IDs) | All user data |
| Excessive Exposure | API3:2023 | 7.5 High | Passive (any GET) | PII + hashes |
| Mass Assignment | API6:2023 | 8.8 High | Low effort | Admin escalation |
| Broken Auth | API2:2023 | 9.1 Critical | Low effort | Full account takeover |
| No Rate Limiting | API4:2023 | 7.5 High | Trivial | Brute force enabled |
| Broken Func Auth | API5:2023 | 6.5 Medium | Low effort | Admin data access |

**Overall risk: CRITICAL — Do not expose to internet in current state.**
