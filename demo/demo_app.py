"""
API Security Lab — Standalone Demo (with Interactive UI)
=========================================================
Start: APP_MODE=vulnerable uvicorn demo.demo_app:app --port 8001 --reload
UI:   http://localhost:8001/
Docs: http://localhost:8001/docs
"""
import base64
import hashlib
import json
import os
import time
import uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Integer, Numeric,
    String, Text, create_engine
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

# ── Mutable app state (allows live mode switching from UI) ────────────────────
class AppState:
    def __init__(self):
        self.mode = os.getenv("APP_MODE", "vulnerable")

state = AppState()

JWT_SECRET = "secret"
JWT_ALGORITHM = "HS256"
DB_URL = "sqlite:///./demo_lab.db"

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)

# ── In-memory rate limiter ────────────────────────────────────────────────────
_rate_windows: dict[str, list[float]] = defaultdict(list)
RATE_LIMITS = {"/auth/login": 5, "/api/": 30, "/admin/": 10}

def check_rate_limit(ip: str, path: str) -> tuple[bool, int, int]:
    now = time.time()
    prefix, limit = "/", 100
    for key, lim in RATE_LIMITS.items():
        if path.startswith(key):
            prefix, limit = key, lim
            break
    bk = f"{ip}:{prefix}"
    _rate_windows[bk] = [t for t in _rate_windows[bk] if now - t < 60]
    current = len(_rate_windows[bk])
    if current >= limit:
        return False, limit, 0
    _rate_windows[bk].append(now)
    return True, limit, limit - current - 1

def reset_rate_limits():
    _rate_windows.clear()

# ── Database ──────────────────────────────────────────────────────────────────
engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    internal_id = Column(String(36), default=lambda: str(uuid.uuid4()), unique=True)
    username = Column(String(50), unique=True, index=True)
    email = Column(String(100), unique=True)
    password_hash = Column(String(200))
    is_admin = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    role = Column(String(20), default="user")
    login_count = Column(Integer, default=0)
    failed_login_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class Product(Base):
    __tablename__ = "products"
    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String(36), default=lambda: str(uuid.uuid4()), unique=True)
    name = Column(String(100))
    description = Column(Text)
    price = Column(Numeric(10, 2))
    internal_cost = Column(Numeric(10, 2))
    sku = Column(String(50), unique=True)
    stock = Column(Integer, default=0)

class Order(Base):
    __tablename__ = "orders"
    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String(36), default=lambda: str(uuid.uuid4()), unique=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    status = Column(String(20), default="pending")
    total = Column(Numeric(10, 2), default=0)
    shipping_street = Column(String(200))
    shipping_city = Column(String(100))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True)
    action = Column(String(100))
    ip_address = Column(String(50))
    path = Column(String(200))
    detail = Column(Text)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def seed_database(db: Session):
    if db.query(User).count() > 0:
        # Always ensure the demo attacker account is reset to a clean state
        attacker = db.query(User).filter(User.username == "attacker_demo").first()
        if attacker:
            attacker.is_admin = False
            attacker.role = "user"
            attacker.email = "attacker_demo@evil.com"
            db.commit()
        return
    for i in range(1, 16):
        role = "user"
        is_admin = False
        if i in (11, 12, 13): role = "manager"
        elif i in (14, 15): role, is_admin = "admin", True
        db.add(User(
            username=f"user{i}", email=f"user{i}@lab.local",
            password_hash=pwd_ctx.hash(f"password{i}"),
            is_admin=is_admin, role=role,
        ))
    # Dedicated demo attacker account — always starts as non-admin
    db.add(User(
        username="attacker_demo",
        email="attacker_demo@evil.com",
        password_hash=pwd_ctx.hash("hacked123"),
        is_admin=False, role="user",
    ))
    db.flush()
    for i in range(1, 21):
        db.add(Product(
            name=f"Product {i}", description=f"Demo product #{i}",
            price=round(9.99 + i * 5, 2), internal_cost=round(2.50 + i * 1.5, 2),
            sku=f"SKU-{i:04d}", stock=100,
        ))
    db.flush()
    for uid in range(1, 11):
        for _ in range(2):
            db.add(Order(
                user_id=uid, total=round(49.99 + uid * 10, 2),
                shipping_street=f"{uid * 10} Demo Lane", shipping_city="Testville",
            ))
    db.commit()

# ── JWT ───────────────────────────────────────────────────────────────────────
def create_token(user: User) -> str:
    data: dict[str, Any] = {"sub": str(user.id), "username": user.username, "role": user.role}
    if state.mode == "secured":
        from datetime import timedelta
        data.update({
            "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
            "iss": "api-security-lab",
            "aud": "api-security-lab-users",
            "iat": datetime.now(timezone.utc),
        })
    return jwt.encode(data, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_token(token: str) -> dict:
    kwargs: dict[str, Any] = {"algorithms": [JWT_ALGORITHM]}
    if state.mode == "vulnerable":
        kwargs["options"] = {"verify_exp": False, "verify_aud": False, "verify_iss": False}
    else:
        kwargs["audience"] = "api-security-lab-users"
        kwargs["issuer"] = "api-security-lab"
    return jwt.decode(token, JWT_SECRET, **kwargs)

def get_current_user(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    if not creds:
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = creds.credentials
    if state.mode == "vulnerable":
        parts = token.split(".")
        if len(parts) == 3 and parts[2] == "":
            try:
                pad = lambda s: s + "=" * (-len(s) % 4)
                payload = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
                user = db.query(User).filter(User.id == int(payload.get("sub", 0))).first()
                if user: return user
            except Exception:
                pass
    try:
        payload = decode_token(token)
    except JWTError as exc:
        raise HTTPException(status_code=401, detail=f"Invalid token: {exc}")
    user = db.query(User).filter(User.id == int(payload.get("sub", 0))).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

def _client_ip(request: Request) -> str:
    fwd = request.headers.get("X-Forwarded-For")
    if fwd: return fwd.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"

# ── App ───────────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    seed_database(db)
    db.close()
    yield

app = FastAPI(
    title="API Security Lab",
    description="OWASP API Top 10 demonstration lab",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def audit_and_rate_limit(request: Request, call_next):
    ip = _client_ip(request)
    path = request.url.path
    if state.mode == "secured" and not path.startswith("/demo/"):
        allowed, limit, remaining = check_rate_limit(ip, path)
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded", "retry_after": 60},
                headers={"Retry-After": "60", "X-RateLimit-Limit": str(limit), "X-RateLimit-Remaining": "0"},
            )
    response = await call_next(request)
    db = SessionLocal()
    try:
        db.add(AuditLog(action=f"{request.method} {response.status_code}", ip_address=ip, path=path, detail=f"status={response.status_code}"))
        db.commit()
    except Exception:
        pass
    finally:
        db.close()
    response.headers["X-Mode"] = state.mode
    return response

# ── Schemas ───────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str

class UserUpdateSecured(BaseModel):
    email: Optional[str] = None
    username: Optional[str] = None

# ══════════════════════════════════════════════════════════════════════════════
# CORE API ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def serve_ui():
    ui_path = os.path.join(os.path.dirname(__file__), "ui.html")
    if os.path.exists(ui_path):
        with open(ui_path, encoding="utf-8") as f:
            return HTMLResponse(f.read())
    return HTMLResponse("<h1>UI not found — place ui.html in demo/ folder</h1>")

@app.get("/health")
def health():
    return {"status": "ok", "mode": state.mode, "vulnerabilities_active": state.mode == "vulnerable", "protections_active": state.mode == "secured"}

@app.post("/auth/login", tags=["Auth"])
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not pwd_ctx.verify(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user.login_count += 1
    db.commit()
    return {"access_token": create_token(user), "token_type": "bearer", "mode": state.mode}

@app.post("/auth/register", tags=["Auth"])
def register(payload: LoginRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    user = User(username=payload.username, email=f"{payload.username}@demo.local", password_hash=pwd_ctx.hash(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"id": user.id, "username": user.username}

@app.get("/api/users/", tags=["Users"])
def list_users(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    users = db.query(User).all()
    if state.mode == "vulnerable":
        return [{"id": u.id, "username": u.username, "email": u.email, "password_hash": u.password_hash, "is_admin": u.is_admin, "internal_id": u.internal_id, "role": u.role, "login_count": u.login_count, "failed_login_count": u.failed_login_count} for u in users]
    return [{"id": u.id, "username": u.username, "email": u.email, "is_active": u.is_active} for u in users]

@app.get("/api/users/{user_id}", tags=["Users"])
def get_user(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if state.mode == "secured" and current_user.id != user_id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Access forbidden")
    user = db.query(User).filter(User.id == user_id).first()
    if not user: raise HTTPException(status_code=404, detail="User not found")
    if state.mode == "vulnerable":
        return {"id": user.id, "username": user.username, "email": user.email, "password_hash": user.password_hash, "is_admin": user.is_admin, "internal_id": user.internal_id, "role": user.role, "login_count": user.login_count}
    return {"id": user.id, "username": user.username, "email": user.email, "is_active": user.is_active}

@app.put("/api/users/{user_id}/update", tags=["Users"])
async def update_user(user_id: int, request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    body: dict = await request.json()
    user = db.query(User).filter(User.id == user_id).first()
    if not user: raise HTTPException(status_code=404, detail="User not found")
    if state.mode == "vulnerable":
        allowed_cols = {c.name for c in User.__table__.columns} - {"id", "internal_id", "password_hash", "created_at"}
        changed = {}
        for field, value in body.items():
            if field in allowed_cols:
                setattr(user, field, value)
                changed[field] = value
        db.commit()
        db.refresh(user)
        return {"message": "Updated", "changed_fields": changed, "is_admin_now": user.is_admin, "role_now": user.role}
    allowed = UserUpdateSecured(**body)
    if allowed.email: user.email = allowed.email
    if allowed.username: user.username = allowed.username
    db.commit()
    db.refresh(user)
    return {"message": "Updated (secured)", "id": user.id, "username": user.username, "email": user.email}

@app.get("/api/products/", tags=["Products"])
def list_products(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    products = db.query(Product).all()
    if state.mode == "vulnerable":
        return [{"id": p.id, "name": p.name, "price": float(p.price), "internal_cost": float(p.internal_cost), "sku": p.sku} for p in products]
    return [{"id": p.uuid, "name": p.name, "price": float(p.price), "sku": p.sku} for p in products]

@app.get("/api/products/{product_id}", tags=["Products"])
def get_product(product_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if state.mode == "vulnerable":
        try: product = db.query(Product).filter(Product.id == int(product_id)).first()
        except ValueError: raise HTTPException(status_code=400, detail="Integer ID required")
    else:
        product = db.query(Product).filter(Product.uuid == product_id).first()
    if not product: raise HTTPException(status_code=404, detail="Product not found")
    if state.mode == "vulnerable":
        return {"id": product.id, "name": product.name, "price": float(product.price), "internal_cost": float(product.internal_cost), "sku": product.sku}
    return {"id": product.uuid, "name": product.name, "price": float(product.price)}

@app.get("/api/orders/", tags=["Orders"])
def list_orders(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    orders = db.query(Order).filter(Order.user_id == current_user.id).all() if state.mode == "secured" else db.query(Order).all()
    return [{"id": o.id, "user_id": o.user_id, "status": o.status, "total": float(o.total)} for o in orders]

@app.get("/api/orders/{order_id}", tags=["Orders"])
def get_order(order_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    order = db.query(Order).filter(Order.id == order_id).first()
    if not order: raise HTTPException(status_code=404, detail="Not found")
    if state.mode == "secured" and order.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Access forbidden")
    return {"id": order.id, "user_id": order.user_id, "status": order.status, "total": float(order.total), "shipping_street": order.shipping_street, "shipping_city": order.shipping_city}

@app.get("/admin/users", tags=["Admin"])
def admin_list_users(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    users = db.query(User).all()
    if state.mode == "vulnerable":
        return [{"id": u.id, "username": u.username, "email": u.email, "password_hash": u.password_hash, "is_admin": u.is_admin, "internal_id": u.internal_id, "login_count": u.login_count} for u in users]
    return [{"id": u.id, "username": u.username, "email": u.email, "role": u.role, "is_active": u.is_active} for u in users]

@app.get("/admin/stats", tags=["Admin"])
def admin_stats(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    return {"total_users": db.query(User).count(), "total_products": db.query(Product).count(), "total_orders": db.query(Order).count(), "mode": state.mode}

@app.get("/admin/audit-logs", tags=["Admin"])
def admin_audit_logs(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    logs = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(50).all()
    return [{"id": l.id, "action": l.action, "ip": l.ip_address, "path": l.path, "at": str(l.created_at)} for l in logs]

# ══════════════════════════════════════════════════════════════════════════════
# DEMO ENDPOINTS — structured results for the interactive UI
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/demo/switch/{new_mode}", tags=["Demo"])
def switch_mode(new_mode: str):
    if new_mode not in ("vulnerable", "secured"):
        raise HTTPException(status_code=400, detail="Mode must be 'vulnerable' or 'secured'")
    state.mode = new_mode
    reset_rate_limits()
    return {"mode": state.mode, "message": f"Switched to {new_mode} mode", "vulnerabilities_active": new_mode == "vulnerable"}

@app.get("/demo/stats", tags=["Demo"])
def demo_stats(db: Session = Depends(get_db)):
    return {
        "mode": state.mode,
        "total_users": db.query(User).count(),
        "total_products": db.query(Product).count(),
        "total_orders": db.query(Order).count(),
        "audit_events": db.query(AuditLog).count(),
        "vulnerabilities_active": state.mode == "vulnerable",
    }

@app.post("/demo/bola", tags=["Demo"])
def demo_bola(db: Session = Depends(get_db)):
    """Run BOLA enumeration attack — enumerate all 15 users as user1."""
    user1 = db.query(User).filter(User.username == "user1").first()
    if not user1:
        raise HTTPException(status_code=500, detail="Seed data missing")
    token = create_token(user1)
    results = []
    for uid in range(1, 16):
        target = db.query(User).filter(User.id == uid).first()
        if not target:
            results.append({"id": uid, "status": 404, "blocked": True, "data": {}})
            continue
        blocked = state.mode == "secured" and uid != user1.id and not user1.is_admin
        if blocked:
            results.append({"id": uid, "status": 403, "blocked": True, "username": None, "hash_leaked": False, "admin_leaked": False, "data": {}})
        else:
            data = {"username": target.username, "email": target.email}
            hash_leaked = False
            admin_leaked = False
            if state.mode == "vulnerable":
                data["password_hash"] = target.password_hash[:20] + "..."
                data["is_admin"] = target.is_admin
                data["internal_id"] = target.internal_id
                hash_leaked = True
                admin_leaked = True
            results.append({"id": uid, "status": 200, "blocked": False, "username": target.username, "hash_leaked": hash_leaked, "admin_leaked": admin_leaked, "data": data})
    exposed = sum(1 for r in results if not r["blocked"] and r["id"] != 1)
    return {
        "attack": "bola", "mode": state.mode,
        "results": results,
        "summary": {"exposed": exposed + 1, "blocked": sum(1 for r in results if r["blocked"]), "vulnerable": state.mode == "vulnerable"},
        "owasp": "API1:2023", "cvss": "8.1 HIGH",
    }

@app.post("/demo/mass-assignment", tags=["Demo"])
def demo_mass_assignment(db: Session = Depends(get_db)):
    """Run mass assignment attack using the seeded attacker_demo account."""
    # Always reset the attacker account to clean state before each demo run
    user = db.query(User).filter(User.username == "attacker_demo").first()
    if not user:
        # Create it if missing (e.g. DB was wiped and re-seeded without restart)
        user = User(
            username="attacker_demo",
            email="attacker_demo@evil.com",
            password_hash=pwd_ctx.hash("hacked123"),
            is_admin=False, role="user",
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        # Reset to non-admin state so the demo is repeatable
        user.is_admin = False
        user.role = "user"
        user.email = "attacker_demo@evil.com"
        db.commit()
        db.refresh(user)

    before = {"is_admin": user.is_admin, "role": user.role}
    payload = {"email": "hacked@evil.com", "is_admin": True, "role": "admin"}

    if state.mode == "vulnerable":
        # Mass assignment: any field in the payload is applied directly to the ORM
        allowed_cols = {c.name for c in User.__table__.columns} - {"id", "internal_id", "password_hash", "created_at"}
        for field, value in payload.items():
            if field in allowed_cols:
                setattr(user, field, value)
        db.commit()
        db.refresh(user)
        after = {"is_admin": user.is_admin, "role": user.role}
        escalated = user.is_admin is True
    else:
        # Secured: strict Pydantic schema — only email and username accepted
        allowed = UserUpdateSecured(**payload)
        if allowed.email:
            user.email = allowed.email
        if allowed.username:
            user.username = allowed.username
        db.commit()
        db.refresh(user)
        after = {"is_admin": user.is_admin, "role": user.role}
        escalated = False

    return {
        "attack": "mass_assignment", "mode": state.mode,
        "payload": payload, "before": before, "after": after,
        "escalated": escalated, "vulnerable": escalated,
        "owasp": "API3:2023", "cvss": "7.5 HIGH",
    }

@app.get("/demo/data-exposure", tags=["Demo"])
def demo_data_exposure(db: Session = Depends(get_db)):
    """Audit which sensitive fields are returned in API responses."""
    user1 = db.query(User).filter(User.username == "user1").first()
    product1 = db.query(Product).filter(Product.id == 1).first()
    sensitive = ["password_hash", "internal_id", "is_admin", "login_count", "failed_login_count", "internal_cost"]
    results = []
    if user1:
        if state.mode == "vulnerable":
            data = {"id": user1.id, "username": user1.username, "email": user1.email, "password_hash": user1.password_hash[:20] + "...", "is_admin": user1.is_admin, "internal_id": user1.internal_id, "login_count": user1.login_count, "failed_login_count": user1.failed_login_count}
        else:
            data = {"id": user1.id, "username": user1.username, "email": user1.email, "is_active": user1.is_active}
        exposed_fields = [f for f in sensitive if f in data and f != "internal_cost"]
        results.append({"endpoint": "GET /api/users/1", "exposed_fields": exposed_fields, "safe": len(exposed_fields) == 0, "data": data})
    if product1:
        if state.mode == "vulnerable":
            data = {"id": product1.id, "name": product1.name, "price": float(product1.price), "internal_cost": float(product1.internal_cost), "sku": product1.sku}
        else:
            data = {"id": product1.uuid, "name": product1.name, "price": float(product1.price)}
        exposed_fields = [f for f in sensitive if f in data]
        results.append({"endpoint": "GET /api/products/1", "exposed_fields": exposed_fields, "safe": len(exposed_fields) == 0, "data": data})
    total_exposed = sum(len(r["exposed_fields"]) for r in results)
    return {
        "attack": "data_exposure", "mode": state.mode,
        "results": results, "total_exposed_fields": total_exposed,
        "vulnerable": total_exposed > 0,
        "owasp": "API3:2023", "cvss": "7.5 HIGH",
    }

@app.post("/demo/jwt", tags=["Demo"])
def demo_jwt_attacks(db: Session = Depends(get_db)):
    """Run all 3 JWT attacks and return structured results."""
    results = []
    user1 = db.query(User).filter(User.username == "user1").first()
    if not user1:
        raise HTTPException(status_code=500, detail="Seed data missing")

    # Attack 1: none-alg
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    payload_b = base64.urlsafe_b64encode(b'{"sub":"14","role":"admin","is_admin":true}').rstrip(b"=").decode()
    none_token = f"{header}.{payload_b}."
    none_works = False
    if state.mode == "vulnerable":
        parts = none_token.split(".")
        try:
            pad = lambda s: s + "=" * (-len(s) % 4)
            pl = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
            u = db.query(User).filter(User.id == int(pl.get("sub", 0))).first()
            none_works = u is not None
        except Exception:
            none_works = False
    results.append({"attack": "none-algorithm", "description": "Token with alg=none, no signature", "token_preview": none_token[:50] + "...", "accepted": none_works, "status_code": 200 if none_works else 401})

    # Attack 2: expired token
    expired_payload = {"sub": str(user1.id), "role": "user", "exp": int(time.time()) - 3600}
    expired_token = jwt.encode(expired_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    expired_works = False
    if state.mode == "vulnerable":
        try:
            jwt.decode(expired_token, JWT_SECRET, algorithms=[JWT_ALGORITHM], options={"verify_exp": False, "verify_aud": False})
            expired_works = True
        except Exception:
            expired_works = False
    results.append({"attack": "expired-token", "description": "Token with exp set 1 hour in the past", "token_preview": expired_token[:50] + "...", "accepted": expired_works, "status_code": 200 if expired_works else 401})

    # Attack 3: tampered role
    tampered = jwt.encode({"sub": str(user1.id), "role": "admin", "is_admin": True}, "wrong_secret", algorithm=JWT_ALGORITHM)
    tampered_works = False  # always fails (wrong secret)
    results.append({"attack": "role-tamper", "description": "Payload tampered to role=admin with wrong secret", "token_preview": tampered[:50] + "...", "accepted": tampered_works, "status_code": 401})

    bypassed = sum(1 for r in results if r["accepted"])
    return {
        "attack": "jwt", "mode": state.mode,
        "results": results, "bypassed": bypassed, "total": len(results),
        "vulnerable": bypassed > 0,
        "owasp": "API2:2023", "cvss": "9.8 CRITICAL",
    }

@app.post("/demo/rate-limit", tags=["Demo"])
def demo_rate_limit(db: Session = Depends(get_db)):
    """Simulate 10 brute-force login attempts and return results."""
    results = []
    hit_limit_at = None
    for i in range(1, 11):
        allowed = True
        status_code = 401
        note = "Invalid credentials (no rate limit)"
        if state.mode == "secured":
            allowed, limit, remaining = check_rate_limit("demo-attacker", "/auth/login")
            if not allowed:
                status_code = 429
                note = "Rate limited (429)"
                if hit_limit_at is None:
                    hit_limit_at = i
            else:
                note = f"Allowed ({remaining} remaining)"
        results.append({"attempt": i, "password": f"wrong{i}", "status_code": status_code, "allowed": status_code != 429})
    reset_rate_limits()  # clean up so UI can rerun
    blocked_count = sum(1 for r in results if r["status_code"] == 429)
    return {
        "attack": "rate_limit", "mode": state.mode,
        "results": results,
        "hit_limit_at": hit_limit_at,
        "blocked_count": blocked_count,
        "vulnerable": hit_limit_at is None,
        "owasp": "API4:2023", "cvss": "7.5 HIGH",
    }
