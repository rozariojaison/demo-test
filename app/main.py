"""
FastAPI application factory.
Router and middleware registration is gated by APP_MODE.
"""
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import MODE, settings

logging.basicConfig(level=settings.LOG_LEVEL)
logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_TITLE,
        version=settings.APP_VERSION,
        description=(
            "API Security Testing & Rate-Limiting Defence Lab\n\n"
            f"**Current mode: `{MODE}`**\n\n"
            "Switch modes via `APP_MODE=vulnerable|secured` environment variable."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # ── CORS (permissive for lab purposes) ────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Middleware stack (secured mode only) ──────────────────────────────────
    if MODE == "secured":
        from middleware.rate_limit import RateLimitMiddleware
        from middleware.authorization import ObjectLevelAuthMiddleware
        app.add_middleware(RateLimitMiddleware)
        app.add_middleware(ObjectLevelAuthMiddleware)

    # Audit middleware active in both modes
    from middleware.audit import AuditMiddleware
    app.add_middleware(AuditMiddleware)

    # ── Routers ───────────────────────────────────────────────────────────────
    from app.routers import auth, users, products, orders, admin

    if MODE == "secured":
        app.include_router(auth.secured_router, prefix="/auth", tags=["Authentication"])
        app.include_router(users.secured_router, prefix="/api/users", tags=["Users"])
        app.include_router(products.secured_router, prefix="/api/products", tags=["Products"])
        app.include_router(orders.secured_router, prefix="/api/orders", tags=["Orders"])
        app.include_router(admin.secured_router, prefix="/admin", tags=["Admin"])
    else:
        app.include_router(auth.vulnerable_router, prefix="/auth", tags=["Authentication"])
        app.include_router(users.vulnerable_router, prefix="/api/users", tags=["Users"])
        app.include_router(products.vulnerable_router, prefix="/api/products", tags=["Products"])
        app.include_router(orders.vulnerable_router, prefix="/api/orders", tags=["Orders"])
        app.include_router(admin.vulnerable_router, prefix="/admin", tags=["Admin"])

    # ── Health & info ─────────────────────────────────────────────────────────
    @app.get("/health", tags=["System"])
    async def health():
        return {"status": "ok", "mode": MODE, "version": settings.APP_VERSION}

    @app.get("/", tags=["System"])
    async def root():
        return {
            "name": settings.APP_TITLE,
            "version": settings.APP_VERSION,
            "mode": MODE,
            "docs": "/docs",
            "warning": (
                "VULNERABLE MODE — for educational purposes only. "
                "Do NOT deploy on public networks."
            ) if MODE == "vulnerable" else "Secured mode active.",
        }

    logger.info("API Security Lab started in [%s] mode", MODE.upper())
    return app


app = create_app()
