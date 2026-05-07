"""
Auth router — dual-mode implementation.

vulnerable_router:
  - No rate limiting
  - Returns token immediately with no expiration
  - No account lockout
  - Refresh token stored in plaintext

secured_router:
  - Rate limiting applied via middleware
  - RS256 tokens with full claims
  - Account lockout after 10 failures
  - Refresh token rotation
"""
from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user
from app.schemas.auth import LoginRequest, RefreshRequest, RegisterRequest, TokenResponse
from app.schemas.common import SuccessResponse
from app.services import auth_service

vulnerable_router = APIRouter()
secured_router = APIRouter()


# ── Vulnerable ─────────────────────────────────────────────────────────────

@vulnerable_router.post("/register", response_model=TokenResponse)
async def register_vulnerable(payload: RegisterRequest, db: AsyncSession = Depends(get_db)):
    user = await auth_service.register_user(payload, db)
    return await auth_service.create_tokens(user, None, db)


@vulnerable_router.post("/login", response_model=TokenResponse)
async def login_vulnerable(payload: LoginRequest, db: AsyncSession = Depends(get_db)):
    # No rate limiting, no lockout — brute force is trivial
    user = await auth_service.authenticate_user(payload.username, payload.password, db)
    if user is None:
        from fastapi import HTTPException, status
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    return await auth_service.create_tokens(user, None, db)


@vulnerable_router.post("/logout", response_model=SuccessResponse)
async def logout_vulnerable(current_user=Depends(get_current_user)):
    # No token revocation in vulnerable mode
    return SuccessResponse(message="Logged out")


# ── Secured ────────────────────────────────────────────────────────────────

@secured_router.post("/register", response_model=TokenResponse)
async def register_secured(
    payload: RegisterRequest, request: Request, db: AsyncSession = Depends(get_db)
):
    user = await auth_service.register_user(payload, db)
    return await auth_service.create_tokens(user, request, db)


@secured_router.post("/login", response_model=TokenResponse)
async def login_secured(
    payload: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)
):
    # Rate limiting enforced by RateLimitMiddleware + Kong
    user = await auth_service.authenticate_user_with_lockout(payload.username, payload.password, db)
    return await auth_service.create_tokens(user, request, db)


@secured_router.post("/refresh", response_model=TokenResponse)
async def refresh_secured(payload: RefreshRequest, db: AsyncSession = Depends(get_db)):
    return await auth_service.refresh_access_token(payload.refresh_token, db)


@secured_router.post("/logout", response_model=SuccessResponse)
async def logout_secured(
    payload: RefreshRequest | None = None,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    raw_refresh = payload.refresh_token if payload else None
    await auth_service.revoke_token(raw_refresh, current_user.id, db)
    return SuccessResponse(message="Logged out — all sessions revoked")
