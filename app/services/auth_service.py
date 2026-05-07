"""Authentication service — register, login, token management."""
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import MODE, settings
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.schemas.auth import RegisterRequest, TokenResponse
from app.security.jwt_utils import (
    create_access_token,
    create_refresh_token_string,
    hash_token,
)
from app.security.password import hash_password, verify_password


async def register_user(payload: RegisterRequest, db: AsyncSession) -> User:
    # Check uniqueness
    existing = await db.execute(
        select(User).where(
            (User.username == payload.username) | (User.email == payload.email)
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username or email already registered")

    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    await db.flush()  # get the new user.id

    # Assign default 'user' role
    from app.models.role import Role
    from app.models.user_role import UserRole
    role_result = await db.execute(select(Role).where(Role.name == "user"))
    role = role_result.scalar_one_or_none()
    if role:
        db.add(UserRole(user_id=user.id, role_id=role.id))

    return user


async def authenticate_user(username: str, password: str, db: AsyncSession) -> User | None:
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if not user:
        return None

    if not verify_password(password, user.password_hash):
        # Track failed logins
        user.failed_login_count += 1
        await db.flush()
        return None

    # Update login stats
    user.login_count += 1
    user.last_login = datetime.now(timezone.utc)
    user.failed_login_count = 0
    await db.flush()
    return user


async def authenticate_user_with_lockout(
    username: str, password: str, db: AsyncSession
) -> User:
    """Secured mode: locks account after 10 consecutive failures."""
    user = await authenticate_user(username, password, db)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if MODE == "secured" and user.failed_login_count >= 10:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account temporarily locked — too many failed attempts",
        )
    return user


async def create_tokens(user: User, request: Request | None, db: AsyncSession) -> TokenResponse:
    access_token = create_access_token(
        {"sub": str(user.id), "roles": user.role_names, "is_admin": user.is_admin}
    )

    if MODE == "secured":
        raw_refresh = create_refresh_token_string()
        token_hash = hash_token(raw_refresh)
        expires_at = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        rt = RefreshToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=expires_at,
            ip_address=request.client.host if request and request.client else None,
            user_agent=request.headers.get("user-agent") if request else None,
        )
        db.add(rt)
        await db.flush()
        return TokenResponse(
            access_token=access_token,
            refresh_token=raw_refresh,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

    # Vulnerable: no refresh token rotation, return raw token
    return TokenResponse(access_token=access_token)


async def refresh_access_token(raw_refresh: str, db: AsyncSession) -> TokenResponse:
    if MODE != "secured":
        raise HTTPException(status_code=400, detail="Refresh not supported in vulnerable mode")

    token_hash = hash_token(raw_refresh)
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked == False,  # noqa: E712
        )
    )
    rt = result.scalar_one_or_none()
    if rt is None:
        raise HTTPException(status_code=401, detail="Invalid or revoked refresh token")
    if rt.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Refresh token expired")

    # Rotate: revoke old, issue new
    rt.revoked = True
    rt.revoked_at = datetime.now(timezone.utc)

    user = await db.get(User, rt.user_id)
    new_access = create_access_token({"sub": str(user.id), "roles": user.role_names})
    new_raw_refresh = create_refresh_token_string()
    new_rt = RefreshToken(
        user_id=user.id,
        token_hash=hash_token(new_raw_refresh),
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )
    db.add(new_rt)
    return TokenResponse(
        access_token=new_access,
        refresh_token=new_raw_refresh,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


async def revoke_token(raw_refresh: str | None, user_id: int, db: AsyncSession) -> None:
    if raw_refresh:
        token_hash = hash_token(raw_refresh)
        result = await db.execute(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        )
        rt = result.scalar_one_or_none()
        if rt:
            rt.revoked = True
            rt.revoked_at = datetime.now(timezone.utc)
    else:
        # Revoke all tokens for user
        result = await db.execute(
            select(RefreshToken).where(
                RefreshToken.user_id == user_id, RefreshToken.revoked == False  # noqa: E712
            )
        )
        for rt in result.scalars().all():
            rt.revoked = True
            rt.revoked_at = datetime.now(timezone.utc)
