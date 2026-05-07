"""
Users router — dual-mode implementation.

BOLA (Broken Object Level Authorization):
  vulnerable_router GET /{user_id}/profile — no ownership check, any user can read any profile
  secured_router GET /{user_id}/profile — ownership enforced, 403 on cross-user access

Mass Assignment:
  vulnerable_router PUT /{user_id} — accepts raw dict, sets is_admin freely
  secured_router PUT /{user_id} — Pydantic allowlist (email, username only)

Excessive Data Exposure:
  vulnerable response schema: UserVulnerable (includes password_hash, is_admin, internal_id)
  secured response schema:    UserPublic (id, username, email, is_active, created_at only)
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user, require_role
from app.schemas.common import SuccessResponse
from app.schemas.user import UserAdmin, UserPublic, UserUpdateSecured, UserVulnerable
from app.services import user_service

vulnerable_router = APIRouter()
secured_router = APIRouter()


# ── Vulnerable ─────────────────────────────────────────────────────────────

@vulnerable_router.get("/{user_id}/profile", response_model=UserVulnerable)
async def get_profile_vulnerable(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    # BOLA: no ownership check — user_id is taken at face value
    # Excessive data exposure: returns password_hash, is_admin, internal_id
    return await user_service.get_user(user_id, db)


@vulnerable_router.put("/{user_id}", response_model=UserVulnerable)
async def update_user_vulnerable(
    user_id: int,
    payload: dict,  # Mass assignment: raw dict, no field validation
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    # Mass assignment: any field accepted including is_admin=true
    return await user_service.update_user_vulnerable(user_id, payload, db)


@vulnerable_router.get("/", response_model=list[UserVulnerable])
async def list_users_vulnerable(
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    # No role check in vulnerable mode
    return await user_service.list_users(db, skip, limit)


@vulnerable_router.delete("/{user_id}", response_model=SuccessResponse)
async def delete_user_vulnerable(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    await user_service.delete_user(user_id, db)
    return SuccessResponse(message=f"User {user_id} deleted")


# ── Secured ────────────────────────────────────────────────────────────────

@secured_router.get("/{user_id}/profile", response_model=UserPublic)
async def get_profile_secured(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    # Ownership enforced: users can only access their own profile (admins excepted)
    if current_user.id != user_id and not current_user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    user = await user_service.get_user(user_id, db)
    return UserPublic.model_validate(user)


@secured_router.put("/{user_id}", response_model=UserPublic)
async def update_user_secured(
    user_id: int,
    payload: UserUpdateSecured,  # Allowlist: only email and username
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("admin")),
):
    user = await user_service.update_user_secured(user_id, payload.email, payload.username, db)
    return UserPublic.model_validate(user)


@secured_router.get("/", response_model=list[UserAdmin])
async def list_users_secured(
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("admin", "manager")),
):
    return await user_service.list_users(db, skip, limit)


@secured_router.delete("/{user_id}", response_model=SuccessResponse)
async def delete_user_secured(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("admin")),
):
    await user_service.delete_user(user_id, db)
    return SuccessResponse(message=f"User {user_id} deleted")
