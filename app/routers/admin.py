"""
Admin router — dual-mode.

Vulnerable: no role enforcement; password_hash and internal fields returned.
Secured:    admin role required; sensitive fields stripped.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user, require_role
from app.schemas.user import UserAdmin, UserVulnerable
from app.services import admin_service

vulnerable_router = APIRouter()
secured_router = APIRouter()


# ── Vulnerable ─────────────────────────────────────────────────────────────

@vulnerable_router.get("/users", response_model=list[UserVulnerable])
async def list_users_admin_vulnerable(
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),  # no role check
):
    return await admin_service.list_all_users(db, skip, limit)


@vulnerable_router.get("/audit-logs")
async def get_audit_logs_vulnerable(
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),  # no role check
):
    logs = await admin_service.list_audit_logs(db, skip, limit)
    return [
        {
            "id": l.id,
            "user_id": l.user_id,
            "action": l.action,
            "resource": l.resource,
            "ip_address": l.ip_address,
            "request_path": l.request_path,
            "response_status": l.response_status,
            "details": l.details,
            "timestamp": l.timestamp,
        }
        for l in logs
    ]


@vulnerable_router.get("/stats")
async def get_stats_vulnerable(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return await admin_service.get_stats(db)


# ── Secured ────────────────────────────────────────────────────────────────

@secured_router.get("/users", response_model=list[UserAdmin])
async def list_users_admin_secured(
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("admin")),
):
    return await admin_service.list_all_users(db, skip, limit)


@secured_router.get("/audit-logs")
async def get_audit_logs_secured(
    skip: int = 0,
    limit: int = 100,
    user_id: int | None = None,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("admin")),
):
    logs = await admin_service.list_audit_logs(db, skip, limit, user_id)
    return [
        {
            "id": l.id,
            "user_id": l.user_id,
            "action": l.action,
            "resource": l.resource,
            "ip_address": l.ip_address,
            "request_path": l.request_path,
            "response_status": l.response_status,
            "timestamp": l.timestamp,
        }
        for l in logs
    ]


@secured_router.get("/stats")
async def get_stats_secured(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_role("admin", "manager")),
):
    return await admin_service.get_stats(db)
