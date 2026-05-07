"""
Object-Level Authorization middleware (SECURED MODE ONLY).

Enforces ownership on resource routes by:
  1. Extracting resource_id from the URL path
  2. Loading the resource owner from the database
  3. Comparing owner to the JWT sub claim
  4. Returning 403 if mismatch (admins bypass)

Routes covered: /api/users/{id}, /api/orders/{id}
"""
import re
from typing import Callable

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.config import MODE

_OWNERSHIP_PATTERNS = [
    (re.compile(r"^/api/orders/(\d+)"), "orders"),
    (re.compile(r"^/api/users/(\d+)"), "users"),
]

_MUTATING_METHODS = {"GET", "PUT", "DELETE", "PATCH"}


class ObjectLevelAuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request, call_next: Callable):
        if MODE != "secured":
            return await call_next(request)

        if request.method not in _MUTATING_METHODS:
            return await call_next(request)

        for pattern, resource in _OWNERSHIP_PATTERNS:
            match = pattern.match(request.url.path)
            if not match:
                continue

            resource_id = int(match.group(1))

            # Extract current user from token
            current_user = await self._extract_user(request)
            if current_user is None:
                # Let the router handle 401
                return await call_next(request)

            # Admins bypass ownership checks
            if current_user.is_admin:
                return await call_next(request)

            owns = await self._check_ownership(current_user.id, resource, resource_id, request)
            if not owns:
                await self._log_violation(request, current_user.id, resource, resource_id)
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Access denied — resource belongs to another user"},
                )

        return await call_next(request)

    async def _extract_user(self, request):
        try:
            from app.models.user import User
            from app.security.jwt_utils import decode_token
            from jose import JWTError

            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return None
            token = auth_header[7:]
            payload = decode_token(token)
            user_id = int(payload.get("sub", 0))

            from app.database import AsyncSessionLocal
            async with AsyncSessionLocal() as db:
                from sqlalchemy.orm import selectinload
                from sqlalchemy import select
                result = await db.execute(
                    select(User).where(User.id == user_id).options(selectinload(User.user_roles))
                )
                return result.scalar_one_or_none()
        except Exception:
            return None

    async def _check_ownership(
        self, user_id: int, resource: str, resource_id: int, request
    ) -> bool:
        try:
            from app.database import AsyncSessionLocal
            async with AsyncSessionLocal() as db:
                if resource == "users":
                    return user_id == resource_id
                elif resource == "orders":
                    from app.models.order import Order
                    order = await db.get(Order, resource_id)
                    return order is not None and order.user_id == user_id
        except Exception:
            return True  # Fail open — let downstream handle
        return False

    async def _log_violation(self, request, user_id: int, resource: str, resource_id: int):
        try:
            from app.database import AsyncSessionLocal
            from app.models.audit_log import AuditLog
            async with AsyncSessionLocal() as db:
                log = AuditLog(
                    user_id=user_id,
                    action="authorization.violation",
                    resource=resource,
                    resource_id=str(resource_id),
                    ip_address=request.client.host if request.client else "unknown",
                    request_method=request.method,
                    request_path=str(request.url.path),
                    response_status=403,
                    details={"violation": "object_level_auth", "attempted_resource_id": resource_id},
                )
                db.add(log)
                await db.commit()
        except Exception:
            pass
