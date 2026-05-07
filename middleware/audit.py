"""
Audit middleware — logs every request/response to audit_logs table.
Active in both modes; provides visibility into all API activity.
"""
import time
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp


class AuditMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start = time.time()
        response = await call_next(request)
        duration_ms = int((time.time() - start) * 1000)

        # Skip health/docs endpoints to keep audit log clean
        skip_paths = {"/health", "/docs", "/redoc", "/openapi.json", "/"}
        if request.url.path in skip_paths:
            return response

        # Extract user_id from request state (set by get_current_user if called)
        user_id: int | None = getattr(request.state, "user_id", None)

        ip = request.client.host if request.client else "unknown"
        # Respect X-Forwarded-For in secured mode (note: validate in production)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            ip = forwarded.split(",")[0].strip()

        try:
            from app.database import AsyncSessionLocal
            from app.models.audit_log import AuditLog

            async with AsyncSessionLocal() as db:
                log = AuditLog(
                    user_id=user_id,
                    action=f"{request.method.lower()}.{request.url.path.split('/')[1] if '/' in request.url.path else 'root'}",
                    resource=request.url.path.split("/")[2] if request.url.path.count("/") >= 2 else "root",
                    ip_address=ip,
                    user_agent=request.headers.get("user-agent"),
                    request_method=request.method,
                    request_path=str(request.url.path),
                    response_status=response.status_code,
                    details={"duration_ms": duration_ms, "query": str(request.url.query) or None},
                )
                db.add(log)
                await db.commit()
        except Exception:
            # Never let audit failures break the request
            pass

        return response
