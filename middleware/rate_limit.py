"""
Rate limiting middleware — Redis sliding window algorithm.
Passthrough in vulnerable mode (demonstrating lack of rate limiting).

Limits (secured mode):
  /auth/login  →  5 requests/minute per IP
  /api/*       →  100 requests/minute per IP
  /admin/*     →  10 requests/minute per IP
"""
import json
from typing import Callable

import redis.asyncio as aioredis
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.config import MODE, settings

# Lua script for atomic sliding-window increment
_SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local window = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local min_score = now - window * 1000

redis.call('ZREMRANGEBYSCORE', key, '-inf', min_score)
local count = redis.call('ZCARD', key)
if count < limit then
    redis.call('ZADD', key, now, now .. math.random())
    redis.call('EXPIRE', key, window)
    return count + 1
else
    return -1
end
"""

_LIMITS: dict[str, tuple[int, int]] = {
    "/auth/login": (5, 60),
    "/auth/": (30, 60),
    "/api/": (100, 60),
    "/admin/": (10, 60),
}

_redis_client: aioredis.Redis | None = None


def _get_redis() -> aioredis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis_client


def _get_limit(path: str) -> tuple[int, int] | None:
    for prefix, limits in _LIMITS.items():
        if path.startswith(prefix) or path == prefix.rstrip("/"):
            return limits
    return None


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable):
        if MODE != "secured":
            return await call_next(request)

        limit_config = _get_limit(request.url.path)
        if limit_config is None:
            return await call_next(request)

        limit, window = limit_config
        ip = request.client.host if request.client else "unknown"

        # Allow X-Forwarded-For only for internal proxies in real deployments
        key = f"rl:{ip}:{request.url.path.split('/')[1]}"

        try:
            import time
            redis = _get_redis()
            now_ms = int(time.time() * 1000)
            count = await redis.eval(_SLIDING_WINDOW_LUA, 1, key, window, limit, now_ms)

            if count == -1:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded. Slow down."},
                    headers={
                        "Retry-After": str(window),
                        "X-RateLimit-Limit": str(limit),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Window": f"{window}s",
                    },
                )
        except Exception:
            # Redis unavailable — fail open (log but allow request)
            pass

        return await call_next(request)
