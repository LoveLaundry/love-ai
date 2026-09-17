"""Hardening middleware for Love AI: rate limiting, security headers, IO audit."""
import os
import time

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from .config import settings

_ACCESS_LOG = None  # populated lazily to avoid import cycles


def _access_log_model():
    global _ACCESS_LOG
    if _ACCESS_LOG is None:
        from pydantic import BaseModel

        class AccessLog(BaseModel):
            user_id: str | None = None
            action: str = "ai_access"
            entity_type: str = "ai_request"
            entity_id: str | None = None
            details: dict = {}

        _ACCESS_LOG = AccessLog
    return _ACCESS_LOG


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Sliding-window token bucket keyed by API key (or client IP).
    In-memory only — suitable for single-instance serverless scale-out.
    """

    def __init__(self, app, requests_per_minute: int = 120):
        super().__init__(app)
        self.limit = requests_per_minute
        self._buckets: dict[str, list[float]] = {}

    async def dispatch(self, request: Request, call_next):
        key = request.headers.get("X-API-Key") or (request.client.host if request.client else "unknown")
        now = time.time()
        window_start = now - 60.0
        hits = [t for t in self._buckets.get(key, []) if t >= window_start]
        self._buckets[key] = hits
        if len(hits) >= self.limit:
            return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded. Retry shortly."})

        self._buckets[key] = [*hits, now]
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Request-Id"] = request.headers.get("X-Request-Id") or _generate_req_id()
        return response


def _generate_req_id() -> str:
    import hashlib
    import uuid
    return hashlib.sha256(uuid.uuid4().bytes).hexdigest()[:16]


async def audit_access(
    user_id: str | None,
    action: str,
    entity_id: str | None,
    details: dict | None = None,
) -> None:
    """Write an AI access audit entry into the shared audit_logs collection."""
    try:
        from .database import audit_logs_collection
        from datetime import datetime, timezone

        await audit_logs_collection().insert_one({
            "user_id": user_id or "",
            "action": action,
            "entity_type": "ai_request",
            "entity_id": entity_id,
            "details": details or {},
            "created_at": datetime.now(timezone.utc),
        })
    except Exception:
        pass


def setup_security(app: FastAPI) -> None:
    from fastapi.middleware.cors import CORSMiddleware

    origins = settings.cors_origins
    app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False, allow_methods=["GET", "POST"], allow_headers=["*"])
    app.add_middleware(RateLimitMiddleware, requests_per_minute=settings.rate_limit_per_minute)
    app.add_middleware(SecurityHeadersMiddleware)