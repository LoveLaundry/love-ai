"""Hardening middleware for Love AI: rate limiting, security headers, IO audit."""
import os
import re
import time
import hashlib
import ipaddress
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from .config import settings

# A client-supplied correlation id is echoed back in `X-Request-Id`. It is
# attacker-controlled, so it is only trusted when it matches this shape —
# otherwise a caller could inject arbitrary bytes (including CR/LF) into the
# response headers and into whatever logs key off that header.
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

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
        self._last_prune = time.time()

    async def dispatch(self, request: Request, call_next):
        key = _rate_limit_key(request)
        now = time.time()
        window_start = now - 60.0
        # Drop idle keys periodically; otherwise the dict keeps one entry per
        # distinct API key / IP for the process lifetime (unbounded memory growth).
        if now - self._last_prune >= 60.0:
            pruned = {}
            for bucket_key, stamps in self._buckets.items():
                live = [t for t in stamps if t >= window_start]
                if live:
                    pruned[bucket_key] = live
            self._buckets = pruned
            self._last_prune = now
        hits = [t for t in self._buckets.get(key, []) if t >= window_start]
        self._buckets[key] = hits
        if len(hits) >= self.limit:
            retry_after = max(1, int(60.0 - (now - min(hits))))
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Retry shortly."},
                headers={"Retry-After": str(retry_after)},
            )

        self._buckets[key] = [*hits, now]
        return await call_next(request)


def _rate_limit_key(request: Request) -> str:
    """Bucket key: the API key when present, otherwise the caller's address.

    The API key is a shared credential, so its bucket is shared by design; it
    is stored hashed so the secret is not retained in a long-lived structure.
    """
    api_key = request.headers.get("X-API-Key", "").strip()
    if api_key:
        return f"key:{hashlib.sha256(api_key.encode('utf-8')).hexdigest()}"
    return f"ip:{_client_key(request)}"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        # HSTS is only honoured over TLS; sending it on a plain-HTTP response
        # is meaningless and locks out local development behind HTTPS.
        if _is_https(request):
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        response.headers["X-Request-Id"] = _resolve_request_id(request)
        return response


def _is_https(request: Request) -> bool:
    """True when the request reached us over TLS.

    ``X-Forwarded-Proto`` is only consulted because this service is deployed
    behind a TLS-terminating proxy; when it is absent the socket scheme is
    authoritative.
    """
    forwarded = request.headers.get("x-forwarded-proto", "")
    if forwarded:
        return forwarded.split(",")[0].strip().lower() == "https"
    return request.url.scheme == "https"


def _resolve_request_id(request: Request) -> str:
    """Return a safe correlation id for the response.

    A well-formed client value is preserved so a caller can correlate its own
    request with ours; anything else is replaced with a freshly generated id
    instead of being echoed verbatim.
    """
    supplied = request.headers.get("x-request-id", "")
    if supplied and _REQUEST_ID_RE.match(supplied):
        return supplied
    return _generate_req_id()


def _client_key(request: Request) -> str:
    """Return the caller's address.

    Behind the nginx reverse proxy every socket arrives from the proxy's own
    address, so ``request.client.host`` is the SAME value for every visitor —
    which turns the per-IP limit into a global limit and lets one client deny
    service to everybody. The forwarded client address is used instead, but
    only when the direct peer is a local/private address (i.e. a trusted
    reverse proxy). A service exposed directly therefore cannot be tricked
    into spoofing another client's bucket by setting the header itself.
    """
    peer = request.client.host if request.client else None
    if peer and _is_trusted_proxy(peer):
        forwarded = _forwarded_client_ip(request)
        if forwarded:
            return forwarded
    return peer or "unknown"


def _is_trusted_proxy(peer: str) -> bool:
    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        return False
    return address.is_loopback or address.is_private or address.is_link_local


def _forwarded_client_ip(request: Request) -> Optional[str]:
    """Extract the client address a trusted proxy recorded."""
    real_ip = request.headers.get("x-real-ip", "").strip()
    if real_ip:
        return real_ip
    forwarded = request.headers.get("x-forwarded-for", "")
    # nginx appends the address it saw to whatever the caller sent, so the
    # RIGHT-most entry is the one it observed, not a client-supplied one.
    for candidate in reversed([part.strip() for part in forwarded.split(",")]):
        if candidate:
            return candidate
    return None


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
    # CORS is added last so it is outermost; see note in the other services.
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware, requests_per_minute=settings.rate_limit_per_minute)
    app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False, allow_methods=["GET", "POST"], allow_headers=["*"])