"""
Authentication for Love AI.

Every request must present a hashed API key (`X-API-Key`). Optionally, a
request signature (`X-Timestamp`, `X-Body-Hash`, `X-Signature`) proves both
the caller's identity and the integrity of the request (no tampering, no
replay beyond the TTL window). An optional JWT (`Authorization: Bearer`)
attributes the call to a signed-in user-service user for audit.
"""
import time

import jwt
from fastapi import Depends, Header, HTTPException, Request, Security, status
from fastapi.security import HTTPBearer

from .config import settings
from .crypto_helper import constant_time_equal, hash_api_key, verify_request_signature

security = HTTPBearer(auto_error=False)


def _api_key_hashes() -> list[str]:
    return [hash_api_key(k) for k in settings.ai_api_keys_raw]


def verify_api_key(
    x_api_key: str | None = Header(None, alias="X-API-Key"),
) -> str:
    """Validate the API key header in constant time against stored hashes."""
    if not x_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing X-API-Key header")
    provided_hash = hash_api_key(x_api_key)
    for stored_hash in _api_key_hashes():
        if constant_time_equal(provided_hash, stored_hash):
            return x_api_key
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")


def require_request_signature(api_key: str = Depends(verify_api_key)) -> dict:
    """Alias of the API-key guard (legacy name)."""
    return {"api_key": api_key}


async def verify_signed_request(
    request: Request,
    credentials=Security(security),
    x_api_key: str | None = Header(None, alias="X-API-Key"),
    x_timestamp: str | None = Header(None, alias="X-Timestamp"),
    x_body_hash: str | None = Header(None, alias="X-Body-Hash"),
    x_signature: str | None = Header(None, alias="X-Signature"),
) -> dict:
    """Authenticate either a privileged user session or an internal signer.

    Browser/mobile clients use the user JWT and never receive an AI API key.
    API-key/HMAC authentication remains available only for explicit internal
    service callers that provide the complete signature set.
    """
    if credentials and credentials.credentials:
        if not settings.jwt_secret:
            raise HTTPException(status_code=503, detail="User authentication is not configured")
        try:
            user = jwt.decode(credentials.credentials, settings.jwt_secret, algorithms=["HS256"])
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid authentication token")
        role = str(user.get("role") or user.get("role_id") or "").upper()
        if role not in {"ADMIN", "MANAGER"}:
            raise HTTPException(status_code=403, detail="Insufficient privileges")
        return {"user": user, "auth_mode": "user"}

    if not x_api_key:
        raise HTTPException(status_code=401, detail="Authentication required")
    api_key = verify_api_key(x_api_key)
    if not x_timestamp or not x_body_hash or not x_signature:
        raise HTTPException(status_code=401, detail="Missing signature headers")

    try:
        ts = int(x_timestamp)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid X-Timestamp")

    now = int(time.time())
    if abs(now - ts) > settings.signature_ttl_seconds:
        raise HTTPException(status_code=401, detail="Request signature expired")

    body = await request.body()
    if not constant_time_equal(_hex(body), x_body_hash):
        raise HTTPException(status_code=401, detail="Body hash mismatch")

    signed_path = request.url.path
    if request.url.query:
        signed_path = f"{signed_path}?{request.url.query}"
    if not verify_request_signature(api_key, request.method, signed_path, x_timestamp, x_body_hash, x_signature):
        raise HTTPException(status_code=401, detail="Invalid request signature")
    return {"api_key": api_key, "auth_mode": "service", "path": signed_path, "timestamp": ts}


def _hex(data: bytes) -> str:
    from .crypto_helper import sha256_hex
    return sha256_hex(data)


def optional_current_user(credentials=Security(security)) -> dict | None:
    """Resolve a user-service JWT into a payload for audit attribution, if attached."""
    if not credentials or not credentials.credentials:
        return None
    if not settings.jwt_secret:
        return None
    try:
        return jwt.decode(credentials.credentials, settings.jwt_secret, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return None