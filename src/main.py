"""Love AI — analytics & insights service for Love Laundry.

Secure service design:
  • Requests must present an API key (verified in constant time against an
    HMAC-SHA256 hash — plaintext keys are never persisted).
  • All insight routes require an HMAC request signature (X-Timestamp,
    X-Body-Hash, X-Signature) which binds caller identity + payload +
    timestamp, rejecting tampered or replayed requests.
  • Responses carry a SHA-256 data hash so clients can verify integrity.
  • PII is read at rest as AES-256-GCM envelope-encrypted data using the
    same MASTER_KEY as laundry-management.
  • Rate limiting, strict CORS, and security headers are applied globally.
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .config import settings
from .routers import insights
from .security import setup_security

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("love-ai")


@asynccontextmanager
async def lifespan(app: FastAPI):
    from .database import ping

    ok = await ping()
    if ok:
        logger.info("MongoDB connected (main database)")
    else:
        logger.warning("MongoDB not reachable at startup (will retry on demand)")
    yield


app = FastAPI(title="Love AI Analytics Service", version="1.0.0", lifespan=lifespan)
setup_security(app)


@app.get("/")
async def root():
    return {"service": "love-ai", "status": "ok"}


@app.get("/api/health")
async def health():
    from .database import ping

    ok = await ping()
    return {"status": "ok" if ok else "degraded", "database": "main" if ok else "unreachable"}


app.include_router(insights.router, prefix="/api/ai")