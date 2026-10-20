"""Browser-facing insight routes authenticate with JWTs, not service keys."""

import hashlib
import time
from unittest.mock import AsyncMock

import httpx
import jwt
import pytest
from mongomock_motor import AsyncMongoMockClient

from src.config import settings
from src.crypto_helper import canonical_json
from src.routers import insights
from src.main import app


@pytest.fixture
def mongo(monkeypatch):
    client = AsyncMongoMockClient()
    monkeypatch.setattr(settings, "jwt_secret", "test-jwt-secret-with-at-least-32-bytes")
    for name in (
        "transactions",
        "customers",
        "employees",
        "expenses",
        "payments",
        "salary_advances",
        "salary_slips",
        "attendance",
    ):
        monkeypatch.setattr(
            insights,
            f"{name}_collection",
            lambda collection=name: client["main"][collection],
        )
    monkeypatch.setattr(insights, "audit_access", AsyncMock())
    return client["main"]


def _token(role="ADMIN", laundry_id="acme", status="ACTIVE"):
    return jwt.encode(
        {
            "user_id": "user-1",
            "role_id": role,
            "laundry_id": laundry_id,
            "laundries": [{"id": laundry_id, "status": status}],
            "exp": int(time.time()) + 60,
        },
        settings.jwt_secret,
        algorithm="HS256",
    )


@pytest.mark.asyncio
async def test_dashboard_accepts_jwt_without_service_key_or_signature(mongo):
    await mongo["transactions"].insert_one({
        "laundry_id": "acme",
        "transaction_date": "2026-10-01",
        "total_amount": 17.5,
    })
    await mongo["transactions"].insert_one({
        "laundry_id": "other",
        "transaction_date": "2026-10-01",
        "total_amount": 99.0,
    })
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/api/ai/insights/dashboard",
            headers={"Authorization": f"Bearer {_token()}"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["data"]["total_revenue"] == 17.5
    assert body["data_hash"] == hashlib.sha256(
        canonical_json(body["data"]).encode("utf-8")
    ).hexdigest()
    assert body["source"] == "love_ai_v1"
    assert body["verified"] is False


@pytest.mark.asyncio
async def test_dashboard_rejects_unprivileged_role_and_inactive_tenant(mongo):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        unprivileged = await client.get(
            "/api/ai/insights/dashboard",
            headers={"Authorization": f"Bearer {_token(role='STAFF')}"},
        )
        inactive = await client.get(
            "/api/ai/insights/dashboard",
            headers={"Authorization": f"Bearer {_token(status='INACTIVE')}"},
        )

    assert unprivileged.status_code == 403
    assert inactive.status_code == 403
