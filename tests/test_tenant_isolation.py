"""Tenant isolation tests for love-ai (same contract as laundry-management)."""

import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock

from fastapi import HTTPException

os.environ.setdefault("JWT_SECRET", "test-secret")
os.environ.setdefault("MASTER_KEY", "test-master-key-1234567890")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from mongomock_motor import AsyncMongoMockClient

from src import tenancy
from src.tenancy import (
    LOVE_LAUNDRY_ID,
    assert_same_laundry,
    laundry_match,
    resolve_laundry_id,
    scoped_query,
)
from src.routers import insights

LAUNDRY_A = "acme"
LAUNDRY_B = "other"


def tenant_user(laundry_id=LAUNDRY_A, role="ADMIN", status="ACTIVE"):
    return {
        "auth_id": "tester",
        "user_id": "tester",
        "user_name": "Tester",
        "role": role,
        "laundry_id": laundry_id,
        "laundries": [{"id": laundry_id, "role": role, "status": status}],
    }


def test_resolve_laundry_fails_closed():
    with pytest.raises(HTTPException) as err:
        resolve_laundry_id(None)
    assert err.value.status_code == 401
    with pytest.raises(HTTPException) as err:
        resolve_laundry_id({"role": "ADMIN", "laundries": []})
    assert err.value.status_code == 400
    with pytest.raises(HTTPException) as err:
        resolve_laundry_id({
            "role": "ADMIN", "laundry_id": LAUNDRY_A,
            "laundries": [{"id": LAUNDRY_B, "status": "ACTIVE"}],
        })
    assert err.value.status_code == 403
    with pytest.raises(HTTPException) as err:
        resolve_laundry_id({
            "role": "ADMIN", "laundry_id": LAUNDRY_A,
            "laundries": [{"id": LAUNDRY_A, "status": "INACTIVE"}],
        })
    assert err.value.status_code == 403
    assert resolve_laundry_id(tenant_user()) == LAUNDRY_A
    platform = {"role": "PLATFORM_ADMIN", "laundry_id": LAUNDRY_B, "laundries": [],
                "platform_admin": True}
    assert resolve_laundry_id(platform) == LAUNDRY_B


def test_love_laundry_sees_legacy_unstamped_documents():
    scoped = scoped_query({"kind": "txn"}, LOVE_LAUNDRY_ID)
    tenant_clause = scoped["$and"][1]["$or"]
    assert {"laundry_id": LOVE_LAUNDRY_ID} in tenant_clause
    assert {"laundry_id": {"$exists": False}} in tenant_clause
    foreign = scoped_query({"kind": "txn"}, LAUNDRY_B)
    assert foreign == {"kind": "txn", "laundry_id": LAUNDRY_B}


def test_assert_same_laundry_404s_across_tenants():
    with pytest.raises(HTTPException) as err:
        assert_same_laundry({"laundry_id": LAUNDRY_B}, LAUNDRY_A, "Transaction")
    assert err.value.status_code == 404
    with pytest.raises(HTTPException) as err:
        assert_same_laundry(None, LAUNDRY_A, "Transaction")
    assert err.value.status_code == 404
    assert_same_laundry({}, LOVE_LAUNDRY_ID, "Transaction")
    assert_same_laundry({"laundry_id": LAUNDRY_A}, LAUNDRY_A, "Transaction")


@pytest.fixture
def db(monkeypatch):
    client = AsyncMongoMockClient()

    def bind(module, *names):
        for name in names:
            collection_name = name[: -len("_collection")] if name.endswith("_collection") else name
            monkeypatch.setattr(module, name, (lambda coll=collection_name: client["main"][coll]))

    bind(insights, "transactions_collection", "customers_collection", "employees_collection", "expenses_collection",
         "payments_collection", "salary_advances_collection", "salary_slips_collection", "attendance_collection")
    monkeypatch.setattr(insights, "audit_access", AsyncMock())
    return client["main"]


async def _seed_txns(db, laundry_id, n=1, **extra):
    coll = db["transactions"]
    ids = []
    for i in range(n):
        doc = {
            "laundry_id": laundry_id,
            "transaction_date": "2026-10-01",
            "total_amount": 10.0 + i,
            "customer_name": f"c-{laundry_id}-{i}",
            "items": [],
            **extra,
        }
        res = await coll.insert_one(doc)
        ids.append(res.inserted_id)
    return ids


@pytest.mark.asyncio
async def test_dashboard_scoped_by_session_laundry(db):
    await _seed_txns(db, LAUNDRY_A, 2)
    await _seed_txns(db, LAUNDRY_B, 3)
    await db["expenses"].insert_one({"laundry_id": LAUNDRY_A, "date": "2026-10-01", "amount": 1.0})
    await db["expenses"].insert_one({"laundry_id": LAUNDRY_B, "date": "2026-10-01", "amount": 5.0})
    await db["salary_slips"].insert_one({"laundry_id": LAUNDRY_A, "status": "PAID", "period_start": "2026-10-01", "net_salary": 2.0})
    await db["salary_slips"].insert_one({"laundry_id": LAUNDRY_B, "status": "PAID", "period_start": "2026-10-01", "net_salary": 10.0})

    # same-tenant
    res_a = await insights.dashboard_insights(months=12, _auth={"api_key": "k"}, user=tenant_user(LAUNDRY_A))
    assert res_a["data"]["total_revenue"] == 21.0  # 10.0+11.0
    assert res_a["data"]["total_expenses"] == 1.0
    assert res_a["data"]["total_payroll"] == 2.0

    # foreign tenant sees only their own
    res_b = await insights.dashboard_insights(months=12, _auth={"api_key": "k"}, user=tenant_user(LAUNDRY_B))
    assert res_b["data"]["total_revenue"] == 33.0  # n=3 -> 10.0 + 11.0 + 12.0
    assert res_b["data"]["total_expenses"] == 5.0
    assert res_b["data"]["total_payroll"] == 10.0


@pytest.mark.asyncio
async def test_endpoints_fail_closed_without_a_session(db):
    # The tenant comes only from the JWT; no session must never mean "all tenants".
    with pytest.raises(HTTPException) as err:
        await insights.dashboard_insights(months=12, _auth={"api_key": "k"}, user=None)
    assert err.value.status_code == 401


@pytest.mark.asyncio
async def test_revenue_scoped_and_top_customers_by_tenant(db):
    await _seed_txns(db, LAUNDRY_A, 1)
    await _seed_txns(db, LAUNDRY_B, 2)
    res_a = await insights.revenue_insights(months=12, _auth={"api_key": "k"}, user=tenant_user(LAUNDRY_A))
    assert res_a["data"]["total"] == 10.0
    res_b = await insights.revenue_insights(months=12, _auth={"api_key": "k"}, user=tenant_user(LAUNDRY_B))
    assert res_b["data"]["total"] == 21.0
