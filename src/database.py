"""MongoDB access for Love AI analytics.

Reads the SAME MAIN database as laundry-management. Collections shared with
that service are accessed read-only for aggregation and forecasting.
"""
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorCollection, AsyncIOMotorDatabase

from .config import settings

_client: AsyncIOMotorClient | None = None


def _get_client() -> AsyncIOMotorClient:
    global _client
    if _client is None:
        _client = AsyncIOMotorClient(settings.resolve_main_uri(), serverSelectionTimeoutMS=5000)
    return _client


def db() -> AsyncIOMotorDatabase:
    return _get_client()[settings.resolve_main_db()]


def salary_slips_collection() -> AsyncIOMotorCollection:
    return db()["salary_slips"]


def expenses_collection() -> AsyncIOMotorCollection:
    return db()["expenses"]


def transactions_collection() -> AsyncIOMotorCollection:
    return db()["transactions"]


def employees_collection() -> AsyncIOMotorCollection:
    return db()["employees"]


def attendance_collection() -> AsyncIOMotorCollection:
    return db()["attendance"]


def salary_advances_collection() -> AsyncIOMotorCollection:
    return db()["salary_advances"]


def customers_collection() -> AsyncIOMotorCollection:
    return db()["customers"]


def payments_collection() -> AsyncIOMotorCollection:
    return db()["payments"]


def audit_logs_collection() -> AsyncIOMotorCollection:
    return db()["audit_logs"]


async def ping() -> bool:
    try:
        await db().command("ping")
        return True
    except Exception:
        return False