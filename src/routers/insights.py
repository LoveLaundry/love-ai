"""Love AI insight endpoints — all authenticated via hashed API key + HMAC request signature."""
import hashlib
import json

from fastapi import APIRouter, Depends, Query

from ..auth_helper import optional_current_user, verify_signed_request
from ..crypto_helper import decrypt_dict, sha256_hex
from ..security import audit_access
from .. import analytics
from ..database import (
    attendance_collection,
    customers_collection,
    employees_collection,
    expenses_collection,
    payments_collection,
    salary_advances_collection,
    salary_slips_collection,
    transactions_collection,
)

router = APIRouter(tags=["AI Insights"])

TXN_SENSITIVE = ["customer_name", "invoice_number", "items", "notes"]
EMPLOYEE_SENSITIVE = ["name", "phone", "nic", "notes"]
EXPCAT_SENSITIVE = ["name"]


def _hash_payload(payload: dict) -> str:
    return sha256_hex(json.dumps(payload, sort_keys=True, default=str).encode("utf-8"))


def _wrap(payload: dict, trusted: bool = False) -> dict:
    """Attach an integrity hash plus trust metadata to every response."""
    return {"data": payload, "data_hash": _hash_payload(payload), "source": "love_ai_v1", "verified": trusted}


@router.get("/health")
async def health(_key: dict = Depends(verify_signed_request)):
    from ..database import ping

    ok = await ping()
    return {"service": "love-ai", "status": "ok" if ok else "degraded", "database": "main" if ok else "unreachable"}


@router.get("/insights/dashboard")
async def dashboard_insights(
    months: int = Query(12, ge=1, le=24),
    _auth: dict = Depends(verify_signed_request),
    user: dict | None = Depends(optional_current_user),
):
    now_year, now_month = None, None  # analytics default = now
    txns = await transactions_collection().find({}).to_list(length=None)
    expenses = await expenses_collection().find({}).to_list(length=None)
    slips = await salary_slips_collection().find({"status": {"$ne": "DELETED"}}).to_list(length=None)

    revenue_series = analytics.default_series_data(txns, "transaction_date", "total_amount", months)
    expense_series = analytics.default_series_data(expenses, "date", "amount", months)
    payroll_series = analytics.default_series_data(slips, "period_start", "net_salary", months)

    revenue_vals = [s["value"] for s in revenue_series]
    expense_vals = [s["value"] for s in expense_series]
    payroll_vals = [s["value"] for s in payroll_series]

    net = [round(r - e, 2) for r, e in zip(revenue_vals, expense_vals)]

    payload = {
        "generated_at": None,
        "months": months,
        "period": {"start": revenue_series[0]["month"] if revenue_series else None, "end": revenue_series[-1]["month"] if revenue_series else None},
        "revenue": _wrap_series(revenue_series, analytics.ols_forecast(revenue_vals, 3)),
        "expenses": _wrap_series(expense_series, analytics.ols_forecast(expense_vals, 3)),
        "payroll": _wrap_series(payroll_series, analytics.ols_forecast(payroll_vals, 3)),
        "net_profit": {"history": net, "total": round(sum(net), 2)},
        "total_revenue": round(sum(revenue_vals), 2),
        "total_expenses": round(sum(expense_vals), 2),
        "total_payroll": round(sum(payroll_vals), 2),
        "avg_monthly_net": round(sum(net) / len(net), 2) if net else 0.0,
    }
    await audit_access((user or {}).get("user_id"), "insights.dashboard", None, {"months": months})
    return _wrap(payload)


@router.get("/insights/revenue")
async def revenue_insights(
    months: int = Query(12, ge=1, le=24),
    _auth: dict = Depends(verify_signed_request),
    user: dict | None = Depends(optional_current_user),
):
    txns = await transactions_collection().find({}).to_list(length=None)
    series = analytics.default_series_data(txns, "transaction_date", "total_amount", months)
    vals = [s["value"] for s in series]
    forecast = analytics.ols_forecast(vals, 3)

    # Top customers by volume (decrypt customer_name)
    by_customer: dict[str, float] = {}
    for t in txns:
        dec = decrypt_dict(t, TXN_SENSITIVE)
        cid = str(dec.get("customer_id") or "")
        name = (dec.get("customer_name") or "").strip() or "Walk-in"
        key = f"{cid}|{name}"
        by_customer[key] = by_customer.get(key, 0.0) + analytics._num(dec.get("total_amount"))
    top_customers = [
        {"customer_name": name.split("|", 1)[1], "amount": round(amt, 2)}
        for name, amt in sorted(by_customer.items(), key=lambda kv: kv[1], reverse=True)[:10]
    ]

    payload = {
        "months": months,
        "series": series,
        "forecast": forecast,
        "total": round(sum(vals), 2),
        "best_month": max(series, key=lambda s: s["value"], default=None),
        "top_customers": top_customers,
        "projected_next_3_months": forecast["forecast"],
    }
    await audit_access((user or {}).get("user_id"), "insights.revenue", None, {"months": months})
    return _wrap(payload)


@router.get("/insights/expenses")
async def expense_insights(
    months: int = Query(12, ge=1, le=24),
    _auth: dict = Depends(verify_signed_request),
    user: dict | None = Depends(optional_current_user),
):
    expenses = await expenses_collection().find({}).to_list(length=None)
    series = analytics.default_series_data(expenses, "date", "amount", months)
    vals = [s["value"] for s in series]
    forecast = analytics.ols_forecast(vals, 3)

    # Top categories by amount (decrypt category names via category collection)
    from ..database import db
    cat_rows = await db()["expense_categories"].find({}).to_list(length=None)
    cat_names: dict[str, str] = {}
    for c in cat_rows:
        dec = decrypt_dict(c, EXPCAT_SENSITIVE)
        cat_names[str(dec.get("_id"))] = (dec.get("name") or "Uncategorized")
    by_cat: dict[str, float] = {}
    for e in expenses:
        cid = str(e.get("category_id") or "None")
        by_cat[cat_names.get(cid, "Uncategorized")] = by_cat.get(cat_names.get(cid, "Uncategorized"), 0.0) + analytics._num(e.get("amount"))
    top_categories = [{"category": k, "amount": round(v, 2)} for k, v in sorted(by_cat.items(), key=lambda kv: kv[1], reverse=True)[:10]]

    payload = {
        "months": months,
        "series": series,
        "forecast": forecast,
        "total": round(sum(vals), 2),
        "highest_month": max(series, key=lambda s: s["value"], default=None),
        "top_categories": top_categories,
        "projected_next_3_months": forecast["forecast"],
    }
    await audit_access((user or {}).get("user_id"), "insights.expenses", None, {"months": months})
    return _wrap(payload)


@router.get("/insights/salary")
async def salary_insights(
    months: int = Query(12, ge=1, le=24),
    _auth: dict = Depends(verify_signed_request),
    user: dict | None = Depends(optional_current_user),
):
    slips_docs = await salary_slips_collection().find({"status": {"$ne": "DELETED"}}).to_list(length=None)
    series = analytics.default_series_data(slips_docs, "period_start", "net_salary", months)
    vals = [s["value"] for s in series]
    forecast = analytics.ols_forecast(vals, 3)

    # Per-employee payroll totals
    per_emp: dict[str, dict] = {}
    for s in slips_docs:
        eid = str(s.get("employee_id") or "")
        rec = per_emp.setdefault(eid, {"employee_id": eid, "employee_name": s.get("employee_name") or "Unknown", "total": 0.0, "slips": 0})
        rec["total"] += analytics._num(s.get("net_salary"))
        rec["slips"] += 1
    employees_sorted = sorted(per_emp.values(), key=lambda r: r["total"], reverse=True)

    payload = {
        "months": months,
        "series": series,
        "forecast": forecast,
        "total_payroll": round(sum(vals), 2),
        "avg_monthly_payroll": round(sum(vals) / len(vals), 2) if vals else 0.0,
        "top_employees": [{**e, "total": round(e["total"], 2)} for e in employees_sorted[:10]],
        "projected_next_3_months": forecast["forecast"],
    }
    await audit_access((user or {}).get("user_id"), "insights.salary", None, {"months": months})
    return _wrap(payload)


@router.get("/insights/payroll-risk")
async def payroll_risk_insights(
    _auth: dict = Depends(verify_signed_request),
    user: dict | None = Depends(optional_current_user),
):
    # Outstanding advances grouped per employee
    advances = await salary_advances_collection().find({"status": "OUTSTANDING", "outstanding": {"$gt": 0}}).to_list(length=None)
    employees = await employees_collection().find({}).to_list(length=None)
    emp_names: dict[str, str] = {}
    for e in employees:
        dec = decrypt_dict(e, EMPLOYEE_SENSITIVE)
        emp_names[str(dec.get("_id"))] = dec.get("name") or "Unknown"

    by_emp: dict[str, dict] = {}
    for a in advances:
        eid = str(a.get("employee_id") or "")
        rec = by_emp.setdefault(eid, {"employee_id": eid, "employee_name": emp_names.get(eid, "Unknown"), "outstanding": 0.0, "count": 0})
        rec["outstanding"] += analytics._num(a.get("outstanding"))
        rec["count"] += 1
    risk_rows = [dict(r, outstanding=round(r["outstanding"], 2)) for r in by_emp.values()]
    risk_rows.sort(key=lambda r: r["outstanding"], reverse=True)

    payload = {
        "as_of": None,
        "total_outstanding_advances": round(sum(r["outstanding"] for r in risk_rows), 2),
        "employees_at_risk": risk_rows,
    }
    await audit_access((user or {}).get("user_id"), "insights.payroll_risk", None, {})
    return _wrap(payload)


@router.post("/insights/query")
async def custom_query(
    payload: dict,
    _auth: dict = Depends(verify_signed_request),
    user: dict | None = Depends(optional_current_user),
):
    """Structured analytical query: {metric: 'revenue'|'expenses'|'salary'|'net', months?: int}."""
    metric = str(payload.get("metric") or "revenue").lower()
    months = int(payload.get("months") or 12)
    months = max(1, min(months, 24))

    coll, date_key, value_key, label = {
        "revenue": (transactions_collection, "transaction_date", "total_amount", "Revenue"),
        "expenses": (expenses_collection, "date", "amount", "Expenses"),
        "salary": (salary_slips_collection, "period_start", "net_salary", "Payroll"),
    }.get(metric, (None, None, None, None))

    if coll is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail=f"Unknown metric '{metric}'")

    docs = await coll.find({}).to_list(length=None)
    series = analytics.default_series_data(docs, date_key, value_key, months)
    vals = [s["value"] for s in series]
    forecast = analytics.ols_forecast(vals, 3)
    result = {
        "metric": metric,
        "label": label,
        "months": months,
        "series": series,
        "forecast": forecast,
        "total": round(sum(vals), 2),
        "average": round(sum(vals) / len(vals), 2) if vals else 0.0,
        "trend": "up" if forecast["slope"] > 0 else ("down" if forecast["slope"] < 0 else "flat"),
        "projected_next_3_months": forecast["forecast"],
    }
    await audit_access((user or {}).get("user_id"), "insights.query", None, {"metric": metric, "months": months})
    return _wrap(result)


def _wrap_series(series: list[dict], forecast: dict) -> dict:
    return {"series": series, "forecast": forecast}