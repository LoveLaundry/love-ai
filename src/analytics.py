"""Forecasting engine: least-squares trend + exponential smoothing.

Pure-Python implementations (no heavy ML deps) so it stays serverless-friendly.
"""
import calendar
from datetime import date, datetime, timezone
from typing import Iterable


def _num(value) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def ols_forecast(values: list[float], future_steps: int) -> dict:
    """Ordinary least-squares linear forecast over evenly spaced points.

    Returns slope/intercept, the next `future_steps` values, and the fitted
    history for charting.
    """
    n = len(values)
    if n < 2:
        flat = values[-1] if values else 0.0
        return {
            "slope": 0.0,
            "intercept": flat,
            "history": values,
            "forecast": [round(flat, 2)] * future_steps,
        }

    xs = list(range(1, n + 1))
    x_mean = sum(xs) / n
    y_mean = sum(values) / n
    num = sum((x - x_mean) * (y - y_mean) for x, y in zip(xs, values))
    den = sum((x - x_mean) ** 2 for x in xs)
    slope = num / den if den != 0 else 0.0
    intercept = y_mean - slope * x_mean

    history = [round(intercept + slope * x, 2) for x in xs]
    forecast = [round(intercept + slope * (n + i), 2) for i in range(1, future_steps + 1)]
    growth_pct = round(slope / (abs(y_mean) or 1.0) * 100.0, 2)
    return {"slope": round(slope, 4), "intercept": round(intercept, 2), "history": history, "forecast": forecast, "growth_pct": growth_pct}


def ema_next(values: list[float], alpha: float = 0.35) -> float:
    """Single exponential smoothing — one-step-ahead level."""
    if not values:
        return 0.0
    level = _num(values[0])
    for v in values[1:]:
        level = alpha * _num(v) + (1 - alpha) * level
    return round(level, 2)


def month_keys(count: int = 12, end_year: int | None = None, end_month: int | None = None) -> list[str]:
    """Last `count` months as 'YYYY-MM' strings ending in the given month (default: now)."""
    now = datetime.now(timezone.utc)
    y = end_year or now.year
    m = end_month or now.month
    keys: list[str] = []
    for i in range(count - 1, -1, -1):
        total = y * 12 + (m - 1) - i
        yy, mm = divmod(total, 12)
        keys.append(f"{yy:04d}-{mm + 1:02d}")
    return keys


def default_series_data(docs: Iterable[dict], date_key: str, value_key: str, count: int = 12) -> list[dict]:
    """Group docs by 'YYYY-MM' prefix of date_key into a monthly series."""
    totals: dict[str, float] = {}
    for doc in docs:
        key = _month_prefix(str(doc.get(date_key) or ""), date_key)
        if key:
            totals[key] = totals.get(key, 0.0) + _num(doc.get(value_key))
    return [{"month": m, "value": round(totals.get(m, 0.0), 2)} for m in month_keys(count)]


def _month_prefix(value: str, date_key: str) -> str | None:
    v = value.strip()
    if len(v) >= 7 and v[4] == "-":
        return v[:7]
    if "T" in v:
        v = v.split("T")[0]
    if len(v) >= 7:
        return v[:7]
    return None


def month_name(ym: str) -> str:
    try:
        yy, mm = ym.split("-")
        return f"{calendar.month_name[int(mm)]} {yy}"
    except Exception:
        return ym


def periods_in_year(year: int) -> list[str]:
    return [f"{year:04d}-{m:02d}" for m in range(1, 13)]