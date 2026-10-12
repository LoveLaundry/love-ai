"""The AI `data_hash` must be computed over the same canonical JSON the
clients (quotations-ui TS / skaner Dart) use to re-derive and verify it.

Clients emit COMPACT JSON (`,`, `:` — no spaces) with sorted keys and UTF-8
preserved. Python's `json.dumps` defaults differ (spaced separators, ASCII
escaping), which made every integrity check fail. These tests pin the exact
byte sequence so the three implementations cannot silently diverge again.
"""
import hashlib
import json
import os

os.environ.setdefault("MASTER_KEY", "test-only-master-key-0123456789abcdef")

import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.crypto_helper import canonical_json  # noqa: E402


def _signed_hash(payload):
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def test_compact_separators_and_sorted_keys():
    # Mirrors TS `{${sortedKeys.map(k => `${JSON.stringify(k)}:${v}`).join(',')}}`.
    payload = {"b": 1, "a": 2, "nested": {"y": [1, 2], "x": "z"}}
    assert canonical_json(payload) == '{"a":2,"b":1,"nested":{"x":"z","y":[1,2]}}'


def test_non_ascii_is_preserved_not_escaped():
    # Sinhala text must survive as UTF-8, matching JS/Dart (no \uXXXX).
    payload = {"client_name": "පිරිසිදු", "city": "කොළඹ"}
    out = canonical_json(payload)
    assert "පිරිසිදු" in out
    assert "\\u" not in out


def test_hash_is_stable_and_deterministic():
    payload = {"z": None, "a": [True, False], "m": "x"}
    assert _signed_hash(payload) == _signed_hash(dict(payload))
    # A known-good fixture so a future accidental change to separators/ascii
    # is caught immediately.
    fixed = {"a": 1, "b": "two"}
    assert canonical_json(fixed) == '{"a":1,"b":"two"}'
    assert (
        _signed_hash(fixed)
        == hashlib.sha256(b'{"a":1,"b":"two"}').hexdigest()
    )


def test_ts_style_serializer_agrees():
    """Re-implement the TS canonicalizer and confirm byte equality over a
    nested payload (guards against ordering/whitespace regressions)."""

    def ts_canonical(value):
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (int, float)):
            return str(value)
        if isinstance(value, str):
            return json.dumps(value, ensure_ascii=False)
        if isinstance(value, list):
            return "[" + ",".join(ts_canonical(v) for v in value) + "]"
        keys = sorted(value.keys())
        return "{" + ",".join(
            f"{json.dumps(k, ensure_ascii=False)}:{ts_canonical(value[k])}" for k in keys
        ) + "}"

    for payload in [
        {"b": 2, "a": 1},
        {"items": [{"qty": 3, "name": "Shirt"}], "total": 10},
        {"name": "සිංහල", "list": [1, 2, 3], "flag": True, "none": None},
    ]:
        assert canonical_json(payload) == ts_canonical(payload)