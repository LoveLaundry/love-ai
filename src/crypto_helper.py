"""
Crypto helpers for the Love AI service.

Mirrors the envelope-encryption scheme used by laundry-management so AI
analytics can decrypt PII (employee / customer names) for insights. Also
provides API-key hashing, constant-time verification, and request signing.
"""
import hmac
import hashlib
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import settings


def _derive(version: str) -> bytes:
    return hashlib.sha256((settings.master_key + "-" + version).encode()).digest()


KEK = _derive("kek")       # key-encryption-key for unwrapping per-doc DEKs
HMAC_KEY = _derive("hmac")  # key for search tokens + integrity hashes

# Envelope format this module understands. Anything else must fail loudly
# instead of being decrypted with the wrong scheme.
ENVELOPE_VERSION = 1
ENVELOPE_ALGORITHM = "AES-256-GCM"
ENVELOPE_KEY_ID = "master-key-v1"


def _validate_metadata(meta: dict) -> None:
    """Reject envelopes this build cannot read, instead of guessing."""
    if not isinstance(meta, dict):
        raise ValueError("Encryption metadata is malformed")

    version = meta.get("version")
    if version is not None and int(version) != ENVELOPE_VERSION:
        raise ValueError(f"Unsupported encryption envelope version: {version!r}")

    algorithm = meta.get("algorithm")
    if algorithm is not None and str(algorithm).strip().upper() != ENVELOPE_ALGORITHM:
        raise ValueError(f"Unsupported encryption algorithm: {algorithm!r}")

    if not isinstance(meta.get("wrappedDek"), dict):
        raise ValueError("Encryption metadata is missing the wrapped data key")


# ── Envelope encryption (compatible with laundry-management) ────────────────
def get_search_token(value: str) -> str:
    if not value:
        return ""
    normalized = value.strip().lower()
    return hmac.new(HMAC_KEY, normalized.encode(), hashlib.sha256).hexdigest()


def encrypt_field(plaintext: str, dek: bytes) -> dict:
    aesgcm = AESGCM(dek)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return {"ciphertext": ciphertext.hex(), "nonce": nonce.hex()}


def decrypt_field(encrypted_data: dict, dek: bytes) -> str:
    aesgcm = AESGCM(dek)
    nonce = bytes.fromhex(encrypted_data["nonce"])
    ciphertext = bytes.fromhex(encrypted_data["ciphertext"])
    return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")


def encrypt_dict(data: dict, sensitive_fields: list) -> dict:
    dek = AESGCM.generate_key(bit_length=256)
    aesgcm_kek = AESGCM(KEK)
    dek_nonce = os.urandom(12)
    wrapped_dek = aesgcm_kek.encrypt(dek_nonce, dek, None)

    encrypted_data = {}
    for key, val in data.items():
        if key in sensitive_fields and val is not None:
            if not isinstance(val, str):
                val_str = json.dumps(val)
                is_json = True
            else:
                val_str = val
                is_json = False
            enc_field = encrypt_field(val_str, dek)
            enc_field["is_json"] = is_json
            encrypted_data[key] = enc_field
        else:
            encrypted_data[key] = val

    encrypted_data["encryption_metadata"] = {
        "version": 1,
        "algorithm": "AES-256-GCM",
        "keyId": "master-key-v1",
        "wrappedDek": {"ciphertext": wrapped_dek.hex(), "nonce": dek_nonce.hex()},
    }
    return encrypted_data


def decrypt_dict(encrypted_data: dict, sensitive_fields: list) -> dict:
    if not encrypted_data:
        return encrypted_data
    if "encryption_metadata" not in encrypted_data:
        return {k: v for k, v in encrypted_data.items() if k != "encryption_metadata" and not k.endswith("_search")}

    meta = encrypted_data["encryption_metadata"]
    _validate_metadata(meta)
    wrapped_dek = meta["wrappedDek"]
    aesgcm_kek = AESGCM(KEK)
    try:
        dek = aesgcm_kek.decrypt(
            bytes.fromhex(wrapped_dek["nonce"]),
            bytes.fromhex(wrapped_dek["ciphertext"]),
            None,
        )
    except Exception as e:
        # The raw crypto error can describe key material / ciphertext
        # internals, so only the exception type is surfaced.
        raise ValueError(f"Failed to unwrap DEK ({type(e).__name__})") from e

    out = {}
    for key, val in encrypted_data.items():
        if key == "encryption_metadata":
            continue
        if key in sensitive_fields and isinstance(val, dict) and "ciphertext" in val and "nonce" in val:
            # Checked before the search-token rule below: a sensitive field
            # whose name happens to end in "_search" holds real (encrypted)
            # data and must be decrypted, not silently dropped.
            dec_val = decrypt_field(val, dek)
            out[key] = json.loads(dec_val) if val.get("is_json") else dec_val
        elif key.endswith("_search"):
            # Derived search tokens never leave the service: they exist so the
            # database can match an exact value without decrypting.
            continue
        else:
            out[key] = val
    return out


# ── Config / key material encryption ────────────────────────────────────────
def encrypt_config_value(plaintext: str) -> str:
    """AES-256-GCM single-value encryption for optional encrypted .env fragments."""
    aesgcm = AESGCM(KEK)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return f"encv1:{ciphertext.hex()}:{nonce.hex()}"


def decrypt_config_value(stored: str) -> str:
    if not stored.startswith("encv1:"):
        return stored
    _, ciphertext_hex, nonce_hex = stored.split(":", 2)
    aesgcm = AESGCM(KEK)
    return aesgcm.decrypt(
        bytes.fromhex(nonce_hex),
        bytes.fromhex(ciphertext_hex),
        None,
    ).decode("utf-8")


# ── API key hashing + constant-time verification ────────────────────────────
def hash_api_key(plain_key: str) -> str:
    """Deterministic HMAC-SHA256 hash of an API key for storage/comparison."""
    if not plain_key:
        return ""
    return hmac.new(HMAC_KEY, plain_key.encode("utf-8"), hashlib.sha256).hexdigest()


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# ── Request signing (who + what are you really asking) ───────────────────────
def canonical_request(method: str, path: str, timestamp: str, body_hash: str) -> str:
    return "\n".join([method.upper(), path, timestamp, body_hash])


def sign_request(api_key: str, method: str, path: str, timestamp: str, body_hash: str) -> str:
    canonical = canonical_request(method, path, timestamp, body_hash)
    return hmac.new(api_key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_request_signature(
    api_key: str,
    method: str,
    path: str,
    timestamp: str,
    body_hash: str,
    provided_signature: str,
) -> bool:
    expected = sign_request(api_key, method, path, timestamp, body_hash)
    return constant_time_equal(expected, provided_signature)


def canonical_json(value) -> str:
    """Canonical JSON for cross-platform integrity hashes.

    MUST stay byte-identical to the clients that verify `data_hash`:
      • quotations-ui `canonicalJson`  (config/ai.ts)
      • skaner (Dart)     `canonicalJson`  (core/utils/idempotency.dart)

    Those implementations emit COMPACT separators (no spaces after `,`/`:`)
    with object keys sorted and non-ASCII preserved as UTF-8. Python's
    `json.dumps` defaults to `", "`/`": "` separators and ASCII-escaping, so
    the defaults cannot be used here — that mismatch made every client
    integrity check fail.
    """
    return json.dumps(
        value,
        sort_keys=True,
        default=str,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()