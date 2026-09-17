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
    wrapped_dek = meta["wrappedDek"]
    aesgcm_kek = AESGCM(KEK)
    dek = aesgcm_kek.decrypt(
        bytes.fromhex(wrapped_dek["nonce"]),
        bytes.fromhex(wrapped_dek["ciphertext"]),
        None,
    )

    out = {}
    for key, val in encrypted_data.items():
        if key == "encryption_metadata" or key.endswith("_search"):
            continue
        if key in sensitive_fields and isinstance(val, dict) and "ciphertext" in val and "nonce" in val:
            dec_val = decrypt_field(val, dek)
            out[key] = json.loads(dec_val) if val.get("is_json") else dec_val
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


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()