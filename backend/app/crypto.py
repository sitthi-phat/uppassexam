"""
Cryptographic helpers — RSA unwrap, AES-GCM encrypt/decrypt, HMAC blind index.

All three key-getter functions use a fetch-and-cache pattern:
  1. Check the in-process cache (state dict) — return immediately on hit.
  2. On miss, fetch the versioned secret from Secret Manager, cache it, return.

This makes the service safe to run with multiple Cloud Run instances.
Any instance that hasn't seen a particular key version yet (e.g. because a
rotation was handled by a different instance) loads it from SM on demand the
first time a record with that version arrives, then caches it for the lifetime
of the process. No cross-instance signalling or shared memory is required.
"""

import base64
import hashlib
import hmac as hmac_mod
import logging
import secrets

from fastapi import HTTPException
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .state import state

log = logging.getLogger("uppass")


# ── Key getters (cache → SM on miss) ─────────────────────────────────────────

def get_private_key(version: str):
    """Return RSA private key for version, fetching from SM if not cached."""
    if version not in state.private_keys:
        from .gcp import load_versioned_secret
        try:
            raw_b64 = load_versioned_secret("uppass-private-key-v1-b64", version)
            pem     = base64.b64decode(raw_b64)
            state.private_keys[version] = serialization.load_pem_private_key(pem, password=None)
            log.info("On-demand loaded RSA key version=%s from Secret Manager", version)
        except Exception as exc:
            log.error("RSA key version=%s not found in SM: %s", version, exc)
            raise HTTPException(status_code=500,
                detail=f"RSA key version {version} not available — {type(exc).__name__}")
    return state.private_keys[version]


def get_storage_key(dek_ver: str) -> bytes:
    """Return AES DEK bytes for version, fetching from SM if not cached."""
    if dek_ver not in state.dek_keys:
        from .gcp import load_versioned_secret
        try:
            raw = load_versioned_secret("uppass-dek", dek_ver)
            state.dek_keys[dek_ver] = hashlib.sha256(raw.encode()).digest()
            log.info("On-demand loaded DEK version=%s from Secret Manager", dek_ver)
        except Exception as exc:
            log.error("DEK version=%s not found in SM: %s", dek_ver, exc)
            raise HTTPException(status_code=500,
                detail=f"DEK version {dek_ver} not available — {type(exc).__name__}")
    return state.dek_keys[dek_ver]


def _get_hmac_secret(ver: str) -> bytes:
    """Return HMAC secret bytes for version, fetching from SM if not cached."""
    if ver not in state.hmac_secrets:
        from .gcp import load_versioned_secret
        try:
            raw = load_versioned_secret("uppass-hmac-secret", ver)
            state.hmac_secrets[ver] = raw.encode()
            log.info("On-demand loaded HMAC secret version=%s from Secret Manager", ver)
        except Exception as exc:
            log.error("HMAC secret version=%s not found in SM: %s", ver, exc)
            raise HTTPException(status_code=500,
                detail=f"HMAC version {ver} not available — {type(exc).__name__}")
    return state.hmac_secrets[ver]


# ── Crypto operations ─────────────────────────────────────────────────────────

def unwrap_aes_key(encrypted_key_b64: str, key_version: str) -> bytes:
    private_key   = get_private_key(key_version)
    encrypted_key = base64.b64decode(encrypted_key_b64)
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def aes_gcm_decrypt(ciphertext_b64: str, iv_b64: str, aes_key: bytes) -> str:
    aesgcm     = AESGCM(aes_key)
    ciphertext = base64.b64decode(ciphertext_b64)
    iv         = base64.b64decode(iv_b64)
    return aesgcm.decrypt(iv, ciphertext, associated_data=None).decode("utf-8")


def aes_gcm_encrypt(plaintext: str, aes_key: bytes) -> tuple[str, str]:
    aesgcm     = AESGCM(aes_key)
    iv         = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(iv, plaintext.encode("utf-8"), associated_data=None)
    return base64.b64encode(ciphertext).decode(), base64.b64encode(iv).decode()


def compute_blind_index(national_id: str, hmac_ver: str = None) -> str:
    ver    = hmac_ver or state.current_hmac_version
    secret = _get_hmac_secret(ver)
    return hmac_mod.new(secret, national_id.encode("utf-8"), hashlib.sha256).hexdigest()
