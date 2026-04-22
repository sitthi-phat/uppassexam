"""Startup key loading — called from lifespan before the app starts serving."""

import os
import base64
import hashlib
import logging

from cryptography.hazmat.primitives import serialization

from .state import state
from .database import db_distinct_versions
from .gcp import load_versioned_secret

log = logging.getLogger("uppass")

_PRIVATE_KEY_PATH = os.environ.get("PRIVATE_KEY_PATH", "keys/private.pem")


def load_private_keys() -> None:
    """
    Load ALL RSA private key versions referenced in the DB.
    v1  → reads uppass-private-key-v1-b64 SM version 1 (env var fallback for local dev)
    v2+ → reads named secret uppass-private-key-v1-b64-v2, uppass-private-key-v1-b64-v3, …
    """
    versions = db_distinct_versions("key_version") | {"v1"}

    for ver in sorted(versions, key=lambda v: int(v[1:])):
        try:
            raw_b64 = load_versioned_secret("uppass-private-key-v1-b64", ver)
            pem = base64.b64decode(raw_b64)
            state.private_keys[ver] = serialization.load_pem_private_key(pem, password=None)
            log.info("Loaded RSA key version=%s from Secret Manager", ver)
            continue
        except Exception:
            pass

        if ver == "v1":
            key_b64 = os.environ.get("PRIVATE_KEY_B64", "")
            if key_b64:
                pem = base64.b64decode(key_b64)
                state.private_keys["v1"] = serialization.load_pem_private_key(pem, password=None)
                log.info("Loaded RSA key version=v1 from env var")
                continue

            key_dir = os.path.dirname(_PRIVATE_KEY_PATH)
            if os.path.isdir(key_dir):
                for fname in os.listdir(key_dir):
                    if fname.startswith("private_") and fname.endswith(".pem"):
                        fver = fname.replace("private_", "").replace(".pem", "")
                        with open(os.path.join(key_dir, fname), "rb") as f:
                            state.private_keys[fver] = serialization.load_pem_private_key(f.read(), password=None)
                        log.info("Loaded RSA key version=%s from file", fver)
            elif os.path.exists(_PRIVATE_KEY_PATH):
                with open(_PRIVATE_KEY_PATH, "rb") as f:
                    state.private_keys["v1"] = serialization.load_pem_private_key(f.read(), password=None)
                log.info("Loaded RSA key version=v1 from file path")

    if not state.private_keys:
        raise RuntimeError("No private key loaded — set PRIVATE_KEY_B64 or PRIVATE_KEY_PATH")

    state.current_rsa_version = max(state.private_keys.keys(), key=lambda v: int(v[1:]))
    log.info("RSA ready: versions=%s current=%s", sorted(state.private_keys), state.current_rsa_version)


def init_dek() -> None:
    """
    Load ALL DEK versions referenced in the DB.
    v1  → reads uppass-dek SM version 1 (env var fallback for local dev)
    v2+ → reads named secret uppass-dek-v2, uppass-dek-v3, …
    """
    versions = db_distinct_versions("dek_version") | {"v1"}

    for ver in sorted(versions, key=lambda v: int(v[1:])):
        try:
            raw = load_versioned_secret("uppass-dek", ver)
            state.dek_keys[ver] = hashlib.sha256(raw.encode()).digest()
            log.info("Loaded DEK version=%s from Secret Manager", ver)
            continue
        except Exception:
            pass

        if ver == "v1":
            raw = os.environ.get("DATA_ENCRYPTION_KEY", "")
            if raw:
                state.dek_keys["v1"] = hashlib.sha256(raw.encode()).digest()
                log.info("Loaded DEK version=v1 from env var")

    if not state.dek_keys:
        raise RuntimeError("DATA_ENCRYPTION_KEY env var is required")

    state.current_dek_version = max(state.dek_keys.keys(), key=lambda v: int(v[1:]))
    log.info("DEK ready: versions=%s current=%s", sorted(state.dek_keys), state.current_dek_version)


def init_hmac() -> None:
    """
    Load ALL HMAC secret versions referenced in the DB.
    v1  → reads uppass-hmac-secret SM version 1 (env var fallback for local dev)
    v2+ → reads named secret uppass-hmac-secret-v2, uppass-hmac-secret-v3, …
    """
    versions = db_distinct_versions("hmac_version") | {"v1"}

    for ver in sorted(versions, key=lambda v: int(v[1:])):
        try:
            raw = load_versioned_secret("uppass-hmac-secret", ver)
            state.hmac_secrets[ver] = raw.encode()
            log.info("Loaded HMAC secret version=%s from Secret Manager", ver)
            continue
        except Exception:
            pass

        if ver == "v1":
            raw = os.environ.get("HMAC_SECRET", "")
            if raw:
                state.hmac_secrets["v1"] = raw.encode()
                log.info("Loaded HMAC secret version=v1 from env var")

    if not state.hmac_secrets:
        raise RuntimeError("HMAC_SECRET env var is required")

    state.current_hmac_version = max(state.hmac_secrets.keys(), key=lambda v: int(v[1:]))
    log.info("HMAC ready: versions=%s current=%s", sorted(state.hmac_secrets), state.current_hmac_version)
