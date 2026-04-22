"""Startup key loading — called from lifespan before the app starts serving."""

import os
import base64
import hashlib
import logging

from cryptography.hazmat.primitives import serialization

from .state import state
from .database import db_distinct_versions
from .gcp import load_secret_version

log = logging.getLogger("uppass")

_PRIVATE_KEY_PATH = os.environ.get("PRIVATE_KEY_PATH", "keys/private.pem")


def load_private_keys() -> None:
    """
    Load ALL RSA private key versions referenced in the DB from Secret Manager.
    DB label "vN" maps to SM version number N on secret 'uppass-private-key-v1-b64'.
    Falls back to PRIVATE_KEY_B64 env var or key files for v1 (local dev).
    """
    versions = db_distinct_versions("key_version") | {"v1"}

    for ver in sorted(versions, key=lambda v: int(v[1:])):
        ver_num = int(ver[1:])
        try:
            raw_b64 = load_secret_version("uppass-private-key-v1-b64", ver_num)
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
    Load ALL DEK versions referenced in the DB from Secret Manager.
    DB label "vN" maps to SM version number N on secret 'uppass-dek'.
    Falls back to DATA_ENCRYPTION_KEY env var for v1 (local dev).
    """
    versions = db_distinct_versions("dek_version") | {"v1"}

    for ver in sorted(versions, key=lambda v: int(v[1:])):
        ver_num = int(ver[1:])
        try:
            raw = load_secret_version("uppass-dek", ver_num)
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
    Load ALL HMAC secret versions referenced in the DB from Secret Manager.
    DB label "vN" maps to SM version number N on secret 'uppass-hmac-secret'.
    Falls back to HMAC_SECRET env var for v1 (local dev).
    """
    versions = db_distinct_versions("hmac_version") | {"v1"}

    for ver in sorted(versions, key=lambda v: int(v[1:])):
        ver_num = int(ver[1:])
        try:
            raw = load_secret_version("uppass-hmac-secret", ver_num)
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
