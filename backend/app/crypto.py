"""Cryptographic helpers — RSA unwrap, AES-GCM encrypt/decrypt, HMAC blind index."""

import base64
import hashlib
import hmac as hmac_mod
import secrets

from fastapi import HTTPException
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .state import state


def get_private_key(version: str):
    key = state.private_keys.get(version)
    if not key:
        raise HTTPException(status_code=500, detail=f"Unknown RSA key version: {version}")
    return key


def get_storage_key(dek_ver: str) -> bytes:
    key = state.dek_keys.get(dek_ver)
    if not key:
        raise HTTPException(status_code=500, detail=f"Unknown DEK version: {dek_ver}")
    return key


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
    aesgcm    = AESGCM(aes_key)
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
    secret = state.hmac_secrets.get(ver)
    if not secret:
        raise HTTPException(status_code=500, detail=f"Unknown HMAC version: {ver}")
    return hmac_mod.new(secret, national_id.encode("utf-8"), hashlib.sha256).hexdigest()
