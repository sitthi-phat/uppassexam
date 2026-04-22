"""
Admin router — key rotation, record management, demo reset.

All endpoints under /v1/admin/. These are utility operations (not part of the
core verification API) and are separated here to keep main.py focused on the
primary submit/search/public-key flow.
"""

import hashlib
import logging
import secrets

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..state import state
from ..database import NationalIdRecord, get_db
from ..crypto import aes_gcm_decrypt, aes_gcm_encrypt, compute_blind_index
from ..gcp import create_versioned_secret
from ..schemas import (
    AdminStatusResponse,
    RotateRSAResponse,
    RotateDEKRequest, RotateDEKResponse,
    RotateHMACRequest, RotateHMACResponse,
)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64

log    = logging.getLogger("uppass")
router = APIRouter(prefix="/v1/admin", tags=["admin"])


@router.get("/status", response_model=AdminStatusResponse)
def admin_status(db: Session = Depends(get_db)):
    total        = db.query(NationalIdRecord).count()
    dek_pending  = db.query(NationalIdRecord).filter(NationalIdRecord.dek_version  != state.current_dek_version).count()
    hmac_pending = db.query(NationalIdRecord).filter(NationalIdRecord.hmac_version != state.current_hmac_version).count()
    return AdminStatusResponse(
        rsa_version=state.current_rsa_version,
        dek_version=state.current_dek_version,
        hmac_version=state.current_hmac_version,
        total_records=total,
        dek_pending=dek_pending,
        hmac_pending=hmac_pending,
    )


@router.get("/records")
def list_records(db: Session = Depends(get_db)):
    """All record metadata — no decrypted data. Long fields truncated for display."""
    records = db.query(NationalIdRecord).order_by(NationalIdRecord.created_at.desc()).all()
    return {
        "total": len(records),
        "records": [
            {
                "id":             rec.id,
                "encrypted_data": rec.encrypted_data[:24] + "…" if rec.encrypted_data else None,
                "storage_iv":     rec.storage_iv,
                "search_index":   rec.search_index[:16] + "…" if rec.search_index else None,
                "key_version":    rec.key_version,
                "dek_version":    rec.dek_version,
                "hmac_version":   rec.hmac_version,
                "created_at":     rec.created_at.isoformat() if rec.created_at else None,
            }
            for rec in records
        ],
    }


@router.post("/records/delete-all")
def delete_all_records(db: Session = Depends(get_db)):
    """Delete all records. Key state is unchanged (use /reset-demo for full reset)."""
    deleted = db.query(NationalIdRecord).delete()
    db.commit()
    log.info("Deleted all %d records (key state unchanged)", deleted)
    return {"deleted_records": deleted, "message": f"Deleted {deleted} records. Key versions unchanged."}


@router.post("/rotate-rsa", response_model=RotateRSAResponse)
def rotate_rsa():
    """
    Generate a new RSA-2048 key pair, store to Secret Manager, hot-reload.
    Old keys remain in state so existing in-flight records remain decryptable.
    """
    existing = list(state.private_keys.keys())
    max_num  = max((int(v[1:]) for v in existing if v.startswith("v") and v[1:].isdigit()), default=1)
    new_ver  = f"v{max_num + 1}"

    new_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem_bytes = new_private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    pub_pem = new_private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    try:
        create_versioned_secret("uppass-private-key-v1-b64", new_ver, base64.b64encode(pem_bytes))
        log.info("Stored new RSA key to Secret Manager (version=%s)", new_ver)
    except Exception as exc:
        log.error("RSA rotation aborted — Secret Manager write failed: %s", exc)
        raise HTTPException(status_code=503,
            detail=f"Secret Manager write failed — rotation aborted so state stays consistent across restarts. {type(exc).__name__}: {exc}")

    state.private_keys[new_ver] = new_private_key
    state.current_rsa_version   = new_ver
    log.info("RSA rotated to version=%s", new_ver)

    return RotateRSAResponse(
        new_version=new_ver,
        public_key=pub_pem,
        message=f"RSA key rotated to {new_ver}. New public key active. Old keys kept for decryption.",
    )


@router.post("/rotate-dek", response_model=RotateDEKResponse)
def rotate_dek(body: RotateDEKRequest = RotateDEKRequest(), db: Session = Depends(get_db)):
    """
    Chunked DEK rotation.

    First call: generates new DEK, stores to Secret Manager, hot-reloads, then
    re-encrypts up to chunk_size records.
    Subsequent calls: continues migrating remaining old-version records.
    Old DEK keys stay in state so unprocessed records remain readable during migration.
    """
    pending_count = db.query(NationalIdRecord).filter(
        NationalIdRecord.dek_version != state.current_dek_version
    ).count()

    if pending_count == 0:
        existing    = list(state.dek_keys.keys())
        max_num     = max((int(v[1:]) for v in existing if v.startswith("v") and v[1:].isdigit()), default=1)
        new_ver     = f"v{max_num + 1}"
        new_raw_hex = secrets.token_hex(32)
        new_dek     = hashlib.sha256(new_raw_hex.encode()).digest()

        try:
            create_versioned_secret("uppass-dek", new_ver, new_raw_hex.encode())
            log.info("Stored new DEK to Secret Manager")
        except Exception as exc:
            log.error("DEK rotation aborted — Secret Manager write failed: %s", exc)
            raise HTTPException(status_code=503,
                detail=f"Secret Manager write failed — rotation aborted so state stays consistent across restarts. {type(exc).__name__}: {exc}")

        state.dek_keys[new_ver]   = new_dek
        state.current_dek_version = new_ver
        log.info("DEK rotated to version=%s", new_ver)
    else:
        new_ver = state.current_dek_version
        log.info("Continuing DEK migration to version=%s, %d records pending", new_ver, pending_count)

    records = (
        db.query(NationalIdRecord)
        .filter(NationalIdRecord.dek_version != new_ver)
        .limit(body.chunk_size)
        .all()
    )

    reencrypted = 0
    for rec in records:
        old_key = state.dek_keys.get(rec.dek_version or "v1")
        if old_key is None:
            log.warning("Record %s has unknown dek_version=%s, skipping", rec.id, rec.dek_version)
            continue
        try:
            plaintext          = aes_gcm_decrypt(rec.encrypted_data, rec.storage_iv, old_key)
            new_ct, new_iv     = aes_gcm_encrypt(plaintext, state.dek_keys[new_ver])
            rec.encrypted_data = new_ct
            rec.storage_iv     = new_iv
            rec.dek_version    = new_ver
            reencrypted += 1
        except Exception as exc:
            log.error("Re-encrypt failed for record %s: %s", rec.id, exc)

    db.commit()

    remaining = db.query(NationalIdRecord).filter(NationalIdRecord.dek_version != new_ver).count()
    log.info("DEK chunk done: reencrypted=%d remaining=%d", reencrypted, remaining)

    return RotateDEKResponse(
        new_version=new_ver,
        reencrypted_records=reencrypted,
        remaining_records=remaining,
        message=(
            f"DEK migrated to {new_ver}: {reencrypted} re-encrypted, {remaining} remaining."
            if remaining > 0
            else f"DEK migration to {new_ver} complete. All records updated."
        ),
    )


@router.post("/rotate-hmac", response_model=RotateHMACResponse)
def rotate_hmac(body: RotateHMACRequest = RotateHMACRequest(), db: Session = Depends(get_db)):
    """
    Chunked HMAC rotation.

    All HMAC versions are loaded at startup so every instance has a consistent view.
    First call: generates new secret, stores to Secret Manager, hot-reloads, migrates chunk.
    Subsequent calls: continues migrating. Search works across all versions during migration.
    """
    pending_count = db.query(NationalIdRecord).filter(
        NationalIdRecord.hmac_version != state.current_hmac_version
    ).count()

    if pending_count == 0:
        cur_num        = int(state.current_hmac_version[1:]) if state.current_hmac_version[1:].isdigit() else 1
        new_ver        = f"v{cur_num + 1}"
        new_secret_hex = secrets.token_hex(32)
        new_secret     = new_secret_hex.encode()

        try:
            create_versioned_secret("uppass-hmac-secret", new_ver, new_secret)
            log.info("Stored new HMAC secret to Secret Manager")
        except Exception as exc:
            log.error("HMAC rotation aborted — Secret Manager write failed: %s", exc)
            raise HTTPException(status_code=503,
                detail=f"Secret Manager write failed — rotation aborted so state stays consistent across restarts. {type(exc).__name__}: {exc}")

        state.hmac_secrets[new_ver] = new_secret
        state.current_hmac_version  = new_ver
        log.info("HMAC rotated to version=%s", new_ver)
    else:
        new_ver = state.current_hmac_version
        log.info("Continuing HMAC migration to version=%s, %d records pending", new_ver, pending_count)

    records = (
        db.query(NationalIdRecord)
        .filter(NationalIdRecord.hmac_version != new_ver)
        .limit(body.chunk_size)
        .all()
    )

    recomputed = 0
    for rec in records:
        dek_key = state.dek_keys.get(rec.dek_version or "v1")
        if dek_key is None:
            log.warning("Record %s has unknown dek_version=%s, skipping", rec.id, rec.dek_version)
            continue
        try:
            plaintext        = aes_gcm_decrypt(rec.encrypted_data, rec.storage_iv, dek_key)
            rec.search_index = compute_blind_index(plaintext, new_ver)
            rec.hmac_version = new_ver
            recomputed += 1
        except Exception as exc:
            log.error("Recompute failed for record %s: %s", rec.id, exc)

    db.commit()

    remaining = db.query(NationalIdRecord).filter(NationalIdRecord.hmac_version != new_ver).count()
    log.info("HMAC chunk done: recomputed=%d remaining=%d", recomputed, remaining)

    return RotateHMACResponse(
        new_version=new_ver,
        recomputed_records=recomputed,
        remaining_records=remaining,
        message=(
            f"HMAC migrated to {new_ver}: {recomputed} recomputed, {remaining} remaining."
            if remaining > 0
            else f"HMAC migration to {new_ver} complete. All records updated."
        ),
    )


@router.post("/reset-demo")
def reset_demo(db: Session = Depends(get_db)):
    """Delete all records AND reset in-memory key state to v1. Demo use only."""
    deleted = db.query(NationalIdRecord).delete()
    db.commit()

    def _keep_first(d: dict) -> None:
        first = next(iter(d.values()), None)
        d.clear()
        if first is not None:
            d["v1"] = first

    _keep_first(state.dek_keys);     state.current_dek_version  = "v1"
    _keep_first(state.private_keys); state.current_rsa_version  = "v1"
    _keep_first(state.hmac_secrets); state.current_hmac_version = "v1"

    log.info("Demo reset: deleted %d records, all key states reset to v1", deleted)
    return {"deleted_records": deleted, "message": "Demo reset complete. All records deleted, key versions reset to v1."}
