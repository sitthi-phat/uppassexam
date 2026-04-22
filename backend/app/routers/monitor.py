"""
Security monitoring router — intentional PII-leak demo + Cloud Logging violations feed.

These endpoints exist solely for the security monitoring demo and are kept separate
from both the core API and the admin rotation utilities.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..state import state
from ..database import NationalIdRecord, get_db
from ..crypto import unwrap_aes_key, aes_gcm_decrypt, aes_gcm_encrypt, compute_blind_index
from ..gcp import sm_project
from ..schemas import SubmitRequest, SubmitResponse

log    = logging.getLogger("uppass")
router = APIRouter(tags=["monitor"])

_VIOLATION_MARKER = "SECURITY_VIOLATION"


@router.post("/v1/submit-unsafe", response_model=SubmitResponse)
def submit_unsafe(body: SubmitRequest, db: Session = Depends(get_db)):
    """
    Intentionally insecure submit — logs plaintext national_id to stdout.
    Simulates a developer accidentally exposing PII in application logs.
    Triggers the Cloud Logging-based violation alert.
    """
    try:
        aes_key     = unwrap_aes_key(body.encrypted_key, body.key_version)
        national_id = aes_gcm_decrypt(body.encrypted_data, body.iv, aes_key)

        # INTENTIONAL SECURITY VIOLATION — never do this in real code
        log.warning("%s: national_id=%s logged by unsafe endpoint", _VIOLATION_MARKER, national_id)

        dek_ver     = state.current_dek_version
        hmac_ver    = state.current_hmac_version
        storage_key = state.dek_keys[dek_ver]
        storage_ciphertext, storage_iv = aes_gcm_encrypt(national_id, storage_key)
        blind_index = compute_blind_index(national_id)

        record = NationalIdRecord(
            encrypted_data=storage_ciphertext,
            storage_iv=storage_iv,
            search_index=blind_index,
            key_version=body.key_version,
            dek_version=dek_ver,
            hmac_version=hmac_ver,
        )
        db.add(record)
        db.commit()
        db.refresh(record)

        log.info("Stored (unsafe) record ref=%s", record.id)
        return SubmitResponse(ref=record.id, message="Stored — WARNING: national ID was written to logs")

    except ValueError:
        log.warning("Decryption failed in submit-unsafe")
        raise HTTPException(status_code=400, detail="Invalid encrypted payload")
    except Exception as exc:
        log.error("Submit-unsafe error: %s", type(exc).__name__)
        raise HTTPException(status_code=500, detail="Internal error")


@router.get("/v1/admin/monitor/violations")
def get_violations(limit: int = 20):
    """Query Cloud Logging for recent SECURITY_VIOLATION entries."""
    try:
        from google.cloud import logging as gcp_logging
        client  = gcp_logging.Client(project=sm_project())
        filter_ = (
            'resource.type="cloud_run_revision" '
            'resource.labels.service_name="uppass-api" '
            f'textPayload=~"{_VIOLATION_MARKER}"'
        )
        entries = []
        for entry in client.list_entries(
            filter_=filter_,
            order_by=gcp_logging.DESCENDING,
            page_size=limit,
        ):
            entries.append({
                "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
                "payload":   str(entry.payload),
                "severity":  str(entry.severity),
            })
            if len(entries) >= limit:
                break
        return {"violations": entries, "count": len(entries)}

    except Exception as exc:
        log.warning("Could not fetch violations from Cloud Logging: %s", exc)
        return {"violations": [], "count": 0, "error": str(exc)}
