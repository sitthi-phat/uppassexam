"""
UpPass Verification Service — FastAPI backend

Core API (primary):
  GET  /v1/public-key  — Current RSA public key for client-side encryption
  POST /v1/submit      — Receive E2E-encrypted payload, decrypt, store with blind index
  GET  /v1/search      — Search by National ID (tries all known HMAC versions)
  GET  /health         — Liveness probe

Admin & utility (secondary, see routers/):
  GET  /v1/admin/status              — Key versions and record counts
  GET  /v1/admin/records             — All record metadata (no decrypted data)
  POST /v1/admin/records/delete-all  — Delete all records (key state unchanged)
  POST /v1/admin/rotate-rsa          — Generate new RSA pair, hot-reload
  POST /v1/admin/rotate-dek          — Chunked DEK re-encryption
  POST /v1/admin/rotate-hmac         — Chunked HMAC blind-index migration
  POST /v1/admin/reset-demo          — Delete records + reset key state to v1

Security monitoring (secondary, see routers/monitor.py):
  POST /v1/submit-unsafe             — Intentionally logs PII (demo only)
  GET  /v1/admin/monitor/violations  — Cloud Logging PII-leak feed
"""

import os
import logging
from pathlib import Path
from contextlib import asynccontextmanager

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parents[2] / ".env")
except ImportError:
    pass

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from .state import state
from .database import Base, engine, NationalIdRecord, get_db, ensure_columns
from .crypto import unwrap_aes_key, aes_gcm_decrypt, aes_gcm_encrypt, compute_blind_index
from .startup import load_private_keys, init_dek, init_hmac
from .schemas import SubmitRequest, SubmitResponse, SearchResponse
from .routers import admin, monitor
from cryptography.hazmat.primitives import serialization

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("uppass")


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(_app: FastAPI):
    Base.metadata.create_all(bind=engine)
    ensure_columns()
    load_private_keys()
    init_dek()
    init_hmac()
    log.info("UpPass started — RSA=%s DEK=%s HMAC=%s",
             state.current_rsa_version, state.current_dek_version, state.current_hmac_version)
    yield
    log.info("UpPass stopped")


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="UpPass Verification Service",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if os.environ.get("ENABLE_DOCS", "true").lower() == "true" else None,
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000").split(","),
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)

app.include_router(admin.router)
app.include_router(monitor.router)


# ── Core API ──────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/v1/public-key")
def public_key():
    ver = state.current_rsa_version
    pk  = state.private_keys.get(ver)
    if not pk:
        raise HTTPException(status_code=503, detail="No key loaded")
    pub_pem = pk.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return {"key_version": ver, "public_key": pub_pem}


@app.post("/v1/submit", response_model=SubmitResponse)
def submit(body: SubmitRequest, db: Session = Depends(get_db)):
    """
    Receive E2E-encrypted payload, decrypt, store with blind index.

    Security notes:
      - national_id is NEVER passed to log.*
      - Storage uses a fresh random IV per record (randomised encryption)
      - Search index uses HMAC-SHA256 (deterministic, searchable without decryption)
    """
    try:
        aes_key     = unwrap_aes_key(body.encrypted_key, body.key_version)
        national_id = aes_gcm_decrypt(body.encrypted_data, body.iv, aes_key)

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

        log.info("Stored record ref=%s key_version=%s dek_version=%s hmac_version=%s",
                 record.id, body.key_version, dek_ver, hmac_ver)
        return SubmitResponse(ref=record.id, message="Stored successfully")

    except ValueError:
        log.warning("Decryption failed")
        raise HTTPException(status_code=400, detail="Invalid encrypted payload")
    except Exception as exc:
        log.error("Submit error: %s", type(exc).__name__)
        raise HTTPException(status_code=500, detail="Internal error")


@app.get("/v1/search", response_model=SearchResponse)
def search(national_id: str, db: Session = Depends(get_db)):
    # Try every loaded HMAC version newest-first — records stay findable during migration
    for ver in sorted(state.hmac_secrets.keys(), key=lambda v: int(v[1:]), reverse=True):
        blind_index = compute_blind_index(national_id, ver)
        record = (
            db.query(NationalIdRecord)
            .filter(NationalIdRecord.search_index == blind_index)
            .first()
        )
        if record:
            return SearchResponse(
                found=True,
                ref=record.id,
                created_at=record.created_at.isoformat() if record.created_at else None,
            )
    return SearchResponse(found=False, ref=None, created_at=None)
