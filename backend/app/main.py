"""
UpPass Verification Service — FastAPI Backend

Endpoints:
  POST /v1/submit              — Decrypt E2E payload, store with blind index
  GET  /v1/search              — Search by National ID (tries all known HMAC versions)
  GET  /v1/public-key          — Return current RSA public key
  GET  /v1/admin/status        — Current key versions and record counts
  POST /v1/admin/rotate-rsa    — Generate new RSA pair, hot-reload
  POST /v1/admin/rotate-dek    — Generate new DEK, re-encrypt all records
  POST /v1/admin/rotate-hmac   — Generate new HMAC secret, chunked blind-index migration
  GET  /health                 — Liveness probe

Security design:
  - Private key loaded once at startup into memory, never logged
  - Plaintext National IDs never written to logs (middleware enforced)
  - Blind index (HMAC-SHA256) enables exact-match search without decrypting
  - Randomised encryption (AES-GCM with random IV) for storage column
  - HMAC versioning: all known HMAC versions loaded from Secret Manager at startup;
    search tries every version so records remain findable across restarts and during migration
"""

import os
import base64
import hashlib
import hmac as hmac_mod
import secrets
import logging
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parents[2] / ".env")
except ImportError:
    pass

from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, String, Text, DateTime, text
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from datetime import datetime, timezone

# ─── Logging (PII-safe) ──────────────────────────────────────────────────────

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("uppass")

# ─── Config from environment ─────────────────────────────────────────────────

DATABASE_URL     = os.environ.get("DATABASE_URL", "sqlite:///./uppass.db")
PRIVATE_KEY_PATH = os.environ.get("PRIVATE_KEY_PATH", "keys/private.pem")
GCP_PROJECT_ID   = os.environ.get("GOOGLE_CLOUD_PROJECT", "")

# ─── Mutable server state (hot-reloadable keys) ──────────────────────────────

class _State:
    def __init__(self):
        self.private_keys: dict        = {}    # version → RSA private key object
        self.current_rsa_version: str  = "v1"
        self.dek_keys: dict            = {}    # version → 32-byte AES key (bytes)
        self.current_dek_version: str  = "v1"
        self.hmac_secrets: dict        = {}    # version → bytes (same pattern as dek_keys/private_keys)
        self.current_hmac_version: str = "v1"

state = _State()

# ─── Database ────────────────────────────────────────────────────────────────

_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine        = create_engine(DATABASE_URL, connect_args=_connect_args, pool_pre_ping=True)
SessionLocal  = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base          = declarative_base()


class NationalIdRecord(Base):
    __tablename__ = "national_ids"

    id             = Column(String(32),  primary_key=True, default=lambda: secrets.token_hex(16))
    encrypted_data = Column(Text,        nullable=False)
    storage_iv     = Column(String(24),  nullable=False)
    search_index   = Column(String(64),  nullable=False, index=True)
    key_version    = Column(String(10),  nullable=False, default="v1")
    dek_version    = Column(String(10),  nullable=False, default="v1")
    hmac_version   = Column(String(10),  nullable=False, default="v1")
    created_at     = Column(DateTime,    default=lambda: datetime.now(timezone.utc))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _db_distinct_versions(column: str) -> set:
    """Return the set of distinct version labels stored in national_ids for a given column."""
    try:
        with engine.connect() as conn:
            rows = conn.execute(
                text(f"SELECT DISTINCT {column} FROM national_ids WHERE {column} IS NOT NULL")
            ).fetchall()
        return {row[0] for row in rows if row[0]}
    except Exception:
        return set()


def _ensure_columns():
    """Add dek_version and hmac_version columns if they don't exist (idempotent)."""
    for col_ddl in [
        "ALTER TABLE national_ids ADD COLUMN dek_version  VARCHAR(10) NOT NULL DEFAULT 'v1'",
        "ALTER TABLE national_ids ADD COLUMN hmac_version VARCHAR(10) NOT NULL DEFAULT 'v1'",
    ]:
        with engine.connect() as conn:
            try:
                conn.execute(text(col_ddl))
                conn.commit()
            except Exception:
                pass  # column already exists


# ─── Secret Manager helper ───────────────────────────────────────────────────

def _secret_manager_client():
    from google.cloud import secretmanager
    return secretmanager.SecretManagerServiceClient()


def _sm_project() -> str:
    project = GCP_PROJECT_ID
    if not project:
        import subprocess
        try:
            result = subprocess.run(
                ["gcloud", "config", "get-value", "project"],
                capture_output=True, text=True, timeout=5
            )
            project = result.stdout.strip()
        except Exception:
            pass
    if not project:
        raise RuntimeError("Cannot determine GCP project — set GOOGLE_CLOUD_PROJECT env var")
    return project


def _load_secret_version(secret_id: str, version: int) -> str:
    """Fetch a specific numbered version of a Secret Manager secret."""
    client = _secret_manager_client()
    name   = f"projects/{_sm_project()}/secrets/{secret_id}/versions/{version}"
    resp   = client.access_secret_version(request={"name": name})
    return resp.payload.data.decode("utf-8")


def _store_secret_version(secret_id: str, data: bytes) -> str:
    """Add a new version to an existing Secret Manager secret. Returns version name."""
    client  = _secret_manager_client()
    project = _sm_project()
    parent  = f"projects/{project}/secrets/{secret_id}"
    resp    = client.add_secret_version(
        request={"parent": parent, "payload": {"data": data}}
    )
    log.info("Stored new secret version: %s", resp.name)
    return resp.name


# ─── Key management ──────────────────────────────────────────────────────────

def load_private_keys() -> None:
    """
    Load ALL RSA private key versions referenced in the DB from Secret Manager.
    Falls back to PRIVATE_KEY_B64 env var or key files for v1 (local dev).

    Versions in DB (key_version column) map 1-to-1 with Secret Manager version
    numbers on the 'uppass-private-key-v1-b64' secret:
      DB "v1" → SM version 1
      DB "v2" → SM version 2  (after rotate-rsa)
      etc.
    """
    versions_needed = _db_distinct_versions("key_version")
    versions_needed.add("v1")  # always need v1 for new installs with empty DB

    for ver in sorted(versions_needed, key=lambda v: int(v[1:])):
        ver_num = int(ver[1:])

        # Try Secret Manager first (authoritative in production)
        try:
            raw_b64 = _load_secret_version("uppass-private-key-v1-b64", ver_num)
            pem = base64.b64decode(raw_b64)
            state.private_keys[ver] = serialization.load_pem_private_key(pem, password=None)
            log.info("Loaded RSA key version=%s from Secret Manager", ver)
            continue
        except Exception:
            pass

        # v1 fallback: env var (Cloud Run initial deploy) or key files (local dev)
        if ver == "v1":
            key_b64 = os.environ.get("PRIVATE_KEY_B64", "")
            if key_b64:
                pem = base64.b64decode(key_b64)
                state.private_keys["v1"] = serialization.load_pem_private_key(pem, password=None)
                log.info("Loaded RSA key version=v1 from env var")
                continue

            key_dir = os.path.dirname(PRIVATE_KEY_PATH)
            if os.path.isdir(key_dir):
                for fname in os.listdir(key_dir):
                    if fname.startswith("private_") and fname.endswith(".pem"):
                        fver = fname.replace("private_", "").replace(".pem", "")
                        with open(os.path.join(key_dir, fname), "rb") as f:
                            state.private_keys[fver] = serialization.load_pem_private_key(f.read(), password=None)
                        log.info("Loaded RSA key version=%s from file", fver)
            elif os.path.exists(PRIVATE_KEY_PATH):
                with open(PRIVATE_KEY_PATH, "rb") as f:
                    state.private_keys["v1"] = serialization.load_pem_private_key(f.read(), password=None)
                log.info("Loaded RSA key version=v1 from file path")

    if not state.private_keys:
        raise RuntimeError("No private key loaded — set PRIVATE_KEY_B64 or PRIVATE_KEY_PATH")

    state.current_rsa_version = max(state.private_keys.keys(), key=lambda v: int(v[1:]))


def init_dek() -> None:
    """
    Load ALL DEK versions referenced in the DB from Secret Manager.
    DB column 'dek_version' label "vN" maps to SM version number N.
    Falls back to DATA_ENCRYPTION_KEY env var for v1 (local dev / initial deploy).
    """
    versions_needed = _db_distinct_versions("dek_version")
    versions_needed.add("v1")

    for ver in sorted(versions_needed, key=lambda v: int(v[1:])):
        ver_num = int(ver[1:])

        try:
            raw = _load_secret_version("uppass-dek", ver_num)
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
    DB column 'hmac_version' label "vN" maps to SM version number N.
    Falls back to HMAC_SECRET env var for v1 (local dev / initial deploy).
    """
    versions_needed = _db_distinct_versions("hmac_version")
    versions_needed.add("v1")

    for ver in sorted(versions_needed, key=lambda v: int(v[1:])):
        ver_num = int(ver[1:])

        try:
            raw = _load_secret_version("uppass-hmac-secret", ver_num)
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


def get_private_key(version: str = "v1"):
    key = state.private_keys.get(version)
    if not key:
        raise HTTPException(status_code=500, detail=f"Unknown key version: {version}")
    return key


# ─── Crypto helpers ──────────────────────────────────────────────────────────

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
    plaintext  = aesgcm.decrypt(iv, ciphertext, associated_data=None)
    return plaintext.decode("utf-8")


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


def get_storage_key(dek_ver: str = "v1") -> bytes:
    key = state.dek_keys.get(dek_ver)
    if not key:
        raise HTTPException(status_code=500, detail=f"Unknown DEK version: {dek_ver}")
    return key


# ─── Lifespan ────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    _ensure_columns()
    load_private_keys()
    init_dek()
    init_hmac()
    log.info("UpPass Verification Service started")
    yield
    log.info("UpPass Verification Service stopped")


# ─── App ─────────────────────────────────────────────────────────────────────

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


# ─── Schemas ─────────────────────────────────────────────────────────────────

class SubmitRequest(BaseModel):
    encrypted_data: str = Field(..., description="AES-GCM ciphertext, base64")
    encrypted_key:  str = Field(..., description="RSA-OAEP wrapped AES key, base64")
    iv:             str = Field(..., description="AES-GCM IV, base64")
    key_version:    str = Field(default="v1", description="RSA key version")


class SubmitResponse(BaseModel):
    ref:     str
    message: str


class SearchResponse(BaseModel):
    found:      bool
    ref:        Optional[str]
    created_at: Optional[str]


class AdminStatusResponse(BaseModel):
    rsa_version:   str
    dek_version:   str
    hmac_version:  str
    total_records: int
    dek_pending:   int   # records not yet on current DEK version
    hmac_pending:  int   # records not yet on current HMAC version


class RotateRSAResponse(BaseModel):
    new_version: str
    public_key:  str
    message:     str


class RotateDEKRequest(BaseModel):
    chunk_size: int = Field(default=1000, ge=1, le=50000, description="Records to re-encrypt per call")


class RotateDEKResponse(BaseModel):
    new_version:         str
    reencrypted_records: int
    remaining_records:   int
    message:             str


class RotateHMACRequest(BaseModel):
    chunk_size: int = Field(default=1000, ge=1, le=50000, description="Records to migrate per call")


class RotateHMACResponse(BaseModel):
    new_version:        str
    recomputed_records: int
    remaining_records:  int
    message:            str


# ─── Endpoints ───────────────────────────────────────────────────────────────

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
      - `national_id` is NEVER passed to log.*
      - Storage uses a fresh random IV (randomised encryption per record)
      - Search index uses HMAC-SHA256 (deterministic, searchable)
    """
    try:
        aes_key    = unwrap_aes_key(body.encrypted_key, body.key_version)
        national_id = aes_gcm_decrypt(body.encrypted_data, body.iv, aes_key)

        dek_ver    = state.current_dek_version
        hmac_ver   = state.current_hmac_version
        storage_key = get_storage_key(dek_ver)
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

    except ValueError as exc:
        log.warning("Decryption failed: %s", type(exc).__name__)
        raise HTTPException(status_code=400, detail="Invalid encrypted payload")
    except Exception as exc:
        log.error("Submit error: %s", type(exc).__name__)
        raise HTTPException(status_code=500, detail="Internal error")


@app.get("/v1/search", response_model=SearchResponse)
def search(national_id: str, db: Session = Depends(get_db)):
    # Try every loaded HMAC version — records remain findable during migration window
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


# ─── Admin endpoints (demo key rotation) ─────────────────────────────────────

@app.get("/v1/admin/status", response_model=AdminStatusResponse)
def admin_status(db: Session = Depends(get_db)):
    total        = db.query(NationalIdRecord).count()
    dek_pending  = (
        db.query(NationalIdRecord)
        .filter(NationalIdRecord.dek_version != state.current_dek_version)
        .count()
    )
    hmac_pending = (
        db.query(NationalIdRecord)
        .filter(NationalIdRecord.hmac_version != state.current_hmac_version)
        .count()
    )
    return AdminStatusResponse(
        rsa_version=state.current_rsa_version,
        dek_version=state.current_dek_version,
        hmac_version=state.current_hmac_version,
        total_records=total,
        dek_pending=dek_pending,
        hmac_pending=hmac_pending,
    )


@app.post("/v1/admin/rotate-rsa", response_model=RotateRSAResponse)
def rotate_rsa():
    """
    Generate a new RSA-2048 key pair, store base64 PEM to Secret Manager,
    hot-reload into state. New submissions will use the new key version.
    Existing records remain decryptable (old keys kept in state).
    """
    # Determine next version
    existing  = list(state.private_keys.keys())
    max_num   = max((int(v[1:]) for v in existing if v.startswith("v") and v[1:].isdigit()), default=1)
    new_ver   = f"v{max_num + 1}"

    # Generate new RSA-2048 key pair
    new_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    pem_bytes = new_private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    pub_pem = new_private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    # Store to Secret Manager (best-effort; skip if no GCP project configured)
    secret_stored = False
    try:
        b64_pem = base64.b64encode(pem_bytes)
        _store_secret_version("uppass-private-key-v1-b64", b64_pem)
        secret_stored = True
        log.info("Stored new RSA key to Secret Manager as new version of uppass-private-key-v1-b64")
    except Exception as exc:
        log.warning("Secret Manager store skipped (%s) — running in demo mode", type(exc).__name__)

    # Hot-reload
    state.private_keys[new_ver]  = new_private_key
    state.current_rsa_version    = new_ver
    log.info("RSA key rotated to version=%s (secret_stored=%s)", new_ver, secret_stored)

    return RotateRSAResponse(
        new_version=new_ver,
        public_key=pub_pem,
        message=f"RSA key rotated to {new_ver}. New public key active. Old keys still available for decryption."
        + ("" if secret_stored else " [Demo mode: Secret Manager not updated]"),
    )


@app.post("/v1/admin/rotate-dek", response_model=RotateDEKResponse)
def rotate_dek(body: RotateDEKRequest = RotateDEKRequest(), db: Session = Depends(get_db)):
    """
    Chunked DEK rotation — same pattern as rotate_hmac.

    First call: generates a new DEK, stores to Secret Manager, hot-reloads
    state.dek_keys, then re-encrypts up to chunk_size records.

    Subsequent calls: continues re-encrypting remaining old-version records.
    During the migration window, reads work for all versions (old keys remain
    in state.dek_keys); new writes use the new DEK version.
    """
    pending_count = (
        db.query(NationalIdRecord)
        .filter(NationalIdRecord.dek_version != state.current_dek_version)
        .count()
    )

    if pending_count == 0:
        # Fresh rotation: bump version, generate new DEK
        existing = list(state.dek_keys.keys())
        max_num  = max((int(v[1:]) for v in existing if v.startswith("v") and v[1:].isdigit()), default=1)
        new_ver     = f"v{max_num + 1}"
        new_raw_hex = secrets.token_hex(32)
        new_dek     = hashlib.sha256(new_raw_hex.encode()).digest()

        # Store to Secret Manager (best-effort)
        secret_stored = False
        try:
            _store_secret_version("uppass-dek", new_raw_hex.encode())
            secret_stored = True
            log.info("Stored new DEK to Secret Manager")
        except Exception as exc:
            log.warning("Secret Manager store skipped (%s) — demo mode", type(exc).__name__)

        # Hot-reload — add to dict, old keys remain for reading existing records
        state.dek_keys[new_ver]   = new_dek
        state.current_dek_version = new_ver
        log.info("DEK rotated to version=%s (secret_stored=%s)", new_ver, secret_stored)
    else:
        new_ver = state.current_dek_version
        log.info("Continuing DEK migration to version=%s, %d records pending", new_ver, pending_count)

    # Re-encrypt one chunk of records still on an old DEK version
    records = (
        db.query(NationalIdRecord)
        .filter(NationalIdRecord.dek_version != new_ver)
        .limit(body.chunk_size)
        .all()
    )

    reencrypted = 0
    for rec in records:
        old_dek_ver = rec.dek_version or "v1"
        old_key     = state.dek_keys.get(old_dek_ver)
        if old_key is None:
            log.warning("Record %s has unknown dek_version=%s, skipping", rec.id, old_dek_ver)
            continue
        try:
            plaintext          = aes_gcm_decrypt(rec.encrypted_data, rec.storage_iv, old_key)
            new_ct, new_iv     = aes_gcm_encrypt(plaintext, state.dek_keys[new_ver])
            rec.encrypted_data = new_ct
            rec.storage_iv     = new_iv
            rec.dek_version    = new_ver
            reencrypted += 1
        except Exception as exc:
            log.error("Failed to re-encrypt record %s: %s — %s", rec.id, type(exc).__name__, exc)

    db.commit()

    remaining = (
        db.query(NationalIdRecord)
        .filter(NationalIdRecord.dek_version != new_ver)
        .count()
    )
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


@app.post("/v1/admin/rotate-hmac", response_model=RotateHMACResponse)
def rotate_hmac(body: RotateHMACRequest = RotateHMACRequest(), db: Session = Depends(get_db)):
    """
    Chunked HMAC rotation — same pattern as DEK/RSA rotation.

    All HMAC versions are loaded from Secret Manager at startup so every instance
    has a consistent view of all secrets across restarts.

    First call: generates a new secret, adds to state.hmac_secrets, stores to
    Secret Manager, then migrates up to chunk_size records.

    Subsequent calls: continues migrating remaining records.
    During the migration window new submissions use the new secret;
    not-yet-migrated records are temporarily unsearchable (same trade-off as DEK
    chunked rotation — acceptable at low traffic / off-peak).
    """
    pending_count = (
        db.query(NationalIdRecord)
        .filter(NationalIdRecord.hmac_version != state.current_hmac_version)
        .count()
    )

    if pending_count == 0:
        # Fresh rotation: bump version, generate new secret
        cur_num   = int(state.current_hmac_version[1:]) if state.current_hmac_version[1:].isdigit() else 1
        new_ver   = f"v{cur_num + 1}"
        new_secret_hex = secrets.token_hex(32)
        new_secret     = new_secret_hex.encode()

        # Store to Secret Manager (best-effort)
        secret_stored = False
        try:
            _store_secret_version("uppass-hmac-secret", new_secret)
            secret_stored = True
            log.info("Stored new HMAC secret to Secret Manager")
        except Exception as exc:
            log.warning("Secret Manager store skipped (%s) — demo mode", type(exc).__name__)

        # Hot-reload — add to dict, same pattern as dek_keys / private_keys
        state.hmac_secrets[new_ver] = new_secret
        state.current_hmac_version  = new_ver
        log.info("HMAC rotated to version=%s (secret_stored=%s)", new_ver, secret_stored)
    else:
        new_ver = state.current_hmac_version
        log.info("Continuing HMAC migration to version=%s, %d records pending", new_ver, pending_count)

    # Migrate one chunk of not-yet-updated records
    records = (
        db.query(NationalIdRecord)
        .filter(NationalIdRecord.hmac_version != new_ver)
        .limit(body.chunk_size)
        .all()
    )

    recomputed = 0
    for rec in records:
        dek_ver = rec.dek_version or "v1"
        dek_key = state.dek_keys.get(dek_ver)
        if dek_key is None:
            log.warning("Record %s has unknown dek_version=%s, skipping", rec.id, dek_ver)
            continue
        try:
            plaintext        = aes_gcm_decrypt(rec.encrypted_data, rec.storage_iv, dek_key)
            rec.search_index = compute_blind_index(plaintext, new_ver)
            rec.hmac_version = new_ver
            recomputed += 1
        except Exception as exc:
            log.error("Failed to recompute record %s: %s — %s", rec.id, type(exc).__name__, exc)

    db.commit()

    remaining = (
        db.query(NationalIdRecord)
        .filter(NationalIdRecord.hmac_version != new_ver)
        .count()
    )
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


# ─── Security monitoring demo endpoints ──────────────────────────────────────

# Marker written to Cloud Logging when the unsafe endpoint is called.
# Used as the log-based metric filter and Logs Explorer query.
_VIOLATION_MARKER = "SECURITY_VIOLATION"


@app.post("/v1/submit-unsafe", response_model=SubmitResponse)
def submit_unsafe(body: SubmitRequest, db: Session = Depends(get_db)):
    """
    Intentionally insecure submit — logs the plaintext national_id to stdout.
    Simulates a developer accidentally exposing PII in application logs.
    Used only for the security monitoring demo.
    """
    try:
        aes_key     = unwrap_aes_key(body.encrypted_key, body.key_version)
        national_id = aes_gcm_decrypt(body.encrypted_data, body.iv, aes_key)

        # ⚠ INTENTIONAL SECURITY VIOLATION — never do this in real code
        log.warning("%s: national_id=%s logged by unsafe endpoint", _VIOLATION_MARKER, national_id)

        dek_ver     = state.current_dek_version
        hmac_ver    = state.current_hmac_version
        storage_key = get_storage_key(dek_ver)
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

    except ValueError as exc:
        log.warning("Decryption failed: %s", type(exc).__name__)
        raise HTTPException(status_code=400, detail="Invalid encrypted payload")
    except Exception as exc:
        log.error("Submit-unsafe error: %s", type(exc).__name__)
        raise HTTPException(status_code=500, detail="Internal error")


@app.get("/v1/admin/monitor/violations")
def get_violations(limit: int = 20):
    """
    Query Cloud Logging for recent SECURITY_VIOLATION entries.
    Returns log lines so the frontend can display a live PII-leak feed.
    """
    try:
        from google.cloud import logging as gcp_logging
        client  = gcp_logging.Client(project=_sm_project())
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


@app.post("/v1/admin/reset-demo")
def reset_demo(db: Session = Depends(get_db)):
    """Delete all records and reset in-memory key state to v1. Demo use only."""
    deleted = db.query(NationalIdRecord).delete()
    db.commit()

    # Reset all in-memory key state to v1
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
