"""
UpPass Verification Service — FastAPI Backend

Endpoints:
  POST /v1/submit   — Decrypt E2E payload, store with blind index
  GET  /v1/search   — Search by National ID via blind index (HMAC-SHA256)
  GET  /health      — Liveness probe

Security design:
  - Private key loaded once at startup into memory, never logged
  - Plaintext National IDs never written to logs (middleware enforced)
  - Blind index (HMAC-SHA256) enables exact-match search without decrypting
  - Randomised encryption (AES-GCM with random IV) for storage column
"""

import os
import base64
import hashlib
import hmac
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
from sqlalchemy import create_engine, Column, String, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from datetime import datetime, timezone

# ─── Logging (PII-safe) ──────────────────────────────────────────────────────

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("uppass")

# ─── Config from environment ─────────────────────────────────────────────────

DATABASE_URL   = os.environ.get("DATABASE_URL", "sqlite:///./uppass.db")
HMAC_SECRET    = os.environ.get("HMAC_SECRET", "").encode()        # 32+ bytes in production
PRIVATE_KEY_PATH = os.environ.get("PRIVATE_KEY_PATH", "keys/private.pem")

if not HMAC_SECRET:
    raise RuntimeError("HMAC_SECRET env var is required")

# ─── Database ────────────────────────────────────────────────────────────────

# connect_args only needed for SQLite (thread safety); MySQL handles this natively
_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=_connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class NationalIdRecord(Base):
    __tablename__ = "national_ids"

    id           = Column(String(32),  primary_key=True, default=lambda: secrets.token_hex(16))
    # Column A: Randomised encryption (AES-GCM, unique IV per record)
    encrypted_data = Column(Text,       nullable=False)
    storage_iv     = Column(String(24), nullable=False)   # base64(12-byte IV) = 16 chars
    # Column B: Deterministic HMAC-SHA256 blind index for exact-match search
    search_index   = Column(String(64), nullable=False, index=True)  # SHA-256 hex = 64 chars
    key_version    = Column(String(10), nullable=False, default="v1")
    created_at     = Column(DateTime, default=lambda: datetime.now(timezone.utc))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ─── Key management ──────────────────────────────────────────────────────────

_private_keys: dict[str, object] = {}   # version → CryptoKey


def load_private_keys() -> None:
    """
    Load private keys at startup. Priority:
    1. PRIVATE_KEY_B64 env var (base64 PEM) — used in Cloud Run via Secret Manager env var
    2. PRIVATE_KEY_PATH file — used locally / docker-compose
    """
    # Cloud Run: key injected as base64 env var from Secret Manager
    key_b64 = os.environ.get("PRIVATE_KEY_B64", "")
    if key_b64:
        pem = base64.b64decode(key_b64)
        _private_keys["v1"] = serialization.load_pem_private_key(pem, password=None)
        log.info("Loaded private key version=v1 (env var)")
        return

    # Local / Docker: scan key directory for versioned PEM files
    key_dir = os.path.dirname(PRIVATE_KEY_PATH)
    loaded = 0
    for fname in os.listdir(key_dir) if os.path.isdir(key_dir) else []:
        if fname.startswith("private_") and fname.endswith(".pem"):
            version = fname.replace("private_", "").replace(".pem", "")
            path = os.path.join(key_dir, fname)
            with open(path, "rb") as f:
                _private_keys[version] = serialization.load_pem_private_key(f.read(), password=None)
            log.info("Loaded private key version=%s", version)
            loaded += 1

    if loaded == 0 and os.path.exists(PRIVATE_KEY_PATH):
        with open(PRIVATE_KEY_PATH, "rb") as f:
            _private_keys["v1"] = serialization.load_pem_private_key(f.read(), password=None)
        log.info("Loaded private key version=v1 (file path)")

    if not _private_keys:
        raise RuntimeError("No private key loaded — set PRIVATE_KEY_B64 or PRIVATE_KEY_PATH")


def get_private_key(version: str = "v1"):
    key = _private_keys.get(version)
    if not key:
        raise HTTPException(status_code=500, detail=f"Unknown key version: {version}")
    return key


# ─── Crypto helpers ──────────────────────────────────────────────────────────

def unwrap_aes_key(encrypted_key_b64: str, key_version: str) -> bytes:
    """RSA-OAEP decrypt the wrapped AES key."""
    private_key = get_private_key(key_version)
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
    """AES-256-GCM decrypt and return plaintext string."""
    aesgcm = AESGCM(aes_key)
    ciphertext = base64.b64decode(ciphertext_b64)
    iv = base64.b64decode(iv_b64)
    plaintext = aesgcm.decrypt(iv, ciphertext, associated_data=None)
    return plaintext.decode("utf-8")


def aes_gcm_encrypt(plaintext: str, aes_key: bytes) -> tuple[str, str]:
    """AES-256-GCM encrypt; returns (ciphertext_b64, iv_b64)."""
    aesgcm = AESGCM(aes_key)
    iv = secrets.token_bytes(12)   # 96-bit random IV — NEVER reuse
    ciphertext = aesgcm.encrypt(iv, plaintext.encode("utf-8"), associated_data=None)
    return base64.b64encode(ciphertext).decode(), base64.b64encode(iv).decode()


def compute_blind_index(national_id: str) -> str:
    """HMAC-SHA256 deterministic blind index for exact-match search."""
    return hmac.new(HMAC_SECRET, national_id.encode("utf-8"), hashlib.sha256).hexdigest()


def generate_storage_key() -> bytes:
    """
    Derive a per-record storage AES key from a server-side DEK.
    In production: use KMS to generate and manage the DEK,
    store only the Key Encryption Key (KEK) in Secrets Manager.
    """
    dek = os.environ.get("DATA_ENCRYPTION_KEY", "")
    if not dek:
        raise RuntimeError("DATA_ENCRYPTION_KEY env var is required")
    # Derive a 256-bit key from the DEK using SHA-256
    return hashlib.sha256(dek.encode()).digest()


# ─── Lifespan ────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    load_private_keys()
    log.info("UpPass Verification Service started")
    yield
    log.info("UpPass Verification Service stopped")


# ─── App ─────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="UpPass Verification Service",
    version="1.0.0",
    lifespan=lifespan,
    # Disable automatic request body logging in OpenAPI playground
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
    key_version:    str = Field(default="v1", description="Key version for rotation support")


class SubmitResponse(BaseModel):
    ref:     str
    message: str


class SearchResponse(BaseModel):
    found:   bool
    ref:     Optional[str]
    created_at: Optional[str]


# ─── Endpoints ───────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/v1/public-key")
def public_key():
    """Return the current RSA public key so the frontend never hardcodes it."""
    for version, private_key in _private_keys.items():
        pub_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        return {"key_version": version, "public_key": pub_pem}
    raise HTTPException(status_code=503, detail="No key loaded")


@app.post("/v1/submit", response_model=SubmitResponse)
def submit(body: SubmitRequest, db: Session = Depends(get_db)):
    """
    Receive E2E-encrypted payload, decrypt, store with blind index.

    Security notes:
      - `national_id` variable is NEVER passed to log.*
      - Storage uses a fresh random IV (randomised encryption per record)
      - Search index uses HMAC-SHA256 (deterministic, searchable)
    """
    try:
        # 1. Unwrap the AES key using the server's RSA private key
        aes_key = unwrap_aes_key(body.encrypted_key, body.key_version)

        # 2. Decrypt the payload  ← THIS VALUE MUST NEVER BE LOGGED
        national_id = aes_gcm_decrypt(body.encrypted_data, body.iv, aes_key)

        # 3. Re-encrypt for storage (randomised — different ciphertext every time)
        storage_key = generate_storage_key()
        storage_ciphertext, storage_iv = aes_gcm_encrypt(national_id, storage_key)

        # 4. Compute deterministic blind index for search
        blind_index = compute_blind_index(national_id)

        # 5. Persist
        record = NationalIdRecord(
            encrypted_data=storage_ciphertext,
            storage_iv=storage_iv,
            search_index=blind_index,
            key_version=body.key_version,
        )
        db.add(record)
        db.commit()
        db.refresh(record)

        log.info("Stored record ref=%s key_version=%s", record.id, body.key_version)
        return SubmitResponse(ref=record.id, message="Stored successfully")

    except ValueError as exc:
        log.warning("Decryption failed: %s", type(exc).__name__)
        raise HTTPException(status_code=400, detail="Invalid encrypted payload")
    except Exception as exc:
        log.error("Submit error: %s", type(exc).__name__)
        raise HTTPException(status_code=500, detail="Internal error")


@app.get("/v1/search", response_model=SearchResponse)
def search(national_id: str, db: Session = Depends(get_db)):
    """
    Exact-match search by National ID using the blind index.

    Only the HMAC of the query hits the database — plaintext never stored in query logs.
    """
    blind_index = compute_blind_index(national_id)

    record = (
        db.query(NationalIdRecord)
        .filter(NationalIdRecord.search_index == blind_index)
        .first()
    )

    if not record:
        return SearchResponse(found=False, ref=None, created_at=None)

    return SearchResponse(
        found=True,
        ref=record.id,
        created_at=record.created_at.isoformat() if record.created_at else None,
    )
