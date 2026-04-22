"""Pydantic request/response schemas."""

from typing import Optional
from pydantic import BaseModel, Field


# ── Core API ──────────────────────────────────────────────────────────────────

class SubmitRequest(BaseModel):
    encrypted_data: str = Field(..., description="AES-GCM ciphertext, base64")
    encrypted_key:  str = Field(..., description="RSA-OAEP wrapped AES key, base64")
    iv:             str = Field(..., description="AES-GCM IV, base64")
    key_version:    str = Field(default="v1", description="RSA key version used to wrap AES key")


class SubmitResponse(BaseModel):
    ref:     str
    message: str


class SearchResponse(BaseModel):
    found:      bool
    ref:        Optional[str]
    created_at: Optional[str]


# ── Admin ─────────────────────────────────────────────────────────────────────

class AdminStatusResponse(BaseModel):
    rsa_version:   str
    dek_version:   str
    hmac_version:  str
    total_records: int
    dek_pending:   int
    hmac_pending:  int


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
