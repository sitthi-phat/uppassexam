"""Database engine, ORM model, session factory, and schema helpers."""

import os
import secrets
import logging
from datetime import datetime, timezone

from sqlalchemy import create_engine, Column, String, Text, DateTime, text
from sqlalchemy.orm import declarative_base, sessionmaker, Session

log = logging.getLogger("uppass")

DATABASE_URL  = os.environ.get("DATABASE_URL", "sqlite:///./uppass.db")
_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine       = create_engine(DATABASE_URL, connect_args=_connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base         = declarative_base()


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


def db_distinct_versions(column: str) -> set:
    """Return distinct version labels stored in national_ids for a given column."""
    try:
        with engine.connect() as conn:
            rows = conn.execute(
                text(f"SELECT DISTINCT {column} FROM national_ids WHERE {column} IS NOT NULL")
            ).fetchall()
        return {row[0] for row in rows if row[0]}
    except Exception:
        return set()


def ensure_columns():
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
