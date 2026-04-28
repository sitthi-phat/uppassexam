# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Does

UpPass is a zero-knowledge PII vault. A browser client encrypts a national ID with a transient AES-256 key, RSA-OAEP wraps that key, and sends the ciphertext to FastAPI. The backend unwraps, re-encrypts with a server-side DEK, stores a HMAC-SHA256 blind index for search, and never logs plaintext. Key versions are tracked per record so RSA, DEK, and HMAC can be rotated independently without downtime.

Full architecture, per-file explanations, and request flow diagrams are in [backend/backend.md](backend/backend.md).

---

## Running Locally

**Quickest path — Docker Compose (MySQL + backend + frontend):**
```bash
# One-time: generate RSA keys
cd backend && python scripts/generate_keys.py

# Copy and fill .env (see Required Env Vars below)
cp .env.example .env

docker compose up --build
# Backend: http://localhost:8000   Docs: http://localhost:8000/docs
# Frontend demo: http://localhost:3000
```

**Backend only (SQLite fallback, no Docker):**
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1
```

**Frontend library:**
```bash
cd frontend-lib
npm install
npm run build          # one-shot build → dist/
npm run build:watch    # watch mode
npm run example        # run src/example.ts via ts-node
```

---

## Required Env Vars (local dev)

| Var | How to generate / value |
|-----|------------------------|
| `HMAC_SECRET` | `python -c "import secrets; print(secrets.token_hex(32))"` |
| `DATA_ENCRYPTION_KEY` | `python -c "import secrets; print(secrets.token_hex(32))"` |
| `DATABASE_URL` | Omit → SQLite (`uppass.db`). MySQL: `mysql+pymysql://user:pass@host/uppass` |
| `PRIVATE_KEY_B64` | `base64 -w0 backend/keys/private_v1.pem` (or set `PRIVATE_KEY_PATH`) |
| `ALLOWED_ORIGINS` | `http://localhost:3000` |
| `ENV` | `development` |

In production (Cloud Run) these are injected via `--set-secrets` and `--set-env-vars`. See [SETUP.md](SETUP.md) for the full deploy walkthrough.

---

## GCP Deployment

```bash
# Build both images (TruffleHog scan gates the build — fails if any secret is hardcoded)
gcloud builds submit . --config=cloudbuild.yaml

# Redeploy (keeps existing env vars/secrets)
gcloud run deploy uppass-api      --image=<registry>/backend:latest  --region=asia-southeast1
gcloud run deploy uppass-frontend --image=<registry>/frontend:latest --region=asia-southeast1
```

---

## Architecture

```
Browser (UpPassSecureBridge.ts)
  └── Cloud Run: uppass-frontend  (nginx, port 8080)
        └── Cloud Run: uppass-api  (FastAPI, --workers 1)
              ├── Cloud SQL: uppass-mysql  (MySQL 8.0)
              ├── Secret Manager  (RSA keys, DEK, HMAC secret, DB password)
              └── Cloud Logging   (security violation queries)
```

**Backend module layout:**

| File | Role |
|------|------|
| `app/state.py` | Shared in-memory singleton — all key dicts and `current_*_version` strings |
| `app/database.py` | ORM model (`NationalIdRecord`), session factory, `db_distinct_versions()`, `ensure_columns()` |
| `app/gcp.py` | Secret Manager and Cloud Logging API calls |
| `app/startup.py` | Loads all key versions at boot (queries DB for referenced versions, then SM) |
| `app/crypto.py` | RSA unwrap, AES-GCM encrypt/decrypt, HMAC blind index; lazy cache-then-SM key getters |
| `app/schemas.py` | Pydantic request/response models |
| `app/main.py` | Lifespan, CORS, `/health`, `/v1/public-key`, `/v1/submit`, `/v1/search` |
| `app/routers/admin.py` | Key rotation, record list/delete, demo reset |
| `app/routers/monitor.py` | Unsafe submit (PII demo) and Cloud Logging violation query |

---

## Critical Invariants

**`--workers 1` per instance.** Keys are in process memory. Multiple workers per process would diverge. Multi-instance deployments are safe because key getters use cache-then-SM: on a cache miss the instance fetches the missing version from Secret Manager and caches it — no cross-instance coordination needed.

**SM write is mandatory before state mutation.** Every rotation endpoint writes the new key to Secret Manager first. If that write fails it raises HTTP 503 and leaves `state` untouched. This guarantees a cold restart always loads the same key material the running instance held.

**Secret Manager naming convention.** Never use SM's auto-increment version numbers for v2+ keys — those can be destroyed and break the mapping. Instead, create a dedicated named secret per rotation label:

| DB label | SM secret accessed |
|----------|--------------------|
| `v1` | `uppass-dek` version `1` (original secret) |
| `v2` | `uppass-dek-v2` (new named secret) at `latest` |
| `v3` | `uppass-dek-v3` (new named secret) at `latest` |

Implemented in `gcp.load_versioned_secret` and `gcp.create_versioned_secret`.

**Search tries all HMAC versions.** During chunked HMAC rotation, old records still carry old-version blind indexes. The search endpoint iterates every loaded HMAC version until a match is found.

**`ensure_columns()` runs at startup.** Adds missing DB columns via `ALTER TABLE` — deploy new schema versions without data loss.

---

## Key Rotation

All rotation is via API — no redeployment needed.

```bash
# RSA (instant, not chunked — new key used for new submits only)
curl -X POST $BACKEND_URL/v1/admin/rotate-rsa

# DEK (chunked — repeat until remaining_records = 0)
curl -X POST $BACKEND_URL/v1/admin/rotate-dek \
  -H "Content-Type: application/json" -d '{"chunk_size": 1000}'

# HMAC (chunked — same pattern)
curl -X POST $BACKEND_URL/v1/admin/rotate-hmac \
  -H "Content-Type: application/json" -d '{"chunk_size": 1000}'
```

The frontend Admin panel automates the loop for DEK and HMAC until `remaining_records = 0`.

---

## Security Notes

- `POST /v1/submit-unsafe` intentionally logs `SECURITY_VIOLATION: national_id=<value>` — it exists only to demonstrate the PII-in-logs threat model and trigger the GCP alerting policy. Do not call it in production flows.
- TruffleHog in Cloud Build scans for private secrets. Public keys are not flagged (by design — they are not sensitive). The example file at `frontend-lib/src/example.ts` uses a `<REPLACE_WITH_YOUR_PUBLIC_KEY>` placeholder.
- The SA needs `roles/secretmanager.admin` (not just `secretAccessor`) to create new named secrets during rotation.
