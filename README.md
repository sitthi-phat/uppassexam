# UpPass Secure Bridge — Technical Assignment

> **Role:** Technical Lead | **Stack:** TypeScript (Frontend) + Python / FastAPI (Backend) + GCP

---

## Table of Contents

1. [Project Structure](#project-structure)
2. [Architecture Overview](#architecture-overview)
3. [Part 1 — TypeScript Encryption Library](#part-1--typescript-encryption-library)
4. [Part 2 — Python Verification Service](#part-2--python-verification-service)
5. [Running Locally](#running-locally)
6. [Deploying to GCP](#deploying-to-gcp)
7. [Scenario A — Key Rotation Strategy](#scenario-a--key-rotation-strategy)
8. [Scenario B — Data Leak Incident Response](#scenario-b--data-leak-incident-response)

---

## Project Structure

```
uppass/
├── frontend-lib/
│   ├── src/
│   │   ├── uppass-secure-bridge.ts   ← Core encryption library
│   │   └── example.ts                ← Integration example
│   ├── index.html                    ← Demo UI (submit, search, key rotation, security monitor)
│   ├── package.json
│   └── tsconfig.json
├── backend/
│   ├── app/
│   │   └── main.py                   ← FastAPI service (all endpoints)
│   ├── scripts/
│   │   └── generate_keys.py          ← RSA key-pair generator (local dev only)
│   ├── requirements.txt
│   └── Dockerfile
├── deploy/
│   ├── deploy.sh                     ← Cloud Run deploy helper
│   └── setup-gcp.sh                  ← One-time GCP resource provisioning
├── cloudbuild.yaml                   ← Cloud Build pipeline (TruffleHog scan → Docker builds)
├── .trufflehog-exclude               ← TruffleHog path exclusions
├── .gcloudignore                     ← Files excluded from gcloud builds submit
├── docker-compose.yml                ← Local dev (MySQL + API + Frontend)
└── SETUP.md                          ← Full GCP setup guide
```

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                     Client (Browser)                    │
│                                                         │
│  National ID ──► UpPassSecureBridge.encrypt()           │
│                   │                                     │
│                   ├─ Generate transient AES-256 key     │
│                   ├─ AES-GCM encrypt(payload)           │
│                   └─ RSA-OAEP wrap(AES key)             │
│                            │                            │
│               { encrypted_data, encrypted_key, iv }     │
└────────────────────────────┼────────────────────────────┘
                             │  HTTPS (TLS in transit)
                             ▼
┌─────────────────────────────────────────────────────────┐
│              UpPass Verification Service (Cloud Run)    │
│                                                         │
│  POST /v1/submit                                        │
│    ├─ RSA-OAEP unwrap(encrypted_key)  → AES key         │
│    ├─ AES-GCM decrypt(encrypted_data) → plaintext       │
│    ├─ AES-GCM encrypt(plaintext, DEK) → encrypted_data  │
│    └─ HMAC-SHA256(plaintext, secret)  → search_index    │
│                                                         │
│  GET  /v1/search?national_id=X                          │
│    └─ HMAC-SHA256(X) → WHERE search_index = ?           │
│                            │                            │
│                            ▼                            │
│  ┌────────────────────────────────────────────────────┐  │
│  │  Cloud SQL (MySQL 8.0)  national_ids table         │  │
│  │                                                    │  │
│  │  id             random hex — returned as ref       │  │
│  │  encrypted_data AES-256-GCM ciphertext (DEK)       │  │
│  │  storage_iv     12-byte GCM IV for encrypted_data  │  │
│  │  search_index   HMAC-SHA256 blind index            │  │
│  │  key_version    RSA key used for this record       │  │
│  │  dek_version    DEK version encrypting this record │  │
│  │  hmac_version   HMAC secret used for search_index  │  │
│  │  created_at     UTC timestamp                      │  │
│  └────────────────────────────────────────────────────┘  │
│                                                         │
│  Secret Manager: RSA key, DEK, HMAC secret, DB password │
└─────────────────────────────────────────────────────────┘
```

---

## Part 1 — TypeScript Encryption Library

### Design Decisions

| Choice | Rationale |
|--------|-----------|
| **Web Crypto API** | Browser-native; no third-party crypto dependencies to audit or update |
| **AES-256-GCM** | Authenticated encryption — provides both confidentiality and integrity; detects tampering |
| **RSA-OAEP + SHA-256** | Resistant to padding-oracle attacks; PKCS#1 v1.5 is deprecated |
| **12-byte random IV** | GCM standard; `crypto.getRandomValues()` — cryptographically secure |
| **Transient AES key** | Generated fresh per submission; compromise of one record does not affect others |
| **`extractable: false` on RSA import** | Private key material cannot be read back out of memory |

### Hybrid Encryption Flow

```
plaintext ──► AES-256-GCM(key=ephemeral, iv=random) ──► encrypted_data
                                │
ephemeral key ──► RSA-OAEP(serverPublicKey) ──────────► encrypted_key
```

### Key Version Support

The library accepts a `keyVersion` option included in every payload. This allows the backend to select the correct private key during a rotation period — the client always uses the current public key but labels it so the server knows which private key to use for unwrapping.

---

## Part 2 — Python Verification Service

### Blind Indexing Pattern

The fundamental challenge: search encrypted data without decrypting it.

**Solution — two columns, two purposes:**

| Column | Technique | Property | Used For |
|--------|-----------|----------|----------|
| `encrypted_data` | AES-256-GCM (random IV per record) | Non-deterministic | Storage — never the same ciphertext twice |
| `search_index` | HMAC-SHA256 (fixed secret) | Deterministic | Search — same input → same output |

**Search flow:**
```
query "1234567890" ──► HMAC-SHA256(query, HMAC_SECRET)
                                │
                    WHERE search_index = <hmac_hex>
```

During an HMAC key rotation, search queries all known HMAC versions so records remain findable throughout the chunked migration window.

### Endpoint Reference

```
POST /v1/submit                   Decrypt E2E payload, store with blind index
POST /v1/submit-unsafe            Same as submit but intentionally logs national_id (security demo)
GET  /v1/search?national_id=X     Search by National ID (queries all HMAC versions)
GET  /v1/public-key               Return current RSA public key + version
GET  /v1/admin/status             Current key versions, record count, HMAC migration progress
POST /v1/admin/rotate-rsa         Generate new RSA pair, hot-reload server
POST /v1/admin/rotate-dek         Generate new DEK, re-encrypt all records
POST /v1/admin/rotate-hmac        Generate new HMAC secret, chunked blind-index migration
GET  /v1/admin/monitor/violations Query Cloud Logging for SECURITY_VIOLATION entries
POST /v1/admin/reset-demo         Delete all records and reset key state to v1 (demo only)
GET  /health                      Liveness probe
```

### Key Versioning

Every record stores three version columns:

| Column | Tracks |
|--------|--------|
| `key_version` | Which RSA private key was used to unwrap the session AES key |
| `dek_version` | Which DEK version currently encrypts `encrypted_data` |
| `hmac_version` | Which HMAC secret was used to compute `search_index` |

This enables zero-downtime key rotation — old and new records coexist and are always decryptable/searchable.

### Security Controls

- **No PII in logs:** `national_id` is never passed to any `log.*` call in normal operation
- **HMAC versioning:** chunked migration; search tries all known versions during rotation window
- **Single worker per instance:** `--workers 1` ensures in-memory key state is consistent; `--max-instances=1` prevents key-state divergence across instances
- **Keys from Secret Manager:** private key, DEK, and HMAC secret are fetched from GCP Secret Manager at startup — never baked into the image
- **Non-root Docker user:** container runs as `uppass`, not `root`
- **TruffleHog in CI:** Cloud Build scans for hardcoded secrets before building Docker images

---

## Running Locally

### Prerequisites

- Docker & Docker Compose
- Node.js 18+
- Python 3.12+

### 1. Generate RSA Keys (first time only)

```bash
cd backend
python scripts/generate_keys.py
# Creates: keys/private_v1.pem  keys/public_v1.pem
```

### 2. Configure Environment

```bash
# Create .env in project root
HMAC_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")
DATA_ENCRYPTION_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
```

### 3. Run with Docker Compose

```bash
docker compose up --build
# API:   http://localhost:8000
# Docs:  http://localhost:8000/docs
# UI:    http://localhost:3000
```

### 4. Build the TypeScript Library

```bash
cd frontend-lib
npm install
npm run build
# Output: dist/uppass-secure-bridge.js
```

---

## Deploying to GCP

Full step-by-step instructions are in [SETUP.md](SETUP.md).

### Quick rebuild + redeploy

```bash
# Rebuild both images (TruffleHog scan runs first)
gcloud builds submit . --config=cloudbuild.yaml

# Redeploy both services
gcloud run deploy uppass-api      --image=asia-southeast1-docker.pkg.dev/$PROJECT_ID/uppass/backend:latest  --region=asia-southeast1
gcloud run deploy uppass-frontend --image=asia-southeast1-docker.pkg.dev/$PROJECT_ID/uppass/frontend:latest --region=asia-southeast1
```

---

## Scenario A — Key Rotation Strategy

### Problem

> Rotate Data Encryption Keys (DEK) and HMAC secrets for compliance.
> Millions of encrypted records exist. Zero downtime required.

### Implemented Solution

The service implements live, hot-reloadable key rotation via admin endpoints:

```
POST /v1/admin/rotate-rsa   → new RSA pair, hot-reloads without restart
POST /v1/admin/rotate-dek   → new DEK, re-encrypts all records in one pass
POST /v1/admin/rotate-hmac  → new HMAC secret, recomputes blind indexes in chunks
```

#### RSA Rotation

```
1. Generate RSA-2048 pair in-process
2. Store new private key (base64) to Secret Manager as new version
3. Hot-reload: add new private key to state.private_keys[new_version]
4. Set state.current_rsa_version = new_version
   → New submits use new public key; old records still decrypt with old private key
```

#### DEK Rotation

```
1. Generate 256-bit DEK (SHA256 of random hex)
2. Store raw hex to Secret Manager
3. For every record:
     plaintext = aes_gcm_decrypt(record.encrypted_data, old_dek)
     record.encrypted_data = aes_gcm_encrypt(plaintext, new_dek)
     record.dek_version = new_version
4. Hot-reload: state.dek_keys[new_version] = new_dek
```

#### HMAC Rotation (chunked)

```
POST /v1/admin/rotate-hmac  body: { "chunk_size": 1000 }

Response: { new_version, recomputed_records, remaining_records, message }

1. Generate new HMAC secret, store to Secret Manager
2. Process chunk_size records where hmac_version != new_version:
     plaintext = aes_gcm_decrypt(record.encrypted_data, DEK)
     record.search_index = hmac_sha256(plaintext, new_secret)
     record.hmac_version = new_version
3. Call repeatedly until remaining_records = 0
   → Search works across all versions during the migration window
```

The demo frontend loops automatically until all records are migrated.

### How the System Knows Which Key to Use

Every record stores plain (non-encrypted) version columns. The read path is:

```python
def decrypt_record(record):
    dek = state.dek_keys[record.dek_version]        # in-memory dict lookup
    return aes_gcm_decrypt(record.encrypted_data, dek)
```

---

## Scenario B — Data Leak Incident Response

### Incident

> A developer accidentally logged the decrypted National ID into Cloud Run stdout
> for the past 24 hours.

### Live Demo

The `/v1/submit-unsafe` endpoint simulates this mistake — it processes the submission correctly but intentionally logs `national_id` to stdout. The frontend "Security Monitor" module:

1. Submits via the unsafe endpoint to create a violation
2. Polls `/v1/admin/monitor/violations` which queries Cloud Logging for `SECURITY_VIOLATION` entries
3. Shows a live feed with timestamp, severity, and payload
4. Links to GCP Logs Explorer, Metrics Explorer, and Alert Policies console

A GCP log-based metric (`uppass-pii-leak`) counts these violations, and an alerting policy fires an email to the team when the count exceeds 0.

---

### Immediate Response (First 30 Minutes)

```
T+0   CONTAIN ──► Redeploy the service with the logging statement removed
                  Remove or disable the unsafe endpoint
                  Revoke developer access to the logging system

T+10  ASSESS ───► Query Cloud Logging:
                  gcloud logging read \
                    'resource.type="cloud_run_revision" AND textPayload=~"national_id"' \
                    --limit=1000
                  → Determine: how many unique IDs, which time window

T+20  ESCALATE ──► Notify: DPO, Legal, CISO, Engineering Director
                   Open an incident channel — do NOT post PII into it

T+30  PRESERVE ──► Export affected log streams for legal/forensic use
                   BEFORE requesting deletion (deletion is irreversible)
```

### Remediation

```
Step 1 — Log Purge
  Cloud Logging entries are immutable — they cannot be selectively edited.
  Options:
    a. Set a log exclusion filter to stop ingesting future violations
    b. Reduce log bucket retention to expire old entries faster
    c. Export to GCS, sanitise (replace national IDs), reimport if needed for audit

Step 2 — Regulatory Notification
  ├─ PDPA (Thailand): notify PDPC within 72 hours of discovery
  ├─ GDPR (if applicable): notify supervisory authority within 72 hours
  └─ Prepare affected-individual notification letters

Step 3 — Affected Data Assessment
  └─ For each leaked National ID: assess identity-theft risk,
     consider proactive user notification + credit monitoring offer
```

### Technical Controls to Prevent Recurrence

#### 1. Log Scrubbing Middleware

```python
import re, logging

NATIONAL_ID_PATTERN = re.compile(r'\b\d{13}\b')   # Thai National ID

class PIIScrubFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg  = NATIONAL_ID_PATTERN.sub('[REDACTED]', str(record.msg))
        record.args = ()
        return True

for handler in logging.root.handlers:
    handler.addFilter(PIIScrubFilter())
```

#### 2. Structured Logging — Allowlist Policy

```python
# ❌ WRONG — logs entire dict which may contain PII
log.info("Processing record: %s", record.__dict__)

# ✅ CORRECT — log only safe, explicitly chosen fields
log.info("Stored record ref=%s key_version=%s", record.id, record.key_version)
```

#### 3. TruffleHog in Cloud Build (already implemented)

```yaml
# cloudbuild.yaml — step 1 blocks the build if secrets are found
- id: secret-scan
  name: trufflesecurity/trufflehog:latest
  args: [filesystem, /workspace, --fail, --no-update,
         --exclude-paths=/workspace/.trufflehog-exclude]
```

#### 4. Semgrep Rule — No PII in Logs

```yaml
# .semgrep.yml
rules:
  - id: no-pii-in-logs
    patterns:
      - pattern: logging.$FUNC(..., national_id, ...)
      - pattern: logging.$FUNC(..., plaintext, ...)
    message: "Do not log PII variables directly"
    severity: ERROR
```

#### 5. GCP Monitoring Alert (already implemented)

A log-based metric `uppass-pii-leak` counts `SECURITY_VIOLATION` log entries. An alerting policy fires an email immediately when the count exceeds 0, giving the team real-time visibility rather than discovering the leak hours later.

### Post-Incident Review (1 Week Later)

Hold a blameless post-mortem. Document:

- **Root cause:** logging statement added during debugging, not caught in review
- **Contributing factors:** no log scrubbing middleware, no lint rule, no real-time alerting
- **Action items with owners and deadlines:** middleware (Platform team, 3 days), semgrep rule (Security team, 1 week), PR checklist update (Tech Lead, 1 day)

---

*All cryptographic primitives follow NIST SP 800-38D (AES-GCM) and PKCS #1 v2.2 (OAEP)*
