# UpPass Secure Bridge — Technical Assignment

> **Role:** Technical Lead | **Stack:** TypeScript (Frontend) + Python / Node.js (Backend)

---

## Table of Contents

1. [Project Structure](#project-structure)
2. [Architecture Overview](#architecture-overview)
3. [Part 1 — TypeScript Encryption Library](#part-1--typescript-encryption-library)
4. [Part 2 — Python Verification Service](#part-2--python-verification-service)
5. [Running the Project](#running-the-project)
6. [Deploying to the Cloud](#deploying-to-the-cloud)
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
│   ├── package.json
│   └── tsconfig.json
├── backend/
│   ├── app/
│   │   └── main.py                   ← FastAPI service
│   ├── scripts/
│   │   └── generate_keys.py          ← RSA key-pair generator
│   ├── requirements.txt
│   └── Dockerfile                    ← Multi-stage, non-root
├── docker-compose.yml
└── README.md
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
│              UpPass Verification Service                │
│                                                         │
│  POST /v1/submit                                        │
│    ├─ RSA-OAEP unwrap(encrypted_key)  → AES key         │
│    ├─ AES-GCM decrypt(encrypted_data) → plaintext       │
│    ├─ AES-GCM encrypt(plaintext, DEK) → Column A        │
│    └─ HMAC-SHA256(plaintext, secret)  → Column B        │
│                                                         │
│  GET  /v1/search?national_id=X                          │
│    └─ HMAC-SHA256(X) → WHERE search_index = ?           │
│                            │                            │
│                            ▼                            │
│  ┌─────────────────────────────────────────────────┐   │
│  │  Database                                        │   │
│  │  id | encrypted_data (A) | search_index (B) |.. │   │
│  └─────────────────────────────────────────────────┘   │
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

The library accepts a `keyVersion` option that is included in every payload. This allows the backend to select the correct private key during a rotation period — the client always uses the current public key but labels it so the server knows which private key to use.

---

## Part 2 — Python Verification Service

### Blind Indexing Pattern

The fundamental challenge: you need to search encrypted data without decrypting it.

**Solution — two columns, two purposes:**

| Column | Technique | Property | Used For |
|--------|-----------|----------|----------|
| `encrypted_data` | AES-256-GCM (random IV per record) | Non-deterministic | Storage — never the same ciphertext twice |
| `search_index` | HMAC-SHA256 (fixed secret key) | Deterministic | Search — same input → same output |

**Search flow:**
```
query "1234567890" ──► HMAC-SHA256(query, HMAC_SECRET)
                                │
                    WHERE search_index = <hmac_hex>
```

The HMAC key (`HMAC_SECRET`) must be separate from the encryption key (`DATA_ENCRYPTION_KEY`) and stored in environment variables / secrets manager — never in the database.

### Endpoint Reference

```
POST /v1/submit
  Body: { encrypted_data, encrypted_key, iv, key_version }
  Response: { ref, message }

GET  /v1/search?national_id=<string>
  Response: { found, ref, created_at }

GET  /health
  Response: { status: "ok" }
```

### Security Controls in Code

- **No PII in logs:** The `national_id` variable is deliberately never passed to any `log.*` call
- **Non-root Docker user:** The container runs as `uppass` user, not `root`
- **Keys never in image:** Private keys are mounted as Docker secrets at runtime
- **Multi-stage Dockerfile:** Build tools are stripped from the final image, reducing attack surface

---

## Running the Project

### Prerequisites

- Docker & Docker Compose
- Node.js 18+ (for frontend library)
- Python 3.12+ (for local backend development)

### 1. Generate RSA Keys

```bash
cd backend
python scripts/generate_keys.py
# Creates: keys/private_v1.pem  keys/public_v1.pem
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env:
#   HMAC_SECRET=<generate with: python -c "import secrets; print(secrets.token_hex(32))">
#   DATA_ENCRYPTION_KEY=<generate same way>
```

### 3. Run with Docker Compose

```bash
docker compose up --build
# API available at: http://localhost:8000
# Docs available at: http://localhost:8000/docs
```

### 4. Build the TypeScript Library

```bash
cd frontend-lib
npm install
npm run build
# Output: dist/uppass-secure-bridge.js
```

### 5. Test the Flow

```bash
# Submit encrypted data
curl -X POST http://localhost:8000/v1/submit \
  -H "Content-Type: application/json" \
  -d '{"encrypted_data":"...","encrypted_key":"...","iv":"...","key_version":"v1"}'

# Search by National ID
curl "http://localhost:8000/v1/search?national_id=1234567890123"
```

---

## Deploying to the Cloud

> **Note on Vercel:** Vercel is optimised for stateless frontend deployments and serverless functions.
> The Python backend is **not suited for Vercel** because it is stateful (holds RSA private keys in memory,
> requires a persistent database connection, and uses long-lived worker processes).
> The recommendation below reflects production-appropriate choices.

### Recommended Split Architecture

```
Frontend (TypeScript Library / Demo UI)  ──►  Vercel / Netlify
Backend (FastAPI Service)                ──►  Railway / Render / Fly.io / AWS ECS
Database                                 ──►  AWS RDS PostgreSQL / PlanetScale
Secrets                                  ──►  AWS Secrets Manager / GCP Secret Manager
```

### Backend — Deploy to Railway

```bash
# Install Railway CLI
npm install -g @railway/cli
railway login
railway init
railway up

# Set secrets (never commit these)
railway variables set HMAC_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")
railway variables set DATA_ENCRYPTION_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
railway variables set DATABASE_URL=postgresql://...
```

### Backend — Deploy to AWS ECS (Production)

```bash
# 1. Push image to ECR
aws ecr create-repository --repository-name uppass-api
docker build -t uppass-api ./backend
docker tag uppass-api:latest <account>.dkr.ecr.<region>.amazonaws.com/uppass-api:latest
docker push <account>.dkr.ecr.<region>.amazonaws.com/uppass-api:latest

# 2. Store private key in AWS Secrets Manager
aws secretsmanager create-secret \
  --name uppass/private-key-v1 \
  --secret-string file://backend/keys/private_v1.pem

# 3. Mount secret into ECS task definition (not environment variable)
# Reference: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/secrets-envvar-secrets-manager.html
```

### Frontend Library — Publish to npm / Vercel

```bash
cd frontend-lib
npm run build
npm publish --access public   # publishes @uppass/secure-bridge

# Or deploy demo app to Vercel
vercel --prod
```

---

## Scenario A — Key Rotation Strategy

### Problem

> Rotate Data Encryption Keys (DEK) annually for compliance.  
> Millions of encrypted records exist. Zero downtime required.

### Solution: Key Versioning + Envelope Encryption

```
┌──────────────────────────────────────────────────────────┐
│  Key Hierarchy                                           │
│                                                          │
│  KMS / Vault                                             │
│    ├── KEK (Key Encryption Key) — never rotated          │
│    ├── DEK v1 — encrypted by KEK, used until 2025-01-01  │
│    └── DEK v2 — encrypted by KEK, current key            │
│                                                          │
│  Database Record                                         │
│    ├── encrypted_data  (ciphertext)                      │
│    ├── key_version     ← "v1" or "v2"                    │
│    └── search_index    (HMAC — unaffected by rotation)   │
└──────────────────────────────────────────────────────────┘
```

### Zero-Downtime Rotation Procedure

```
Phase 1 — Preparation (Day 0)
  ├─ Generate DEK v2 in KMS
  ├─ Update app config: CURRENT_WRITE_VERSION = "v2"
  ├─ Add v2 to decryption key map (app can now decrypt v1 and v2)
  └─ Deploy — all NEW records are written with v2; reads work for both

Phase 2 — Background Migration (Days 1–N)
  ├─ Migration job runs in batches (e.g., 1,000 records / 5 seconds)
  │     for record in db.where(key_version="v1").batch(1000):
  │         plaintext = aes_decrypt(record.encrypted_data, DEK_v1)
  │         record.encrypted_data = aes_encrypt(plaintext, DEK_v2)
  │         record.key_version = "v2"
  │         db.save(record)
  └─ Job is idempotent — safe to stop and restart

Phase 3 — Cleanup (After 100% migration confirmed)
  ├─ Verify: SELECT COUNT(*) WHERE key_version = "v1" → must be 0
  ├─ Remove v1 from decryption key map
  ├─ Archive DEK v1 (keep in cold storage for audit; do not delete yet)
  └─ Update compliance documentation
```

### How the System Knows Which Key to Use

Every record stores `key_version` as a plain (non-encrypted) column. The decryption path is:

```python
def decrypt_record(record):
    dek = kms.get_key(version=record.key_version)   # O(1) lookup from in-memory cache
    return aes_gcm_decrypt(record.encrypted_data, dek)
```

The KMS client caches key material locally to avoid a network call per record during the migration job.

### HMAC Search Index During Rotation

The `search_index` (HMAC) is **unaffected by key rotation** because it is derived from the HMAC secret, not the DEK. This means the search capability remains fully functional throughout the entire migration.

---

## Scenario B — Data Leak Incident Response

### Incident

> A developer accidentally logged the decrypted National ID into CloudWatch/Stackdriver  
> for the past 24 hours.

---

### Immediate Response (First 30 Minutes)

```
T+0   CONTAIN ──► Redeploy the service with the logging statement removed
                  Rate-limit or temporarily suspend the affected endpoint
                  Revoke any developer access to the logging system

T+10  ASSESS ───► Query CloudWatch for the past 24h:
                  fields @message | filter message like /national.?id/i
                  → Determine: how many unique IDs, which users, what regions

T+20  ESCALATE ──► Notify: DPO, Legal, CISO, Engineering Director
                   Open an incident channel (Slack #incident-YYYY-MM-DD)
                   Do NOT post PII data into the incident channel

T+30  PRESERVE ──► Export and secure affected log streams for legal/forensic use
                   BEFORE requesting deletion (deletion is irreversible)
```

### Remediation

```
Step 1 — Log Purge
  ├─ AWS CloudWatch: aws logs delete-log-group --log-group-name <group>
  │    or create a log export job, purge, then reimport sanitised copy
  └─ Confirm deletion with audit trail (screenshot + ticket reference)

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

NATIONAL_ID_PATTERN = re.compile(r'\b\d{13}\b')   # Thai National ID pattern

class PIIScrubFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = NATIONAL_ID_PATTERN.sub('[REDACTED]', str(record.msg))
        record.args = ()
        return True

# Apply globally at app startup
for handler in logging.root.handlers:
    handler.addFilter(PIIScrubFilter())
```

#### 2. Structured Logging — Allowlist Policy

```python
# ❌ WRONG — logs entire dict which may contain PII
log.info("Processing record: %s", record.__dict__)

# ✅ CORRECT — log only safe, explicitly chosen fields
log.info("Processing record ref=%s key_version=%s", record.id, record.key_version)
```

#### 3. CI Static Analysis Rule

Add a custom lint rule (e.g., `flake8` plugin or `semgrep`) that fails the build if any `log.*()` call appears inside a function named `decrypt*` or handles a variable named `national_id` or `plaintext`.

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

#### 4. Code Review Checklist (PR Template)

```markdown
## Security Checklist
- [ ] No PII (National ID, name, phone, email) passed to any log statement
- [ ] New environment variables documented and added to Secrets Manager
- [ ] No secrets committed to repository
- [ ] Decryption logic reviewed by a second engineer
```

#### 5. Secret Detection in CI

```yaml
# .github/workflows/security.yml
- name: Detect secrets
  uses: trufflesecurity/trufflehog@v3
  with:
    path: ./
    base: main
```

### Post-Incident Review (1 Week Later)

Hold a blameless post-mortem. Document:

- **Root cause:** logging statement added during debugging, not caught in review
- **Contributing factors:** no log scrubbing middleware, no lint rule
- **Action items with owners and deadlines:** middleware (Platform team, 3 days), semgrep rule (Security team, 1 week), PR checklist update (Tech Lead, 1 day)

The goal is systemic improvement — not individual blame.

---

*Document authored for UpPass Technical Lead Assignment*  
*All cryptographic primitives follow NIST SP 800-38D (AES-GCM) and PKCS #1 v2.2 (OAEP)*
