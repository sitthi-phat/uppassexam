# Part 3 — System Design & Incident Response

---

## Scenario A: Key Rotation Strategy

### Problem Statement

> "We need to rotate our Data Encryption Keys (DEK) annually for compliance. However, we have millions of encrypted records in the database."

---

### Core Principle: Key Versioning

Every encrypted record carries a `dek_version` column — a plain (non-encrypted) label stored alongside the ciphertext. During a rotation, old and new records coexist in the database. The system reads the version label to select the correct key for decryption, with no guessing or trial-and-error.

```
national_ids table
┌────────┬────────────────┬────────────┬─────────────┐
│   id   │ encrypted_data │ storage_iv │ dek_version │
├────────┼────────────────┼────────────┼─────────────┤
│ a1b2…  │ <ciphertext>   │ <iv>       │    v1       │  ← old record, DEK v1
│ c3d4…  │ <ciphertext>   │ <iv>       │    v2       │  ← new record, DEK v2
│ e5f6…  │ <ciphertext>   │ <iv>       │    v1       │  ← old record, still v1
└────────┴────────────────┴────────────┴─────────────┘
```

---

### Zero-Downtime Rotation Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Secret Manager                               │
│                                                                     │
│   uppass-dek  version 1 ──► raw hex of DEK v1  (ENABLED)           │
│   uppass-dek  version 2 ──► raw hex of DEK v2  (ENABLED, current)  │
└───────────────────────────────┬─────────────────────────────────────┘
                                │  loaded at startup / rotation
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     API Server (Cloud Run)                          │
│                                                                     │
│   state.dek_keys = {                                                │
│       "v1": bytes(sha256(hex_v1)),   ← retained for decryption      │
│       "v2": bytes(sha256(hex_v2)),   ← current write key            │
│   }                                                                 │
│   state.current_dek_version = "v2"                                  │
│                                                                     │
│   READ path:                                                        │
│     key = state.dek_keys[record.dek_version]   ← always correct    │
│     plaintext = aes_gcm_decrypt(record.data, key, record.iv)        │
│                                                                     │
│   WRITE path:                                                       │
│     key = state.dek_keys[state.current_dek_version]                 │
│     record.encrypted_data = aes_gcm_encrypt(plaintext, key)         │
│     record.dek_version    = state.current_dek_version               │
└─────────────────────────────────────────────────────────────────────┘
```

---

### Rotation Procedure (Zero Downtime)

```
┌──────────────────────────────────────────────────────────────────┐
│  PHASE 1 — Generate & Hot-Reload  (instantaneous, no downtime)   │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  POST /v1/admin/rotate-dek                                       │
│                                                                  │
│  1. Generate new DEK:  new_hex = secrets.token_hex(32)           │
│                        new_key = sha256(new_hex.encode())        │
│  2. Store to Secret Manager as new version                       │
│  3. Add to in-memory map:  state.dek_keys["v2"] = new_key        │
│  4. Set write pointer:     state.current_dek_version = "v2"      │
│                                                                  │
│  Result: new records write with v2; old records still decrypt    │
│          with v1 — zero downtime, zero errors                    │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│  PHASE 2 — Background Re-encryption  (batched, non-blocking)     │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  for record in db.where(dek_version != "v2").batch(1000):        │
│      plaintext            = aes_gcm_decrypt(record, DEK_v1)      │
│      record.encrypted_data = aes_gcm_encrypt(plaintext, DEK_v2)  │
│      record.storage_iv    = new_random_iv                        │
│      record.dek_version   = "v2"                                 │
│      db.save(record)                                             │
│                                                                  │
│  Properties:                                                     │
│    • Reads and writes continue normally throughout               │
│    • Job is idempotent — safe to stop, restart, or parallelize   │
│    • Each batch is a separate DB transaction                     │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│  PHASE 3 — Cleanup  (after 100 % migration confirmed)            │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Verify:  SELECT COUNT(*) WHERE dek_version = "v1"  → must = 0│
│  2. Remove v1 from state.dek_keys                                │
│  3. Disable Secret Manager version 1 of uppass-dek               │
│     (keep disabled for 90-day audit window, then destroy)        │
│  4. Update compliance documentation                              │
└──────────────────────────────────────────────────────────────────┘
```

---

### State During Transition

```
Time ──────────────────────────────────────────────────────────────►

           rotate-dek called          migration complete
                 │                           │
  v1 only        ▼    v1 + v2 coexist        ▼   v2 only
  ───────────────┬─────────────────────────────┬──────────────────
  All records v1 │  Old: v1  New writes: v2    │  All records v2
                 │  Reads: both keys needed    │  v1 key removed
                 │                             │
                 └─── migration job runs ──────┘
                      (can take hours/days for millions of records)
```

---

### HMAC Blind Index Rotation

The `search_index` column uses a separate HMAC secret — independent of the DEK. Rotating it follows the same versioning pattern but with an additional constraint: the blind index must be recomputed (not just re-encrypted), so the entire record must be decrypted, the new HMAC computed, and the new index written back.

```
POST /v1/admin/rotate-hmac  { "chunk_size": 1000 }

Response: {
  "new_version":        "v2",
  "recomputed_records": 1000,
  "remaining_records":  45230,
  "message":            "Chunk complete. Call again to continue."
}
```

During migration, **search queries all known HMAC versions** in parallel so no record becomes unfindable:

```python
for ver, secret in state.hmac_keys.items():
    index = hmac_sha256(national_id, secret)
    results = db.where(search_index=index)
    if results:
        return results
```

---

### Key Derivation

All DEK values use `SHA-256(raw_hex)` as the actual AES key. The raw hex is what is stored in Secret Manager. This ensures the AES key is always exactly 32 bytes regardless of the input length, and the derivation is deterministic across restarts.

```python
raw_hex = secret_manager.get("uppass-dek")      # "a3f9…" (64 hex chars)
aes_key = hashlib.sha256(raw_hex.encode()).digest()  # 32 bytes
```

---

### Compliance Summary

| Requirement | How it is met |
|-------------|---------------|
| Annual DEK rotation | `POST /v1/admin/rotate-dek` generates and hot-reloads a new key |
| Zero downtime | Phase 1 is instantaneous; Phase 2 runs in background |
| Auditability | Every record carries its own `dek_version`; Secret Manager logs all access |
| Old key retention | v1 kept in memory and Secret Manager (disabled) during migration window |
| Search continuity | HMAC versioning keeps all records searchable throughout migration |

---
---

## Scenario B: Data Leak Incident Response

### Incident

> "A security audit reveals that a developer accidentally logged the decrypted National ID into Cloud Logging for the past 24 hours."

---

### Incident Timeline & Immediate Actions

```
T + 0 min   CONTAIN
            ├─ Identify the offending code path (log statement inside decrypt/submit handler)
            ├─ Redeploy the service immediately with the log line removed
            │    gcloud run deploy uppass-api --image=<fixed-image> --region=asia-southeast1
            └─ If redeployment takes > 5 min: temporarily disable the affected endpoint
                 gcloud run services update uppass-api --no-traffic (route 0% to current revision)

T + 10 min  ASSESS — Scope the damage
            ├─ Query Cloud Logging for the full 24-hour window:
            │    gcloud logging read \
            │      'resource.type="cloud_run_revision"
            │       AND resource.labels.service_name="uppass-api"
            │       AND textPayload=~"national_id"' \
            │      --freshness=25h --limit=10000 \
            │      --format="value(timestamp,textPayload)" > /tmp/leak-audit.txt
            │
            ├─ Determine:
            │    • Total unique national IDs exposed
            │    • Time window (exact first and last log entry)
            │    • Which Cloud Run revision introduced the bug
            │    • Whether log entries were exported to any log sink (BigQuery, GCS, Pub/Sub)
            └─ Do NOT delete logs yet — they are evidence

T + 20 min  ESCALATE
            ├─ Notify: DPO (Data Protection Officer), CISO, Legal, Engineering Director
            ├─ Open a dedicated incident channel (e.g., Slack #inc-2026-04-21-pii-leak)
            ├─ Rule: NO plaintext national IDs in the incident channel — reference by count/range only
            └─ Assign an Incident Commander and a Scribe

T + 30 min  PRESERVE — Secure evidence before any deletion
            ├─ Export the affected log entries to a restricted GCS bucket (legal hold)
            │    gcloud logging sinks create inc-2026-04-21-hold \
            │      storage.googleapis.com/uppass-incident-hold \
            │      --log-filter='...'
            └─ Screenshot log entries in GCP Console with timestamps for the legal record

T + 60 min  NOTIFY (if required by regulation)
            ├─ PDPA Thailand: notify PDPC within 72 hours of discovery
            ├─ GDPR (if applicable): notify supervisory authority within 72 hours
            └─ Draft affected-individual notification letters (coordinate with Legal)
```

---

### Remediation Steps

```
┌────────────────────────────────────────────────────────────────────┐
│  Step 1 — Stop the bleeding                                        │
│                                                                    │
│  Remove the log statement, redeploy.                               │
│  Verify with a test request that national_id no longer appears     │
│  in logs before declaring containment complete.                    │
└────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────┐
│  Step 2 — Log purge / retention                                    │
│                                                                    │
│  Cloud Logging entries are immutable — they cannot be edited or    │
│  selectively deleted via the API.                                  │
│                                                                    │
│  Options (choose based on legal/audit requirements):               │
│                                                                    │
│  a. Shorten log bucket retention                                   │
│       gcloud logging buckets update _Default \                     │
│         --location=global --retention-days=1                       │
│     Entries older than 1 day will expire automatically.            │
│                                                                    │
│  b. Delete entire log (nuclear — loses all entries for that log)   │
│       gcloud logging logs delete \                                 │
│         "projects/PROJECT/logs/run.googleapis.com%2Fstdout"        │
│                                                                    │
│  c. Add a log exclusion filter (stops further ingestion)           │
│       gcloud logging sinks create /dev/null \                      │
│         --log-filter='textPayload=~"national_id"'                  │
│     Note: does not remove entries already written.                 │
│                                                                    │
│  Always preserve a secured copy for legal hold BEFORE purging.     │
└────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────┐
│  Step 3 — Assess affected individuals                              │
│                                                                    │
│  For each leaked national ID:                                      │
│    • Cross-reference with user records to identify the person      │
│    • Assess identity-theft risk level                              │
│    • Prepare individual notification letters                       │
│    • Offer credit monitoring / identity protection services        │
│      for high-risk cases                                           │
└────────────────────────────────────────────────────────────────────┘
```

---

### Technical Controls to Prevent Recurrence

#### Control 1 — PII Scrubbing Middleware (defence-in-depth)

Even if a developer accidentally logs a variable named `national_id`, this filter replaces it before the log entry is written.

```python
import re, logging

_NATIONAL_ID_RE = re.compile(r'\b\d{13}\b')   # Thai 13-digit National ID

class PIIScrubFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg  = _NATIONAL_ID_RE.sub('[REDACTED]', str(record.msg))
        record.args = ()
        return True

# Apply at startup — covers every logger in the process
for handler in logging.root.handlers:
    handler.addFilter(PIIScrubFilter())
```

---

#### Control 2 — Structured Logging Allowlist

```python
# ❌ WRONG — logs entire object which may contain PII
log.info("Processing: %s", record.__dict__)
log.debug("Decrypted payload: %s", payload)

# ✅ CORRECT — only log safe, explicitly selected fields
log.info("Stored record ref=%s dek_version=%s", record.id, record.dek_version)
```

Team rule: **log IDs and version labels, never values.**

---

#### Control 3 — Semgrep Static Analysis in CI

Fails the pull request if any log call receives a variable named `national_id` or `plaintext`.

```yaml
# .semgrep.yml
rules:
  - id: no-pii-in-logs
    languages: [python]
    patterns:
      - pattern: logging.$FUNC(..., national_id, ...)
      - pattern: logging.$FUNC(..., plaintext, ...)
      - pattern: log.$FUNC(..., national_id, ...)
      - pattern: log.$FUNC(..., plaintext, ...)
    message: "PII variable passed directly to a log statement — use ref/version labels instead"
    severity: ERROR
```

Add to CI pipeline:
```yaml
- name: Semgrep PII check
  run: semgrep --config .semgrep.yml backend/
```

---

#### Control 4 — TruffleHog in Cloud Build (already implemented)

```yaml
# cloudbuild.yaml — step 1 blocks builds if secrets or tokens are found
- id: secret-scan
  name: trufflesecurity/trufflehog:latest
  args: [filesystem, /workspace, --fail, --no-update,
         --exclude-paths=/workspace/.trufflehog-exclude]
```

---

#### Control 5 — GCP Real-Time Alerting (already implemented)

A log-based metric fires an email alert the moment a `SECURITY_VIOLATION` entry appears in Cloud Logging — turning a 24-hour silent breach into a sub-minute notification.

```
Log entry written
       │
       ▼
Cloud Logging ingests entry
       │
       ▼
Log-based metric "uppass-pii-leak" increments (count > 0)
       │
       ▼
Alerting policy fires → email to josukekung@gmail.com
       │
       ▼
On-call engineer investigates within minutes, not hours
```

The demo endpoint `/v1/submit-unsafe` simulates this path — it writes `SECURITY_VIOLATION: national_id=…` to stdout, which is visible in the Security Monitor module of the frontend and triggers the live alert.

---

#### Control 6 — PR Review Checklist

```markdown
## Security Checklist (required for every PR touching decrypt/submit paths)
- [ ] No PII (National ID, name, phone, email) passed to any log statement
- [ ] New environment variables documented and stored in Secret Manager
- [ ] No secrets committed to the repository (TruffleHog will block the build)
- [ ] Decryption logic reviewed by a second engineer
- [ ] Semgrep PII check passing in CI
```

---

### Control Effectiveness Summary

```
Attack surface: developer accidentally logs plaintext national_id

Layer 1 — Prevention (before merge)
  ├─ Semgrep rule blocks PR if log(national_id) pattern is detected
  └─ PR checklist requires second-engineer review of decrypt paths

Layer 2 — Prevention (at runtime)
  └─ PIIScrubFilter replaces 13-digit strings with [REDACTED] before write

Layer 3 — Detection (post-deployment)
  ├─ GCP log-based metric counts SECURITY_VIOLATION entries
  └─ Alerting policy emails on-call within 60 seconds of first occurrence

Layer 4 — Response (if detection fires)
  ├─ Immediate: redeploy with fix, scope damage via log query
  ├─ Short-term: purge or expire affected logs
  └─ Long-term: PDPA/GDPR notification, post-mortem, process improvement

Without Layer 3:  breach discovered at next audit  → 24+ hours of exposure
With    Layer 3:  breach discovered within 1 minute → minimal exposure window
```

---

### Post-Incident Review (1 Week After Containment)

Hold a **blameless post-mortem**. The goal is systemic improvement, not individual blame.

| Section | Content |
|---------|---------|
| **Timeline** | Exact sequence from code commit to discovery to containment |
| **Root cause** | Log statement added during debugging, not caught in review |
| **Contributing factors** | No scrubbing middleware, no lint rule, no real-time alerting |
| **Impact** | N unique national IDs exposed, T hours of exposure |
| **What went well** | Audit process caught it; fast containment once discovered |
| **Action items** | Middleware (Platform, 3 days), Semgrep (Security, 1 week), PR checklist (Tech Lead, 1 day), alerting (already done) |

Document and circulate to all engineers. Review action item completion at the next sprint.

---

*UpPass Secure Bridge — Part 3 System Design & Incident Response*
