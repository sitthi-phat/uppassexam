# Part 3 — System Design & Incident Response

---

## Scenario A: Key Rotation Strategy

### Problem Statement

> "We need to rotate our Data Encryption Keys (DEK) annually for compliance. However, we have millions of encrypted records in the database."

---

### Core Principle: Three Version Columns

Every record carries three plain (non-encrypted) version labels — one per key type. During any rotation, old and new records coexist. The system reads the label to select the exact key, with no guessing.

```
national_ids table (Cloud SQL MySQL 8.0)
┌────────┬────────────────┬────────────┬──────────────┬─────────────┬──────────────┬─────────────┐
│   id   │ encrypted_data │ storage_iv │ search_index │ key_version │ dek_version  │ hmac_version│
├────────┼────────────────┼────────────┼──────────────┼─────────────┼──────────────┼─────────────┤
│ a1b2…  │ <ciphertext>   │ <iv>       │ <hmac_hex>   │     v1      │     v1       │     v1      │ ← original
│ c3d4…  │ <ciphertext>   │ <iv>       │ <hmac_hex>   │     v1      │     v2       │     v1      │ ← DEK rotated
│ e5f6…  │ <ciphertext>   │ <iv>       │ <hmac_hex>   │     v2      │     v2       │     v2      │ ← all rotated
└────────┴────────────────┴────────────┴──────────────┴─────────────┴──────────────┴─────────────┘

key_version  — which RSA private key decrypts the session AES key (set at submit time, never changes)
dek_version  — which DEK currently encrypts encrypted_data       (updated by rotate-dek)
hmac_version — which HMAC secret produced search_index           (updated by rotate-hmac, chunked)
```

---

### Secret Manager Version Mapping

The version label in the DB maps **directly and deterministically** to a Secret Manager version number. No lookup table, no config — just strip the `"v"` prefix.

```
DB label   Secret Manager secret         SM version
─────────  ────────────────────────────  ──────────
"v1"       uppass-dek                    1
"v2"       uppass-dek                    2          ← after first DEK rotation
"v3"       uppass-dek                    3          ← after second DEK rotation

"v1"       uppass-hmac-secret            1
"v2"       uppass-hmac-secret            2          ← after first HMAC rotation

"v1"       uppass-private-key-v1-b64     1
"v2"       uppass-private-key-v1-b64     2          ← after first RSA rotation
```

This makes restarts deterministic: given the DB label `"vN"`, the system always fetches SM version `N` — no env var drift, no guessing.

---

### Zero-Downtime Architecture

```
                      ┌──────────────────────────────────────────────────────────┐
                      │                   Secret Manager                         │
                      │                                                          │
                      │  uppass-dek          ver 1 → DEK v1 raw hex (ENABLED)   │
                      │                      ver 2 → DEK v2 raw hex (ENABLED)   │
                      │                                                          │
                      │  uppass-hmac-secret  ver 1 → HMAC v1 secret (ENABLED)   │
                      │                      ver 2 → HMAC v2 secret (ENABLED)   │
                      │                                                          │
                      │  uppass-private-key  ver 1 → RSA v1 base64 (ENABLED)    │
                      │  -v1-b64             ver 2 → RSA v2 base64 (ENABLED)    │
                      └────────────────────────────┬─────────────────────────────┘
                                                   │
                          At startup: for each key type
                          1. SELECT DISTINCT <ver_col> FROM national_ids
                          2. for "vN" → fetch SM version N
                          3. load into state dict
                                                   │
                                                   ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                            API Server (Cloud Run)                                │
│                                                                                  │
│   state.dek_keys     = { "v1": sha256(hex1),  "v2": sha256(hex2)  }             │
│   state.hmac_secrets = { "v1": b"secret_v1",  "v2": b"secret_v2"  }             │
│   state.private_keys = { "v1": <RSA key v1>,  "v2": <RSA key v2>  }             │
│                                                                                  │
│   state.current_dek_version  = "v2"   ← max version label in DB                 │
│   state.current_hmac_version = "v2"                                              │
│   state.current_rsa_version  = "v2"                                              │
│                                                                                  │
│   READ  → state.dek_keys[record.dek_version]         always correct              │
│   WRITE → state.dek_keys[state.current_dek_version]  always newest               │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

### Startup Key Loading (actual implementation)

```python
# backend/app/database.py
def db_distinct_versions(column: str) -> set:
    rows = conn.execute(
        f"SELECT DISTINCT {column} FROM national_ids WHERE {column} IS NOT NULL"
    ).fetchall()
    return {row[0] for row in rows if row[0]}

# backend/app/startup.py
def init_dek() -> None:
    versions = db_distinct_versions("dek_version")
    versions.add("v1")                                    # always need v1 for empty DB

    for ver in sorted(versions, key=lambda v: int(v[1:])):
        ver_num = int(ver[1:])                            # "v2" → 2
        try:
            raw = load_secret_version("uppass-dek", ver_num)   # fetch SM version N
            state.dek_keys[ver] = hashlib.sha256(raw.encode()).digest()
        except Exception:
            if ver == "v1":                               # local dev fallback only
                raw = os.environ.get("DATA_ENCRYPTION_KEY", "")
                if raw:
                    state.dek_keys["v1"] = hashlib.sha256(raw.encode()).digest()

    state.current_dek_version = max(state.dek_keys, key=lambda v: int(v[1:]))

# init_hmac() and load_private_keys() follow the identical pattern
# using "uppass-hmac-secret" and "uppass-private-key-v1-b64" respectively
# All three live in backend/app/startup.py, called from main.py lifespan
```

**Before this fix:** `init_dek` loaded ONE key from `DATA_ENCRYPTION_KEY` env var (always the original v1 bytes) and labeled it with whatever version was in the DB. After a rotation the env var still held v1's hex, so v1's key was stored under label `"v2"` — every decrypt of a v2 record silently failed after restart.

**After this fix:** env var is only a last-resort fallback for v1 when SM is unreachable (local dev without GCP). Every other version is fetched from SM by its exact version number.

---

### DEK Rotation Procedure

```
┌──────────────────────────────────────────────────────────────────────┐
│  PHASE 1 — Generate & Hot-Reload  (instantaneous, zero downtime)     │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  POST /v1/admin/rotate-dek                                           │
│                                                                      │
│  1. new_raw_hex = secrets.token_hex(32)                              │
│     new_dek     = sha256(new_raw_hex.encode())   # 32-byte AES key   │
│  2. _store_secret_version("uppass-dek", new_raw_hex)                 │
│     → stored as SM version N+1                                       │
│  3. state.dek_keys[new_ver]     = new_dek                            │
│     state.current_dek_version   = new_ver                            │
│                                                                      │
│  ✓ New submits write with new_ver                                    │
│  ✓ Old records still decrypt with old key (still in state dict)      │
│  ✓ Any future restart loads both from SM                             │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│  PHASE 2 — Re-encryption  (chunked, same pattern as HMAC rotation)   │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  POST /v1/admin/rotate-dek  { "chunk_size": 1000 }                  │
│                                                                      │
│  Response: { new_version, reencrypted_records,                       │
│              remaining_records, message }                            │
│                                                                      │
│  First call  → generates new DEK, hot-reloads, re-encrypts chunk     │
│  Subsequent  → continues migrating remaining old-version records     │
│  Final call  → remaining_records = 0, migration complete             │
│                                                                      │
│  for record in db.where(dek_version != new_ver).limit(chunk_size):  │
│      plaintext             = aes_gcm_decrypt(record, old_dek)        │
│      record.encrypted_data = aes_gcm_encrypt(plaintext, new_dek)     │
│      record.storage_iv     = new_random_iv        # fresh IV         │
│      record.dek_version    = new_ver                                 │
│      db.save(record)                                                 │
│                                                                      │
│  • Reads and writes continue normally throughout                     │
│  • Idempotent — safe to stop, restart, or call in parallel batches   │
│  • Each chunk is a separate DB transaction                           │
│  • Demo UI: one chunk per button click; auto-loop checkbox for       │
│    hands-free completion                                             │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│  PHASE 3 — Cleanup  (after migration confirmed 100 %)                │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. Verify:  SELECT COUNT(*) WHERE dek_version = old_ver → must = 0  │
│  2. Disable SM version N of uppass-dek                               │
│     (keep 90 days for audit, then destroy)                           │
│  3. Update compliance documentation                                  │
└──────────────────────────────────────────────────────────────────────┘
```

---

### State During DEK Transition

```
Time ──────────────────────────────────────────────────────────────►

        rotate-dek called             re-encryption done
              │                              │
 v1 only      ▼   v1 + v2 in state           ▼   v2 only
 ─────────────┬──────────────────────────────┬─────────────────────
 All DB: v1   │  DB: v1 + v2                 │  DB: all v2
              │  state.dek_keys = {v1, v2}   │  v1 SM version disabled
              │  new writes: v2              │
              │  old reads:  v1 still works  │
              │                              │
              └─── re-encryption batch ──────┘
                   (minutes for demo; hours/days for millions)

Restarts during this window:
  init_dek queries DB → finds {v1, v2} → loads both from SM → correct
```

---

### HMAC Blind Index Rotation (Chunked)

The `search_index` column uses a separate HMAC secret — independent of the DEK. The blind index cannot simply be re-encrypted; the record must be fully decrypted, then the new HMAC computed over the plaintext and written back.

```
POST /v1/admin/rotate-hmac  { "chunk_size": 1000 }

First call  → generates new secret, stores to SM, hot-reloads, begins migration
              { new_version: "v2", recomputed_records: 1000, remaining_records: 45230 }

Subsequent  → continues migrating remaining old-version records
              { new_version: "v2", recomputed_records: 1000, remaining_records: 44230 }

Final call  → { new_version: "v2", recomputed_records: 230, remaining_records: 0 }

POST /v1/admin/rotate-dek uses the identical chunked pattern:
              { new_version: "v2", reencrypted_records: 1000, remaining_records: 44230 }
```

**Search during migration** — `state.hmac_secrets` is a dict loaded from SM at startup, same pattern as `dek_keys`. Search tries every version so no record becomes unfindable:

```python
# state after HMAC rotation (both versions loaded from SM at startup)
state.hmac_secrets = {
    "v1": b"original_secret_hex",   # old records still use this search_index
    "v2": b"new_secret_hex",        # new / migrated records use this
}

# search endpoint — tries newest version first, falls back to older
def search(national_id: str, db):
    for ver in sorted(state.hmac_secrets, key=lambda v: int(v[1:]), reverse=True):
        blind = hmac_sha256(national_id, state.hmac_secrets[ver])
        record = db.filter(search_index == blind).first()
        if record:
            return found(record)
    return not_found()
```

```
State during HMAC migration (same process or after restart):
─────────────────────────────────────────────────────────────
Record a1b2  hmac_version="v1"  → search tries v2 (miss) → tries v1 (hit) ✓
Record c3d4  hmac_version="v2"  → search tries v2 (hit)                   ✓
New submit   hmac_version="v2"  → written with v2 HMAC                    ✓
```

---

### Key Derivation

DEK: `SHA-256(raw_hex_string)` → 32-byte AES key. The raw hex is stored in Secret Manager; the derived key is never persisted.

```python
raw_hex = "a3f9bc…"                              # 64-char hex, stored in SM
aes_key = hashlib.sha256(raw_hex.encode()).digest()  # 32 bytes, in memory only
```

HMAC: raw bytes of the secret string, used directly as the HMAC key.

```python
raw = "d8e2fa…"                  # stored in SM
hmac_key = raw.encode("utf-8")   # bytes, in memory only
```

Both are deterministic: given the same SM version, every restart produces the same key.

---

### Compliance Summary

| Requirement | How it is met |
|-------------|---------------|
| Annual DEK rotation | `POST /v1/admin/rotate-dek` — generates, stores to SM as new version, hot-reloads, re-encrypts |
| Zero downtime (live rotation) | Old key stays in `state.dek_keys`; new writes use new key immediately |
| Zero downtime (after restart) | `init_dek` queries DB for all `dek_version` labels, fetches each from SM by version number |
| HMAC rotation — no search disruption | `state.hmac_secrets` dict; search tries all versions; all reloaded from SM on restart |
| Auditability | Every record carries its own `dek_version`, `hmac_version`, `key_version`; SM access logs every fetch |
| Old key retention | Previous SM versions stay ENABLED during migration; disabled only after `COUNT(old_ver) = 0` |
| Deterministic state reconstruction | Version label `"vN"` = SM version `N` — no env var drift, no config lookup, no guessing |

---
---

## Scenario B: Data Leak Incident Response

### Incident

> "A security audit reveals that a developer accidentally logged the decrypted National ID into Cloud Logging for the past 24 hours."

---

### Live Demo in This Project

The `/v1/submit-unsafe` endpoint simulates exactly this mistake. It processes the payload correctly but intentionally writes:

```
WARNING SECURITY_VIOLATION: national_id=1234567890123 logged by unsafe endpoint
```

The frontend **Security Monitor** module:
- Triggers the leak via "Submit Unsafe" button
- Polls `/v1/admin/monitor/violations` → queries Cloud Logging for `SECURITY_VIOLATION` entries
- Displays a live feed with timestamp, severity, payload
- Links to GCP Logs Explorer, Metrics Explorer, and Alert Policies

A log-based metric (`uppass-pii-leak`) counts violations. An alerting policy fires an email within ~60 seconds of the first entry appearing.

---

### Incident Timeline & Immediate Actions

```
T + 0 min   CONTAIN
            ├─ Identify offending code (log statement in decrypt/submit handler)
            ├─ Build and deploy fixed image immediately
            │    gcloud builds submit . --config=cloudbuild.yaml
            │    gcloud run deploy uppass-api --image=<fixed>:latest --region=asia-southeast1
            └─ If deploy takes > 5 min: route 0 % traffic to current revision
                 gcloud run services update-traffic uppass-api \
                   --to-revisions=LATEST=0 --region=asia-southeast1

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
            │    • Total unique national IDs in the log
            │    • Exact first and last timestamp of exposure
            │    • Which Cloud Run revision introduced the bug (gcloud run revisions list)
            │    • Whether any log sinks (BigQuery, GCS, Pub/Sub) ingested the entries
            └─ Do NOT delete logs yet — they are legal evidence

T + 20 min  ESCALATE
            ├─ Notify: DPO, CISO, Legal, Engineering Director
            ├─ Open incident channel — e.g. Slack #inc-2026-04-22-pii-leak
            ├─ Rule: NO plaintext national IDs in the channel — reference count/range only
            └─ Assign Incident Commander and Scribe

T + 30 min  PRESERVE — evidence before any deletion
            ├─ Export affected log entries to a restricted GCS bucket (legal hold):
            │    gcloud logging sinks create inc-hold-2026-04-22 \
            │      storage.googleapis.com/uppass-incident-hold \
            │      --log-filter='resource.labels.service_name="uppass-api"
            │                    AND textPayload=~"national_id"'
            └─ Screenshot GCP Console log entries with timestamps for legal record

T + 60 min  NOTIFY (regulatory obligation)
            ├─ PDPA Thailand: notify PDPC within 72 hours of discovery
            ├─ GDPR (if applicable): notify supervisory authority within 72 hours
            └─ Draft affected-individual notification letters (coordinate with Legal)
```

---

### Remediation Steps

```
┌────────────────────────────────────────────────────────────────────────┐
│  Step 1 — Stop the bleeding                                            │
│                                                                        │
│  Remove the log statement, deploy the fix.                             │
│  Send a test request and confirm national_id no longer appears in      │
│  Cloud Logging before declaring containment complete.                  │
└────────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────────┐
│  Step 2 — Log purge                                                    │
│                                                                        │
│  Cloud Logging entries are immutable — they cannot be selectively      │
│  edited or deleted. Options (apply after legal hold is secured):       │
│                                                                        │
│  a. Shorten log bucket retention (entries expire automatically)        │
│       gcloud logging buckets update _Default \                         │
│         --location=global --retention-days=1                           │
│                                                                        │
│  b. Delete the entire stdout log (nuclear — loses all log history)     │
│       gcloud logging logs delete \                                     │
│         "projects/PROJECT/logs/run.googleapis.com%2Fstdout"            │
│                                                                        │
│  c. Add a log exclusion to stop ingesting future PII lines             │
│       gcloud logging sinks create pii-exclusion /dev/null \            │
│         --log-filter='textPayload=~"national_id"'                      │
│     (does not remove already-written entries)                          │
│                                                                        │
│  Always preserve the secured GCS copy BEFORE purging.                 │
└────────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────────┐
│  Step 3 — Assess affected individuals                                  │
│                                                                        │
│  For each unique national ID found in the audit log:                   │
│    • Cross-reference with DB records to identify the person            │
│    • Assess identity-theft risk (name + ID = high risk)                │
│    • Prepare individual notification letters                           │
│    • Offer credit monitoring for high-risk cases                       │
└────────────────────────────────────────────────────────────────────────┘
```

---

### Technical Controls to Prevent Recurrence

#### Control 1 — PII Scrubbing Middleware (defence-in-depth)

Even if a developer accidentally logs `national_id`, this filter replaces the value before it reaches Cloud Logging.

```python
import re, logging

_NATIONAL_ID_RE = re.compile(r'\b\d{13}\b')   # Thai 13-digit National ID

class PIIScrubFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg  = _NATIONAL_ID_RE.sub('[REDACTED]', str(record.msg))
        record.args = ()
        return True

# Applied at startup — covers every logger in the process
for handler in logging.root.handlers:
    handler.addFilter(PIIScrubFilter())
```

---

#### Control 2 — Structured Logging Allowlist

**Rule: log IDs and version labels, never values.**

```python
# ❌ WRONG — entire dict may contain PII
log.info("Processing: %s", record.__dict__)
log.debug("Decrypted: %s", national_id)

# ✅ CORRECT — only safe fields explicitly chosen
log.info("Stored ref=%s dek_version=%s hmac_version=%s",
         record.id, record.dek_version, record.hmac_version)
```

---

#### Control 3 — Semgrep Static Analysis in CI

Blocks the pull request if any `log.*()` call receives a variable named `national_id` or `plaintext`.

```yaml
# .semgrep.yml
rules:
  - id: no-pii-in-logs
    languages: [python]
    patterns:
      - pattern: log.$FUNC(..., national_id, ...)
      - pattern: log.$FUNC(..., plaintext, ...)
      - pattern: logging.$FUNC(..., national_id, ...)
      - pattern: logging.$FUNC(..., plaintext, ...)
    message: "PII variable passed to log — use ref/version labels only"
    severity: ERROR
```

```yaml
# In CI pipeline (e.g. Cloud Build step or GitHub Actions)
- name: Semgrep PII check
  run: semgrep --config .semgrep.yml backend/ --error
```

---

#### Control 4 — TruffleHog in Cloud Build (implemented)

```yaml
# cloudbuild.yaml step 1 — blocks build if any hardcoded secret is found
- id: secret-scan
  name: trufflesecurity/trufflehog:latest
  args:
    - filesystem
    - /workspace
    - --fail
    - --no-update
    - --exclude-paths=/workspace/.trufflehog-exclude
```

Both Docker image builds (`build-backend`, `build-frontend`) declare `waitFor: [secret-scan]` so they only run if the scan passes.

---

#### Control 5 — GCP Real-Time Alerting (implemented)

```
Developer accidentally logs national_id
            │
            ▼
Cloud Run stdout → Cloud Logging ingests entry
            │
            ▼
Log-based metric "uppass-pii-leak" increments
(filter: textPayload =~ "SECURITY_VIOLATION")
            │
            ▼  threshold: count > 0
Alerting policy "UpPass PII Leak Alert" fires
            │
            ▼
Email → josukekung@gmail.com  (within ~60 seconds)
            │
            ▼
Engineer investigates — breach window: minutes, not 24 hours
```

Without this alerting: a breach discovered only at the next audit = 24+ hours of exposure.
With this alerting: notified within 1 minute = minimal exposure window.

---

#### Control 6 — PR Review Checklist

```markdown
## Security Checklist (required for every PR touching submit/decrypt paths)
- [ ] No PII (national ID, name, phone) passed to any log statement
- [ ] All new secrets stored in Secret Manager, not env vars or code
- [ ] No secrets committed (TruffleHog blocks the build if any are found)
- [ ] Decrypt/submit logic reviewed by a second engineer
- [ ] Semgrep PII check passing in CI
```

---

### Defence-in-Depth Summary

```
Attack: developer accidentally calls log.warning("...", national_id, ...)

Layer 1 — Prevention at code review (before merge)
  ├─ Semgrep blocks PR: log($FUNC, ..., national_id, ...) pattern detected
  └─ PR checklist: second-engineer review required for all decrypt paths

Layer 2 — Prevention at runtime (even if merged)
  └─ PIIScrubFilter: replaces \d{13} with [REDACTED] before log write
     → log entry contains "[REDACTED]" not the real national ID

Layer 3 — Detection (even if scrubbing missed it)
  ├─ Log-based metric counts "SECURITY_VIOLATION" entries
  └─ Alert fires within ~60 seconds → on-call notified immediately

Layer 4 — Response
  ├─ Redeploy fix, disable endpoint if needed
  ├─ Scope damage: gcloud logging read + audit log export
  └─ PDPA/GDPR notification, individual letters, post-mortem

Without Layer 3:  24+ hours silent exposure
With    Layer 3:  ~1 minute to detection
```

---

### Post-Incident Review (1 Week After Containment)

Hold a **blameless post-mortem**. Systemic improvement, not individual blame.

| Section | Content |
|---------|---------|
| **Timeline** | Code commit → deployment → first log entry → alert → containment |
| **Root cause** | Debug log statement left in production code, not caught in review |
| **Contributing factors** | No scrubbing middleware, no lint rule, alert not configured at time of incident |
| **Impact** | N unique national IDs, T hours of exposure, Y log sinks reached |
| **What went well** | Fast containment once alert fired; legal hold preserved before purge |
| **Action items** | PIIScrubFilter (Platform, 3 days) · Semgrep rule (Security, 1 week) · PR checklist update (Tech Lead, 1 day) · GCP alerting (already done) |

Circulate to all engineers. Review action items at next sprint retro.

---

*UpPass Secure Bridge — Part 3 System Design & Incident Response*
