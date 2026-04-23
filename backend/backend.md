# Backend Architecture

## File Dependency Graph

```
main.py
  ├── state.py          (shared in-memory key state)
  ├── database.py       (ORM model, DB engine, session factory)
  ├── schemas.py        (Pydantic request/response models)
  ├── startup.py        (key loading at boot)
  │     ├── state.py
  │     ├── database.py (db_distinct_versions)
  │     └── gcp.py      (load_versioned_secret)
  ├── crypto.py         (RSA unwrap, AES-GCM, HMAC)
  │     ├── state.py
  │     └── gcp.py      (on-demand SM fetch)
  └── routers/
        ├── admin.py    (key rotation, record ops)
        │     ├── state.py
        │     ├── database.py
        │     ├── crypto.py
        │     ├── gcp.py
        │     └── schemas.py
        └── monitor.py  (unsafe submit, violation log query)
              ├── database.py
              └── gcp.py (Cloud Logging)
```

---

## state.py

**Role:** Shared mutable singleton that holds all in-process cryptographic material.

```python
class _State:
    private_keys: dict        = {}   # version label → RSA private key object
    current_rsa_version: str  = "v1"
    dek_keys: dict            = {}   # version label → 32-byte AES key
    current_dek_version: str  = "v1"
    hmac_secrets: dict        = {}   # version label → bytes
    current_hmac_version: str = "v1"

state = _State()
```

Every other module imports `state` directly. Because Python modules are singletons, all routers and helpers share the same object — no global variables or thread-local tricks needed.

The `current_*_version` fields track which key version to use for **new** records. Older versions are kept in the dicts so that existing records (which may reference an older version) remain decryptable.

---

## database.py

**Role:** Database engine, ORM model, session dependency, and schema helpers.

### Engine

SQLite is used when `DATABASE_URL` is not set (local dev). MySQL via Cloud SQL otherwise.

### NationalIdRecord (ORM model)

| Column | Type | Purpose |
|--------|------|---------|
| `id` | UUID (string) | Primary key |
| `encrypted_data` | Text | AES-GCM ciphertext (base64) of national ID |
| `storage_iv` | String | AES-GCM nonce (base64) |
| `search_index` | String | HMAC-SHA256 blind index — used for lookup without decryption |
| `key_version` | String | RSA key version that wrapped the transient AES key |
| `dek_version` | String | DEK version that encrypted the data |
| `hmac_version` | String | HMAC secret version that produced the search index |
| `created_at` | DateTime | Insert timestamp |

### db_distinct_versions(column)

Called during startup to discover which key versions the DB already references, so startup loads exactly those versions from Secret Manager.

### ensure_columns()

Adds any missing columns to an existing table with `ALTER TABLE` — handles schema migration without dropping data when a new column is introduced.

---

## gcp.py

**Role:** All Google Cloud API calls — Secret Manager and Cloud Logging.

### Secret naming convention

| Version label | SM resource accessed |
|---------------|----------------------|
| `v1` | `uppass-dek` version `1` (the original secret, first SM version) |
| `v2` | `uppass-dek-v2` version `latest` (a separate named secret) |
| `v3` | `uppass-dek-v3` version `latest` |

This avoids the drift problem where destroying SM version numbers (v2, v3…) of the original secret breaks the label → version number mapping.

### Key functions

- **`load_versioned_secret(base_id, ver_label)`** — returns secret payload as string
- **`create_versioned_secret(base_id, ver_label, data)`** — creates a new named secret and adds its first version; idempotent on `AlreadyExists`
- **`load_secret_version(secret_id, version_number)`** — low-level fetch by numeric SM version
- **`query_security_violations(hours, limit)`** — queries Cloud Logging for `SECURITY_VIOLATION` entries

In local dev (no `GOOGLE_CLOUD_PROJECT` env var), `_client()` will fail gracefully and env var fallbacks in `startup.py` take over.

---

## startup.py

**Role:** Loads all required key material from Secret Manager (or env var fallbacks) before the server starts accepting requests.

### Flow (called from `main.py` lifespan)

1. **`load_private_keys()`**
   - Queries `db_distinct_versions("key_version")` to find all RSA key versions referenced in the DB
   - Adds `v1` unconditionally
   - For each version: calls `load_versioned_secret("uppass-private-key-v1-b64", ver)`, decodes base64, deserialises PEM
   - Fallback for `v1`: `PRIVATE_KEY_B64` env var → local `.pem` file
   - Sets `state.current_rsa_version` to the highest loaded version

2. **`init_dek()`**
   - Same pattern for `dek_version` → `uppass-dek`
   - SHA-256 hashes the raw hex string to produce a 32-byte AES key
   - Fallback for `v1`: `DATA_ENCRYPTION_KEY` env var

3. **`init_hmac()`**
   - Same pattern for `hmac_version` → `uppass-hmac-secret`
   - Stores raw bytes
   - Fallback for `v1`: `HMAC_SECRET` env var

If any of the three functions cannot load at least one version, it raises `RuntimeError` and the process exits — the server never enters the serving state.

---

## crypto.py

**Role:** All cryptographic operations plus lazy-loading key getters.

### Key getters — cache-then-SM pattern

Each getter checks `state` first (O(1) dict lookup). On a cache miss it fetches from Secret Manager, caches the result, and returns. This makes multi-instance deployments safe: a new Cloud Run instance that missed a rotation on another instance will self-heal on the first request that references the new version.

```
get_storage_key("v3")
  → state.dek_keys has "v3"? → return it
  → miss → load_versioned_secret("uppass-dek", "v3")
         → cache in state.dek_keys["v3"]
         → return
```

### Crypto operations

| Function | Algorithm | Used for |
|----------|-----------|---------|
| `unwrap_aes_key(encrypted_key_b64, key_version)` | RSA-OAEP / SHA-256 | Recovers transient AES key from the submit payload |
| `aes_gcm_decrypt(ciphertext_b64, iv_b64, aes_key)` | AES-256-GCM | Decrypts national ID from storage |
| `aes_gcm_encrypt(plaintext, aes_key)` | AES-256-GCM | Re-encrypts during DEK rotation |
| `compute_blind_index(national_id, hmac_ver)` | HMAC-SHA256 | Produces searchable index without storing plaintext |

---

## schemas.py

**Role:** Pydantic models for request validation and response serialisation.

| Model | Endpoint |
|-------|---------|
| `SubmitRequest` | `POST /v1/submit` |
| `SubmitResponse` | `POST /v1/submit` |
| `SearchResponse` | `GET /v1/search` |
| `AdminStatusResponse` | `GET /v1/admin/status` |
| `RotateRSAResponse` | `POST /v1/admin/rotate-rsa` |
| `RotateDEKRequest` | `POST /v1/admin/rotate-dek` |
| `RotateDEKResponse` | `POST /v1/admin/rotate-dek` |
| `RotateHMACRequest` | `POST /v1/admin/rotate-hmac` |
| `RotateHMACResponse` | `POST /v1/admin/rotate-hmac` |

FastAPI uses these for automatic input validation and OpenAPI doc generation.

---

## main.py

**Role:** Application entry point — lifespan, CORS, and the core API endpoints.

### Lifespan

```python
@asynccontextmanager
async def lifespan(_app: FastAPI):
    ensure_columns()
    load_private_keys()
    init_dek()
    init_hmac()
    yield   # server is live
```

Everything in the `yield` block runs before the first request is served. The server only becomes healthy after all three key types are loaded.

### Core endpoints

| Method | Path | Action |
|--------|------|--------|
| `GET` | `/health` | Returns `{"status": "ok"}` — used by frontend cold-start poller |
| `GET` | `/v1/public-key` | Returns current RSA public key and version |
| `POST` | `/v1/submit` | Stores encrypted national ID |
| `GET` | `/v1/search` | Looks up a national ID by HMAC blind index |

Admin and monitor endpoints are mounted via `include_router`.

---

## routers/admin.py

**Role:** Key rotation and record management under `/v1/admin/`.

### Rotation pattern (DEK and HMAC — chunked)

Both DEK and HMAC rotations follow the same safe chunked pattern:

1. **First call** (no pending records on old version):
   - Generate new secret
   - **Write to Secret Manager** — if this fails, raise `HTTP 503` immediately, do not touch state
   - Update `state` with new key and bump `current_*_version`
   - Re-encrypt / recompute the first `chunk_size` records

2. **Subsequent calls** (pending records remain):
   - Skip secret generation, use `current_*_version` already set
   - Continue migrating the next chunk

3. **Return** includes `remaining_records` so the caller knows when to stop

The SM write is mandatory before any state mutation. This ensures a restart always sees the same key the in-memory state held, preventing version drift.

### RSA rotation

Not chunked — RSA wraps only a transient AES key per submit, so existing records are independent of the RSA version. Old RSA keys are kept in `state.private_keys` for decryption of records that still reference them.

### Other endpoints

| Endpoint | Purpose |
|---------|---------|
| `GET /v1/admin/status` | RSA/DEK/HMAC versions, total records, pending counts |
| `GET /v1/admin/records` | All record metadata (encrypted fields truncated) |
| `POST /v1/admin/records/delete-all` | Deletes records, leaves key state intact |
| `POST /v1/admin/reset-demo` | Deletes records **and** resets in-memory state to v1 |

---

## routers/monitor.py

**Role:** Security demonstration and violation log query under `/v1/`.

| Endpoint | Purpose |
|---------|---------|
| `POST /v1/submit-unsafe` | Intentionally logs `SECURITY_VIOLATION: national_id=<value>` to Cloud Logging |
| `GET /v1/admin/monitor/violations` | Queries Cloud Logging for `SECURITY_VIOLATION` entries, returns them as JSON |

The unsafe submit endpoint exists to demonstrate the PII-in-logs threat model and trigger the GCP alerting policy (`uppass-pii-leak` log metric → email alert).

---

## Request Flow: Submit

```
Browser
  1. Fetch GET /v1/public-key
       ← {"key_version": "v2", "public_key": "-----BEGIN PUBLIC KEY-----..."}

  2. Generate random AES-256 key (client-side)
  3. AES-GCM encrypt national_id with that key → {ciphertext, iv}
  4. RSA-OAEP encrypt the AES key with public_key → encrypted_key
  5. POST /v1/submit  {encrypted_national_id, iv, encrypted_key, key_version}

Backend
  6. unwrap_aes_key(encrypted_key, key_version) → transient AES key (RSA decrypt)
  7. aes_gcm_decrypt(encrypted_national_id, iv, aes_key) → national_id plaintext
  8. compute_blind_index(national_id, current_hmac_version) → search_index
  9. aes_gcm_encrypt(national_id, storage_key(current_dek_version)) → {new_ct, new_iv}
 10. INSERT NationalIdRecord(encrypted_data=new_ct, storage_iv=new_iv,
                              search_index=search_index,
                              key_version=key_version,
                              dek_version=current_dek_version,
                              hmac_version=current_hmac_version)
```

Note: the transient AES key from the browser is used only for decryption (step 6-7) and then discarded. The national ID is immediately re-encrypted with the server-side DEK (step 9) before storage. The RSA key protects the channel; the DEK protects storage.

---

## Request Flow: Search

```
Browser
  1. GET /v1/search?national_id=1234567890123

Backend
  2. For each HMAC version in state.hmac_secrets:
       compute_blind_index(national_id, ver) → candidate_index
       SELECT * FROM national_id_records WHERE search_index = candidate_index
       → if found: break

  3. On match:
       get_storage_key(rec.dek_version) → DEK bytes
       aes_gcm_decrypt(rec.encrypted_data, rec.storage_iv, dek) → plaintext
       ← {"found": true, "national_id": plaintext, ...}

  4. No match across any HMAC version:
       ← {"found": false}
```

Searching across all HMAC versions is required during rotation — records written under `v1` still have `v1` blind indexes even while `v2` is the current version. Once all records are migrated, only one version remains active.

---

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Named secrets per rotation label (`uppass-dek-v2`) | Avoids SM version number drift; deleting old SM versions cannot break the label mapping |
| Mandatory SM write before state mutation | Guarantees restarts see the same key state; 503 on write failure is safer than silent drift |
| Cache-then-SM in key getters | Multi-instance safe; new instances self-heal on first request referencing an unseen version |
| Three version columns per record | Independent rotation schedules; DEK and HMAC can be rotated separately |
| HMAC blind index (not plaintext search) | Enables lookup without storing or decrypting the national ID |
| Chunked DEK/HMAC rotation | No forced downtime for large datasets; caller controls pace |
