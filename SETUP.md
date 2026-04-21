# UpPass — GCP Cloud Setup Guide

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Google Cloud SDK | 562+ | https://cloud.google.com/sdk/docs/install |
| Python | 3.12+ | https://python.org |
| Node.js | 18+ | https://nodejs.org |

Authenticate gcloud before starting:
```bash
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
gcloud config set compute/region asia-southeast1
```

---

## Architecture

```
Browser
  └── Cloud Run: uppass-frontend  (nginx, port 8080)
        └── fetches /v1/public-key, POSTs /v1/submit, calls admin endpoints
              └── Cloud Run: uppass-api  (FastAPI, port 8080, --workers 1)
                    ├── Cloud SQL: uppass-mysql  (MySQL 8.0)
                    ├── Secret Manager
                    │     ├── uppass-private-key-v1-b64
                    │     ├── uppass-hmac-secret
                    │     ├── uppass-dek
                    │     └── uppass-db-password
                    └── Cloud Logging  ← queried by /v1/admin/monitor/violations
```

> **Single worker requirement:** The backend holds RSA, DEK, and HMAC keys in process memory.
> Deploy with `--workers 1` and `--max-instances=1` to prevent key-state divergence across instances.

---

## Step 1 — Generate RSA Keys (one time, local dev only)

```bash
cd backend
python scripts/generate_keys.py
# Creates: keys/private_v1.pem  keys/public_v1.pem
```

These files are gitignored and excluded from Cloud Build. In production, the private key is stored in Secret Manager (Step 5).

---

## Step 2 — Enable GCP APIs

```bash
gcloud services enable \
  run.googleapis.com \
  sqladmin.googleapis.com \
  sql-component.googleapis.com \
  secretmanager.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  logging.googleapis.com \
  monitoring.googleapis.com
```

---

## Step 3 — Artifact Registry

```bash
gcloud artifacts repositories create uppass \
  --repository-format=docker \
  --location=asia-southeast1 \
  --description="UpPass Docker images"
```

---

## Step 4 — Cloud SQL (MySQL 8.0)

```bash
# Create instance (~5 min)
gcloud sql instances create uppass-mysql \
  --database-version=MYSQL_8_0 \
  --tier=db-f1-micro \
  --region=asia-southeast1 \
  --storage-auto-increase \
  --backup-start-time=02:00

# Create database
gcloud sql databases create uppass --instance=uppass-mysql

# Create user  (replace PASSWORD with your password)
gcloud sql users create dbadmin \
  --instance=uppass-mysql \
  --password='YOUR_DB_PASSWORD'
```

> **Note:** If your password contains `#`, URL-encode it as `%23` in `DATABASE_URL`.

---

## Step 5 — Secret Manager

```bash
PROJECT_ID=$(gcloud config get-value project)

# Generate cryptographic secrets
HMAC=$(python -c "import secrets; print(secrets.token_hex(32))")
DEK=$(python  -c "import secrets; print(secrets.token_hex(32))")

# Store HMAC secret
echo -n "$HMAC" | gcloud secrets create uppass-hmac-secret \
  --data-file=- --replication-policy=automatic

# Store DEK
echo -n "$DEK"  | gcloud secrets create uppass-dek \
  --data-file=- --replication-policy=automatic

# Store DB password
echo -n 'YOUR_DB_PASSWORD' | gcloud secrets create uppass-db-password \
  --data-file=- --replication-policy=automatic

# Store RSA private key as base64
python -c "
import base64
with open('backend/keys/private_v1.pem','rb') as f:
    print(base64.b64encode(f.read()).decode())
" | gcloud secrets create uppass-private-key-v1-b64 \
  --data-file=- --replication-policy=automatic
```

Save `HMAC` and `DEK` values to your local `.env` for local development.

---

## Step 6 — IAM Permissions

```bash
SA=$(gcloud projects describe $(gcloud config get-value project) \
  --format="value(projectNumber)")"-compute@developer.gserviceaccount.com"

# Secret Manager access
for secret in uppass-hmac-secret uppass-dek uppass-private-key-v1-b64 uppass-db-password; do
  gcloud secrets add-iam-policy-binding $secret \
    --member="serviceAccount:$SA" \
    --role="roles/secretmanager.secretAccessor"
done

# Cloud Logging read access (required for /v1/admin/monitor/violations)
gcloud projects add-iam-policy-binding $(gcloud config get-value project) \
  --member="serviceAccount:$SA" \
  --role="roles/logging.viewer"
```

---

## Step 7 — Build Docker Images (via Cloud Build)

No local Docker required. Cloud Build runs TruffleHog secret scanning first, then builds both images in parallel.

```bash
# Authenticate Docker (first time only)
gcloud auth configure-docker asia-southeast1-docker.pkg.dev

# Build backend + frontend (TruffleHog scan gates both builds)
gcloud builds submit . --config=cloudbuild.yaml
```

The `cloudbuild.yaml` pipeline:
1. **Step 1** — TruffleHog filesystem scan (fails build if any hardcoded secrets are found)
2. **Step 2a** — Build backend image (runs in parallel after scan passes)
3. **Step 2b** — Build frontend image (runs in parallel after scan passes)

---

## Step 8 — Deploy Backend (Cloud Run)

```bash
PROJECT_ID=$(gcloud config get-value project)
SQL_CONN="$PROJECT_ID:asia-southeast1:uppass-mysql"
REGISTRY="asia-southeast1-docker.pkg.dev/$PROJECT_ID/uppass"
DB_PASS_ENCODED="YOUR_DB_PASSWORD"   # URL-encode # as %23

gcloud run deploy uppass-api \
  --image="$REGISTRY/backend:latest" \
  --region=asia-southeast1 \
  --platform=managed \
  --allow-unauthenticated \
  --port=8080 \
  --memory=512Mi \
  --cpu=1 \
  --min-instances=0 \
  --max-instances=1 \
  --add-cloudsql-instances="$SQL_CONN" \
  --set-env-vars="ENV=production" \
  --set-env-vars="ENABLE_DOCS=true" \
  --set-env-vars="GOOGLE_CLOUD_PROJECT=$PROJECT_ID" \
  --set-env-vars="DATABASE_URL=mysql+pymysql://dbadmin:${DB_PASS_ENCODED}@/uppass?unix_socket=/cloudsql/${SQL_CONN}" \
  --set-secrets="HMAC_SECRET=uppass-hmac-secret:1" \
  --set-secrets="DATA_ENCRYPTION_KEY=uppass-dek:1" \
  --set-secrets="PRIVATE_KEY_B64=uppass-private-key-v1-b64:1"
```

> **`--max-instances=1`**: The backend holds RSA/DEK/HMAC keys in process memory. Multiple instances would each have independent key state, causing decryption failures on requests routed to a different instance. Keep at 1 until the architecture moves keys to an external store (e.g., Cloud KMS).

Note the backend URL, e.g.:
```
Service URL: https://uppass-api-XXXXXXXXX.asia-southeast1.run.app
```

---

## Step 9 — Deploy Frontend (Cloud Run)

```bash
BACKEND_URL="https://uppass-api-XXXXXXXXX.asia-southeast1.run.app"
REGISTRY="asia-southeast1-docker.pkg.dev/$(gcloud config get-value project)/uppass"

gcloud run deploy uppass-frontend \
  --image="$REGISTRY/frontend:latest" \
  --region=asia-southeast1 \
  --platform=managed \
  --allow-unauthenticated \
  --port=8080 \
  --memory=256Mi \
  --cpu=1 \
  --min-instances=0 \
  --max-instances=5 \
  --set-env-vars="UPPASS_API_URL=$BACKEND_URL"
```

Then update backend CORS with the frontend URL:

```bash
FRONTEND_URL="https://uppass-frontend-XXXXXXXXX.asia-southeast1.run.app"

gcloud run services update uppass-api \
  --region=asia-southeast1 \
  --update-env-vars="ALLOWED_ORIGINS=$FRONTEND_URL"
```

---

## Step 10 — Security Monitoring (GCP Alerting)

Set up a log-based metric and alerting policy so the team is notified immediately if a `SECURITY_VIOLATION` (PII in logs) event occurs.

```bash
# 1. Create log-based metric
gcloud logging metrics create uppass-pii-leak \
  --description="Counts SECURITY_VIOLATION PII leak log entries in Cloud Run" \
  --log-filter='resource.type="cloud_run_revision" AND resource.labels.service_name="uppass-api" AND textPayload=~"SECURITY_VIOLATION"'

# 2. Create email notification channel
gcloud beta monitoring channels create \
  --display-name="UpPass PII Alert" \
  --type="email" \
  --channel-labels="email_address=YOUR_EMAIL"

# Note the channel name from output:
# projects/PROJECT_ID/notificationChannels/CHANNEL_ID

# 3. Create alert policy (fires when metric count > 0)
# Save the JSON below as /tmp/alert-policy.json, replace CHANNEL with your channel name
cat > /tmp/alert-policy.json << 'EOF'
{
  "displayName": "UpPass PII Leak Alert",
  "conditions": [{
    "displayName": "SECURITY_VIOLATION log entries detected",
    "conditionThreshold": {
      "filter": "metric.type=\"logging.googleapis.com/user/uppass-pii-leak\" resource.type=\"cloud_run_revision\"",
      "comparison": "COMPARISON_GT",
      "thresholdValue": 0,
      "duration": "0s",
      "aggregations": [{
        "alignmentPeriod": "60s",
        "perSeriesAligner": "ALIGN_RATE",
        "crossSeriesReducer": "REDUCE_SUM"
      }]
    }
  }],
  "notificationChannels": ["YOUR_CHANNEL_NAME"],
  "combiner": "OR",
  "enabled": true
}
EOF

gcloud alpha monitoring policies create --policy-from-file=/tmp/alert-policy.json
```

---

## Step 11 — Verify

```bash
BACKEND_URL="https://uppass-api-XXXXXXXXX.asia-southeast1.run.app"

# Health check
curl $BACKEND_URL/health
# → {"status":"ok"}

# Public key
curl $BACKEND_URL/v1/public-key
# → {"key_version":"v1","public_key":"-----BEGIN PUBLIC KEY-----..."}

# Admin status
curl $BACKEND_URL/v1/admin/status
# → {"rsa_version":"v1","dek_version":"v1","hmac_version":"v1","total_records":0,"hmac_pending":0}

# API docs
open $BACKEND_URL/docs
```

Open the frontend URL in a browser to test submit, search, key rotation, and security monitoring.

---

## Redeployment (after code changes)

```bash
# Rebuild both images (TruffleHog scan runs automatically)
gcloud builds submit . --config=cloudbuild.yaml

# Redeploy both services (keeps existing env vars / secrets)
gcloud run deploy uppass-api \
  --image=asia-southeast1-docker.pkg.dev/$PROJECT_ID/uppass/backend:latest \
  --region=asia-southeast1

gcloud run deploy uppass-frontend \
  --image=asia-southeast1-docker.pkg.dev/$PROJECT_ID/uppass/frontend:latest \
  --region=asia-southeast1
```

---

## Key Rotation (via Admin Endpoints)

Key rotation is performed through the API — no redeployment required.

### RSA Key Rotation

```bash
curl -X POST $BACKEND_URL/v1/admin/rotate-rsa
# → {"new_version":"v2","message":"RSA key rotated and hot-reloaded"}
```

Or use the **Admin → Key Rotation** panel in the frontend UI.

### DEK Rotation

```bash
curl -X POST $BACKEND_URL/v1/admin/rotate-dek
# → {"new_version":"v2","reencrypted_records":N,"message":"..."}
```

### HMAC Rotation (chunked)

```bash
# Repeat until remaining_records = 0
curl -X POST $BACKEND_URL/v1/admin/rotate-hmac \
  -H "Content-Type: application/json" \
  -d '{"chunk_size": 1000}'
# → {"new_version":"v2","recomputed_records":1000,"remaining_records":500,"message":"..."}
```

The frontend HMAC card loops automatically until migration is complete.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `/v1/public-key` → 503 `No key loaded` | `PRIVATE_KEY_B64` secret not set or SA lacks access | Check Step 6, re-run `--set-secrets` |
| Container fails to start — DB connection error | `DATABASE_URL` not set or Cloud SQL connector missing | Re-run Step 8, verify `--add-cloudsql-instances` |
| `DATABASE_URL` truncated at `#` | `#` is URL fragment separator | URL-encode password: replace `#` with `%23` |
| `/docs` → 404 | `ENABLE_DOCS` not set | `--update-env-vars="ENABLE_DOCS=true"` |
| `Permission denied on secret` | SA not granted Secret Accessor role | Re-run Step 6 |
| `rotate_hmac` returns `recomputed_records: 0` | Multiple workers with divergent in-memory state | Ensure `--max-instances=1` and `--workers 1` in Dockerfile CMD |
| `/v1/admin/monitor/violations` returns empty or error | SA missing `roles/logging.viewer` | Re-run Step 6 logging.viewer grant |
| TruffleHog blocks Cloud Build | Hardcoded secret detected in source | Remove secret, store in Secret Manager, re-submit |

### Check running env vars

```bash
gcloud run services describe uppass-api \
  --region=asia-southeast1 \
  --format="value(spec.template.spec.containers[0].env)"
```

### Tail live logs

```bash
gcloud logging read \
  "resource.type=cloud_run_revision AND resource.labels.service_name=uppass-api" \
  --limit=50 --format="value(textPayload)"
```

### Check for PII violations in logs

```bash
gcloud logging read \
  'resource.type="cloud_run_revision" AND resource.labels.service_name="uppass-api" AND textPayload=~"SECURITY_VIOLATION"' \
  --limit=20 --format="value(timestamp,textPayload)"
```

---

## Deployed Resources

| Resource | Name / URL |
|----------|-----------|
| Cloud Run — Backend | https://uppass-api-909715233757.asia-southeast1.run.app |
| Cloud Run — Frontend | https://uppass-frontend-909715233757.asia-southeast1.run.app |
| Cloud SQL | `uppass-mysql` — asia-southeast1 |
| Artifact Registry | `asia-southeast1-docker.pkg.dev/gen-lang-client-0453424159/uppass` |
| Secret Manager | `uppass-hmac-secret`, `uppass-dek`, `uppass-db-password`, `uppass-private-key-v1-b64` |
| Log-based Metric | `uppass-pii-leak` — counts `SECURITY_VIOLATION` entries |
| Alert Policy | `UpPass PII Leak Alert` — emails `josukekung@gmail.com` when metric > 0 |
| Notification Channel | `UpPass PII Alert` — email |
