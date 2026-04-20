# UpPass — GCP Cloud Setup Guide

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Google Cloud SDK | 562+ | https://cloud.google.com/sdk/docs/install |
| Docker Desktop | any | https://www.docker.com/products/docker-desktop (local only) |
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
        └── fetches /v1/public-key, POSTs /v1/submit
              └── Cloud Run: uppass-api  (FastAPI, port 8080)
                    ├── Cloud SQL: uppass-mysql  (MySQL 8.0)
                    └── Secret Manager
                          ├── uppass-hmac-secret
                          ├── uppass-dek
                          ├── uppass-db-password
                          └── uppass-private-key-v1-b64
```

---

## Step 1 — Generate RSA Keys (one time)

```bash
cd backend
python scripts/generate_keys.py
# Creates: keys/private_v1.pem  keys/public_v1.pem
```

---

## Step 2 — Enable GCP APIs

```bash
gcloud services enable \
  run.googleapis.com \
  sqladmin.googleapis.com \
  sql-component.googleapis.com \
  secretmanager.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com
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

# Store secrets
echo -n "$HMAC" | gcloud secrets create uppass-hmac-secret \
  --data-file=- --replication-policy=automatic

echo -n "$DEK"  | gcloud secrets create uppass-dek \
  --data-file=- --replication-policy=automatic

echo -n 'YOUR_DB_PASSWORD' | gcloud secrets create uppass-db-password \
  --data-file=- --replication-policy=automatic

# Store RSA private key as base64 (used by Cloud Run via env var)
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

Grant the default Compute service account access to secrets:

```bash
SA=$(gcloud projects describe $(gcloud config get-value project) \
  --format="value(projectNumber)")"-compute@developer.gserviceaccount.com"

for secret in uppass-hmac-secret uppass-dek uppass-private-key-v1-b64; do
  gcloud secrets add-iam-policy-binding $secret \
    --member="serviceAccount:$SA" \
    --role="roles/secretmanager.secretAccessor"
done
```

---

## Step 7 — Build Docker Images (via Cloud Build)

No local Docker required — builds run on GCP.

```bash
REGISTRY="asia-southeast1-docker.pkg.dev/$(gcloud config get-value project)/uppass"

# Authenticate Docker
gcloud auth configure-docker asia-southeast1-docker.pkg.dev

# Build backend
gcloud builds submit ./backend \
  --tag $REGISTRY/backend:latest \
  --region=asia-southeast1

# Build frontend
gcloud builds submit ./frontend-lib \
  --tag $REGISTRY/frontend:latest \
  --region=asia-southeast1
```

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
  --max-instances=10 \
  --add-cloudsql-instances="$SQL_CONN" \
  --set-env-vars="ENV=production" \
  --set-env-vars="ENABLE_DOCS=true" \
  --set-env-vars="DATABASE_URL=mysql+pymysql://dbadmin:${DB_PASS_ENCODED}@/uppass?unix_socket=/cloudsql/${SQL_CONN}" \
  --set-env-vars="PRIVATE_KEY_PATH=/run/secrets/private_key" \
  --set-env-vars="ALLOWED_ORIGINS=https://placeholder" \
  --set-secrets="HMAC_SECRET=uppass-hmac-secret:latest" \
  --set-secrets="DATA_ENCRYPTION_KEY=uppass-dek:latest" \
  --set-secrets="PRIVATE_KEY_B64=uppass-private-key-v1-b64:latest"
```

Note the backend URL from the output, e.g.:
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

Note the frontend URL, then update backend CORS:

```bash
FRONTEND_URL="https://uppass-frontend-XXXXXXXXX.asia-southeast1.run.app"

gcloud run services update uppass-api \
  --region=asia-southeast1 \
  --update-env-vars="ALLOWED_ORIGINS=$FRONTEND_URL"
```

---

## Step 10 — Verify

```bash
BACKEND_URL="https://uppass-api-XXXXXXXXX.asia-southeast1.run.app"

# Health check
curl $BACKEND_URL/health
# → {"status":"ok"}

# Public key
curl $BACKEND_URL/v1/public-key
# → {"key_version":"v1","public_key":"-----BEGIN PUBLIC KEY-----..."}

# API docs
open $BACKEND_URL/docs
```

Open the frontend URL in a browser to test the full encrypt → submit → search flow.

---

## Redeployment (after code changes)

```bash
PROJECT_ID=$(gcloud config get-value project)
REGISTRY="asia-southeast1-docker.pkg.dev/$PROJECT_ID/uppass"

# Rebuild and push
gcloud builds submit ./backend  --tag $REGISTRY/backend:latest  --region=asia-southeast1
gcloud builds submit ./frontend-lib --tag $REGISTRY/frontend:latest --region=asia-southeast1

# Redeploy (picks up new image, keeps existing env vars)
gcloud run services update uppass-api      --region=asia-southeast1 --image=$REGISTRY/backend:latest
gcloud run services update uppass-frontend --region=asia-southeast1 --image=$REGISTRY/frontend:latest
```

---

## Key Rotation

```bash
# 1. Generate new key pair
cd backend && python scripts/generate_keys.py  # creates private_v2.pem

# 2. Store new key in Secret Manager
python -c "
import base64
with open('backend/keys/private_v2.pem','rb') as f:
    print(base64.b64encode(f.read()).decode())
" | gcloud secrets create uppass-private-key-v2-b64 --data-file=- --replication-policy=automatic

# 3. Grant access
gcloud secrets add-iam-policy-binding uppass-private-key-v2-b64 \
  --member="serviceAccount:$(gcloud projects describe $(gcloud config get-value project) \
    --format='value(projectNumber)')-compute@developer.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

# 4. Update service (new records use v2, old records still decrypt with v1)
gcloud run services update uppass-api --region=asia-southeast1 \
  --update-secrets="PRIVATE_KEY_B64=uppass-private-key-v2-b64:latest"
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `/v1/public-key` → 503 `No key loaded` | `PRIVATE_KEY_B64` secret not set or SA lacks access | Check Step 6, re-run `--update-secrets` |
| Container fails to start — `sqlite3 unable to open` | `DATABASE_URL` not set (fell back to SQLite) | Re-run Step 8, verify env vars with `gcloud run services describe` |
| `DATABASE_URL` truncated at `#` | `#` is URL fragment separator | URL-encode password: replace `#` with `%23` |
| `/docs` → 404 | `ENABLE_DOCS` not set or `false` | `--update-env-vars="ENABLE_DOCS=true"` |
| `Permission denied on secret` | SA not granted Secret Accessor role | Re-run Step 6 |

### Check running env vars

```bash
gcloud run services describe uppass-api \
  --region=asia-southeast1 \
  --format="value(spec.template.spec.containers[0].env)"
```

### Tail live logs

```bash
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=uppass-api" \
  --limit=50 --format="value(textPayload)"
```

---

## Deployed Resources (current)

| Resource | Name / URL |
|----------|-----------|
| Cloud Run — Backend | https://uppass-api-909715233757.asia-southeast1.run.app |
| Cloud Run — Frontend | https://uppass-frontend-909715233757.asia-southeast1.run.app |
| Cloud SQL | `uppass-mysql` — asia-southeast1-c |
| Artifact Registry | `asia-southeast1-docker.pkg.dev/gen-lang-client-0453424159/uppass` |
| Secret Manager secrets | `uppass-hmac-secret`, `uppass-dek`, `uppass-db-password`, `uppass-private-key-v1-b64` |
