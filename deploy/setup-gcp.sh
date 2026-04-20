#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# UpPass — GCP one-time infrastructure setup
# Run this ONCE before deploying Cloud Run services.
#
# Prerequisites:
#   gcloud CLI installed and authenticated  (gcloud auth login)
#   Keys already generated:  cd backend && python scripts/generate_keys.py
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Configure these ───────────────────────────────────────────────────────────
PROJECT_ID="${GCP_PROJECT_ID:?Set GCP_PROJECT_ID}"
REGION="${GCP_REGION:-asia-southeast1}"
SQL_INSTANCE="uppass-mysql"
SQL_DB="uppass"
SQL_USER="uppass"
SQL_PASSWORD="${DB_PASSWORD:?Set DB_PASSWORD}"

echo "==> Setting project: $PROJECT_ID"
gcloud config set project "$PROJECT_ID"

# ── Enable APIs ───────────────────────────────────────────────────────────────
echo "==> Enabling APIs..."
gcloud services enable \
  run.googleapis.com \
  sqladmin.googleapis.com \
  secretmanager.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com

# ── Artifact Registry ─────────────────────────────────────────────────────────
echo "==> Creating Artifact Registry repository..."
gcloud artifacts repositories create uppass \
  --repository-format=docker \
  --location="$REGION" \
  --description="UpPass Docker images" || true

# ── Cloud SQL (MySQL 8.0) ─────────────────────────────────────────────────────
echo "==> Creating Cloud SQL instance (this takes ~5 min)..."
gcloud sql instances create "$SQL_INSTANCE" \
  --database-version=MYSQL_8_0 \
  --tier=db-f1-micro \
  --region="$REGION" \
  --storage-auto-increase \
  --backup-start-time=02:00 || true

echo "==> Creating database and user..."
gcloud sql databases create "$SQL_DB" --instance="$SQL_INSTANCE" || true
gcloud sql users create "$SQL_USER" \
  --instance="$SQL_INSTANCE" \
  --password="$SQL_PASSWORD" || true

# ── Secret Manager ────────────────────────────────────────────────────────────
echo "==> Storing secrets in Secret Manager..."

HMAC=$(python3 -c "import secrets; print(secrets.token_hex(32))")
DEK=$(python3 -c "import secrets; print(secrets.token_hex(32))")

echo -n "$HMAC" | gcloud secrets create uppass-hmac-secret \
  --data-file=- --replication-policy=automatic || \
  echo -n "$HMAC" | gcloud secrets versions add uppass-hmac-secret --data-file=-

echo -n "$DEK" | gcloud secrets create uppass-dek \
  --data-file=- --replication-policy=automatic || \
  echo -n "$DEK" | gcloud secrets versions add uppass-dek --data-file=-

echo -n "$SQL_PASSWORD" | gcloud secrets create uppass-db-password \
  --data-file=- --replication-policy=automatic || \
  echo -n "$SQL_PASSWORD" | gcloud secrets versions add uppass-db-password --data-file=-

# Store RSA private key
gcloud secrets create uppass-private-key-v1 \
  --data-file=backend/keys/private_v1.pem \
  --replication-policy=automatic || \
  gcloud secrets versions add uppass-private-key-v1 \
    --data-file=backend/keys/private_v1.pem

echo ""
echo "==> Write these to your .env (for local dev only):"
echo "    HMAC_SECRET=$HMAC"
echo "    DATA_ENCRYPTION_KEY=$DEK"
echo ""
echo "✅ GCP infrastructure ready. Run ./deploy/deploy.sh next."
