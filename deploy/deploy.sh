#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# UpPass — Build & deploy both Cloud Run services
# Run:  ./deploy/deploy.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

PROJECT_ID="${GCP_PROJECT_ID:?Set GCP_PROJECT_ID}"
REGION="${GCP_REGION:-asia-southeast1}"
REGISTRY="$REGION-docker.pkg.dev/$PROJECT_ID/uppass"
SQL_INSTANCE="uppass-mysql"
SQL_DB="uppass"
SQL_USER="uppass"
SQL_CONNECTION_NAME="$PROJECT_ID:$REGION:$SQL_INSTANCE"

gcloud config set project "$PROJECT_ID"
gcloud auth configure-docker "$REGION-docker.pkg.dev" --quiet

# ── Build & push images ───────────────────────────────────────────────────────
echo "==> Building backend..."
docker build -t "$REGISTRY/backend:latest" ./backend
docker push "$REGISTRY/backend:latest"

echo "==> Building frontend..."
docker build -t "$REGISTRY/frontend:latest" ./frontend-lib
docker push "$REGISTRY/frontend:latest"

# ── Deploy backend ────────────────────────────────────────────────────────────
echo "==> Deploying backend Cloud Run service..."
gcloud run deploy uppass-api \
  --image="$REGISTRY/backend:latest" \
  --region="$REGION" \
  --platform=managed \
  --allow-unauthenticated \
  --port=8080 \
  --memory=512Mi \
  --cpu=1 \
  --min-instances=0 \
  --max-instances=10 \
  --add-cloudsql-instances="$SQL_CONNECTION_NAME" \
  --set-env-vars="ENV=production" \
  --set-env-vars="DATABASE_URL=mysql+pymysql://$SQL_USER:__DB_PASS__@/uppass?unix_socket=/cloudsql/$SQL_CONNECTION_NAME" \
  --set-env-vars="PRIVATE_KEY_PATH=/run/secrets/private_key" \
  --set-secrets="HMAC_SECRET=uppass-hmac-secret:latest" \
  --set-secrets="DATA_ENCRYPTION_KEY=uppass-dek:latest" \
  --set-secrets="/run/secrets/private_key=uppass-private-key-v1:latest" \
  --set-secrets="DB_PASSWORD=uppass-db-password:latest"

# Grab the backend URL to inject into the frontend
BACKEND_URL=$(gcloud run services describe uppass-api \
  --region="$REGION" --format="value(status.url)")
echo "==> Backend URL: $BACKEND_URL"

# Fix DATABASE_URL with real DB password (Cloud Run resolves the secret at runtime)
# The DB password is injected via --set-secrets as DB_PASSWORD env var
# Update the DATABASE_URL to reference it properly
gcloud run services update uppass-api \
  --region="$REGION" \
  --set-env-vars="DATABASE_URL=mysql+pymysql://$SQL_USER:\$(DB_PASSWORD)@/uppass?unix_socket=/cloudsql/$SQL_CONNECTION_NAME"

# ── Deploy frontend ───────────────────────────────────────────────────────────
echo "==> Deploying frontend Cloud Run service..."
gcloud run deploy uppass-frontend \
  --image="$REGISTRY/frontend:latest" \
  --region="$REGION" \
  --platform=managed \
  --allow-unauthenticated \
  --port=8080 \
  --memory=256Mi \
  --cpu=1 \
  --min-instances=0 \
  --max-instances=5 \
  --set-env-vars="UPPASS_API_URL=$BACKEND_URL"

FRONTEND_URL=$(gcloud run services describe uppass-frontend \
  --region="$REGION" --format="value(status.url)")
echo "==> Frontend URL: $FRONTEND_URL"

# Update backend CORS to allow the frontend origin
gcloud run services update uppass-api \
  --region="$REGION" \
  --set-env-vars="ALLOWED_ORIGINS=$FRONTEND_URL"

echo ""
echo "✅ Deployment complete!"
echo "   Frontend : $FRONTEND_URL"
echo "   Backend  : $BACKEND_URL"
echo "   API docs : $BACKEND_URL/docs"
