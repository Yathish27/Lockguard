#!/usr/bin/env bash
# Deploy Lockguard: static UI to Firebase Hosting, API to Cloud Run. Run from the repo root.
set -euo pipefail

PROJECT="${LOCKGUARD_GCP_PROJECT:-lockguard-9b9b2}"
REGION="${LOCKGUARD_REGION:-us-central1}"
SERVICE="lockguard-api"

command -v firebase >/dev/null || { echo "firebase CLI not found: npm install -g firebase-tools"; exit 1; }
command -v gcloud >/dev/null || { echo "gcloud not found: https://cloud.google.com/sdk/docs/install"; exit 1; }

echo "==> Project: $PROJECT  Region: $REGION"
gcloud config set project "$PROJECT" >/dev/null

echo "==> Building UI"
npm ci
npm run build

echo "==> Deploying API to Cloud Run ($SERVICE)"
gcloud run deploy "$SERVICE" \
  --source . \
  --region "$REGION" \
  --allow-unauthenticated \
  --memory 2Gi --cpu 2 \
  --min-instances 1 --max-instances 1 \
  --no-cpu-throttling \
  --timeout 300 \
  --set-env-vars LOCKGUARD_HOSTED=1

echo "==> Deploying Hosting"
firebase deploy --only hosting --project "$PROJECT"

echo "==> Done. Open: https://$PROJECT.web.app"
