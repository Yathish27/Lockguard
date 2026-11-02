#!/usr/bin/env bash
# One-time: let GitHub Actions in Yathish27/Lockguard deploy to Firebase/Cloud Run with NO stored key (OIDC).
# Run once with your own gcloud auth. Safe to re-run (commands are idempotent-ish; existing resources just error harmlessly).
set -euo pipefail

PROJECT="lockguard-9b9b2"
PROJECT_NUMBER="356135058855"
REGION="us-central1"
REPO="Yathish27/Lockguard"
POOL="github-pool"
PROVIDER="github-provider"
SA="lockguard-deployer"
SA_EMAIL="${SA}@${PROJECT}.iam.gserviceaccount.com"

command -v gcloud >/dev/null || { echo "gcloud not found: https://cloud.google.com/sdk/docs/install"; exit 1; }
echo "==> Using project $PROJECT (number $PROJECT_NUMBER), repo $REPO"
gcloud config set project "$PROJECT" >/dev/null

echo "==> Enabling APIs"
gcloud services enable \
  run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com \
  iamcredentials.googleapis.com firebasehosting.googleapis.com serviceusage.googleapis.com

echo "==> Creating the deploy service account"
gcloud iam service-accounts create "$SA" --display-name "Lockguard GitHub deployer" 2>/dev/null || echo "   (service account already exists)"

echo "==> Granting roles"
for ROLE in \
  roles/run.admin \
  roles/cloudbuild.builds.editor \
  roles/artifactregistry.admin \
  roles/firebasehosting.admin \
  roles/iam.serviceAccountUser \
  roles/storage.admin \
  roles/serviceusage.serviceUsageConsumer ; do
  gcloud projects add-iam-policy-binding "$PROJECT" \
    --member="serviceAccount:${SA_EMAIL}" --role="$ROLE" --condition=None >/dev/null
  echo "   granted $ROLE"
done

echo "==> Creating the Workload Identity pool + provider (GitHub OIDC)"
gcloud iam workload-identity-pools create "$POOL" --location=global \
  --display-name="GitHub Actions" 2>/dev/null || echo "   (pool already exists)"
gcloud iam workload-identity-pools providers create-oidc "$PROVIDER" \
  --location=global --workload-identity-pool="$POOL" \
  --display-name="GitHub provider" \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository" \
  --attribute-condition="assertion.repository=='${REPO}'" 2>/dev/null || echo "   (provider already exists)"

echo "==> Allowing ${REPO} to impersonate ${SA_EMAIL}"
gcloud iam service-accounts add-iam-policy-binding "$SA_EMAIL" \
  --role=roles/iam.workloadIdentityUser \
  --member="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL}/attribute.repository/${REPO}" >/dev/null

echo ""
echo "Done. These values are already hard-wired into .github/workflows/firebase-deploy.yml:"
echo "  workload_identity_provider: projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL}/providers/${PROVIDER}"
echo "  service_account:            ${SA_EMAIL}"
echo ""
echo "Now push to main (or run the 'deploy' workflow manually) and it deploys. No secrets stored."
