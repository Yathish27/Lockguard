# Deploying Lockguard to Firebase

Lockguard is designed to run locally, so the hosted version runs **only the parts that make sense in the cloud**:

| Module | Hosted on Firebase | Why |
|---|---|---|
| **Web** scan | Yes — public URLs only | SSRF guard blocks localhost, private, and cloud-metadata addresses |
| **Chain** scan + signer-policy linter | Yes | read-only RPC + pure logic |
| **Harden** tools (CSP, SRI, pin actions, revoke calldata) | Yes | stateless |
| **Repo** scan | No — local CLI only | it reads a local filesystem that does not exist in the cloud |
| **Lab** | No — local only | it spins up extra local servers |

The hosted server runs with `LOCKGUARD_HOSTED=1`, which enforces all of the above. The UI hides the repo module and the lab automatically.

## Pick a route

| Route | What you get | Billing | GitHub connected |
|---|---|---|---|
| **A. Hosting only (static)** | UI visible: incidents, kill chains, every check + fix, CSP builder. Scanning disabled (shown as "run locally"). | **Free** (Spark plan) | Yes — pushes auto-deploy |
| **B. Hosting + Cloud Run (full)** | Everything, including the web/chain scanners. | Blaze (pay-as-you-go) | Yes — manual or on push |
| **C. App Hosting (console button)** | Full app except the web scanner (no Chromium in App Hosting). | Blaze | Yes — console "Connect to GitHub" |

If you just want it visible with no billing, use **Route A**. For working web scans, use **Route B**.

---

## Route A — Hosting only, free, scans disabled

The UI ships with the knowledge base baked in, so it works with no backend. One-time keyless setup, then every push deploys the UI for free.

```bash
# one time, with your own login:
gcloud auth login
./scripts/setup-github-deploy.sh      # creates the keyless GitHub->Firebase link (no billing used for hosting)

# then: push to main, or run the "hosting" workflow in the Actions tab.
```

That runs `.github/workflows/firebase-hosting-only.yml`, which builds the static UI and deploys it with `firebase.json` (default) (no Cloud Run). Live at `https://lockguard-9b9b2.web.app`.

Prefer zero GitHub setup? Deploy it straight from your machine, also free:

```bash
npm ci && npm run build
npm install -g firebase-tools && firebase login
firebase deploy --only hosting --project lockguard-9b9b2
```

---

## Route C — App Hosting (console "Connect to GitHub")

App Hosting connects your repo through the Firebase console and redeploys on every push. `apphosting.yaml` in the repo root configures it (sets `LOCKGUARD_HOSTED=1`). **Note:** App Hosting's runtime has no Chromium, so the web scanner is unavailable on this route; the chain scanner and Harden tools work. It needs the Blaze plan.

Steps:
1. Firebase console → **Build → App Hosting** → **Get started**.
2. **Connect to GitHub**, authorize the Firebase GitHub app, and select `Yathish27/Lockguard`.
3. Live branch **main**, root directory **/** (the repo root). App Hosting picks up `apphosting.yaml`.
4. Choose a region, name the backend, and create (this is where it asks you to be on the Blaze plan).
5. It builds and deploys; every later push to `main` redeploys automatically.

---

## Route B — Hosting + Cloud Run (full app)

## Architecture

- **Firebase Hosting** serves the static UI (`packages/server/ui-dist`) from the CDN.
- **Cloud Run** runs the Express API in a container that includes Chromium (for the web scanner).
- Hosting rewrites `/api/**` to the Cloud Run service, so the browser only ever talks to one origin (no CORS).

```
 Browser ──▶ Firebase Hosting (static UI, CDN)
                 │  /api/**  (rewrite)
                 ▼
            Cloud Run: lockguard-api  (Express + Chromium, LOCKGUARD_HOSTED=1)
```

## Prerequisites (one time)

Cloud Run and Cloud Build need the project on the **Blaze (pay-as-you-go) plan** with a billing account attached. Upgrade it in the [Firebase console](https://console.firebase.google.com/project/lockguard-9b9b2/usage/details) under Usage and billing. Hosting stays free; Cloud Run bills per use (one small always-on instance is a few dollars a month — set `--min-instances 0` to pay only per request).

```bash
npm install -g firebase-tools
firebase login                       # your Google account
gcloud auth login                    # same account
gcloud config set project lockguard-9b9b2
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com
```

### Connect GitHub and auto-deploy

Instead of deploying by hand, let GitHub deploy on every push. This uses **Workload Identity Federation**, so there is **no service-account key stored in GitHub** — the keyless approach Lockguard's own repo scanner recommends (rule R3).

**One time**, with your own gcloud login:

```bash
gcloud auth login
./scripts/setup-github-deploy.sh
```

That script enables the APIs, creates a `lockguard-deployer` service account with the deploy roles, and wires GitHub OIDC so only the `Yathish27/Lockguard` repo can impersonate it. The provider path and service-account email it prints are already hard-wired into `.github/workflows/firebase-deploy.yml`.

**After that**, run the **deploy-full** workflow from the Actions tab (it is manual, since it needs billing). It builds the UI, deploys the API to Cloud Run, and deploys the UI to Firebase Hosting. No secrets are stored.

> The workflow's action references use version tags so it runs out of the box. Pin them to commit SHAs before you rely on it — with Lockguard itself: **Harden → Pin GitHub Actions**.

### Deploy by hand

From the repository root:

```bash
# 1. Build the UI that Firebase Hosting will serve
npm ci
npm run build

# 2. Deploy the API to Cloud Run (Cloud Build reads the Dockerfile).
#    Single warm instance so the in-memory scan jobs survive polling; 2 GiB for Chromium.
gcloud run deploy lockguard-api \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --memory 2Gi --cpu 2 \
  --min-instances 1 --max-instances 1 \
  --no-cpu-throttling \
  --timeout 300 \
  --set-env-vars LOCKGUARD_HOSTED=1

# 3. Deploy the static UI + the /api rewrite
firebase deploy --only hosting --config firebase.full.json
```

Firebase prints the live URL (`https://lockguard-9b9b2.web.app`). Open it; the web scan, chain scan and Harden tools work, and the UI shows a note that repo scanning and the lab run in the local app.

Or run all three steps with:

```bash
./scripts/deploy-firebase.sh
```

## Why the Cloud Run flags matter

- `--memory 2Gi --cpu 2` — headless Chromium needs the headroom.
- `--min-instances 1 --max-instances 1` — scans run as in-memory jobs you poll for progress. One instance keeps every job on the same server; more than one would route a poll to an instance that never ran the job.
- `--no-cpu-throttling` — a scan keeps working after the initial HTTP response returns; without this, Cloud Run would throttle the background work.
- `--timeout 300` — comfortably longer than a scan.

Cost note: `--min-instances 1` keeps one small instance warm. Set `--min-instances 0` to scale to zero (cheaper, but the first scan after idle waits for a cold start and a page reload during a cold start can miss an in-flight job).

## Custom domain

```bash
firebase hosting:sites:list
firebase hosting:channel:deploy preview   # a shareable preview URL
```

Add a custom domain in the Firebase console under Hosting.

## Updating

Re-run the three deploy steps (or the script). Hosting and Cloud Run both update in place.
