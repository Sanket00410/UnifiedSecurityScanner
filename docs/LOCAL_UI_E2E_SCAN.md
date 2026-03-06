# Run End-to-End Scan From Dedicated UI

This guide runs the new `ui/` app with the control plane, worker, and PostgreSQL locally.

## Prerequisites

- Docker Desktop (for PostgreSQL)
- Go (for control-plane API/scheduler)
- Rust + Cargo (for worker runtime)
- Node.js 20+ + npm (for dedicated UI local dev) or Docker UI mode
- At least one scanner binary available in PATH for real scan execution:
  - recommended first path: `semgrep`, `gitleaks`, `trivy`

## Fast Start (PowerShell)

From repo root:

```powershell
.\ops\start-local-e2e.ps1
```

This starts:
- PostgreSQL
- Control-plane API (`:8080`)
- Scheduler
- Worker runtime (daemon mode)
- Dedicated UI (`:5173`) if npm is installed

To force Docker-based UI startup (no local npm required):

```powershell
.\ops\start-local-e2e.ps1 -UseDockerUI
```

## Manual Start (if preferred)

```powershell
# 1) postgres
docker compose -f .\ops\docker-compose.postgres.yml up -d

# 2) api
cd .\control-plane
go run .\cmd\api

# 3) scheduler (second shell)
cd .\control-plane
go run .\cmd\scheduler

# 4) worker (third shell)
cd .\worker-runtime\crates\uss-worker
$env:USS_WORKER_DAEMON="true"
cargo run --release

# 5) dedicated ui (fourth shell)
cd .\ui
copy .env.example .env
npm install
npm run dev
```

## Serve Built UI From Control Plane (Primary UI Path)

If you want control-plane to serve dedicated UI as primary (`/ui/`), build UI and set `USS_UI_DIST_PATH`:

```powershell
cd .\ui
npm install
npm run build

cd ..\control-plane
$env:USS_UI_DIST_PATH = "..\ui\dist"
go run .\cmd\api
```

Then opening `http://localhost:8080/` redirects to `/ui/`.

## Use the Dedicated UI (Guided Scan Flow)

- Open `http://localhost:5173`
- Token: `uss-local-admin-token`
- Go to **Operations**:
  - use **Guided Quick Run**:
    - select a preset (optional)
    - set `target_kind` + `target`
    - start scan with one click
  - use **Save Scan Target** to store reusable targets
  - select a saved target and click **Run Selected Target** for one-click reruns
  - use **Automation Ingestion Source** to create webhook-driven scan automation:
    - create a source with provider + default target/profile/tools
    - copy the generated ingest token (shown once in UI)
    - use displayed webhook path `/ingest/webhooks/{sourceId}` in your CI/repo webhook
    - rotate token anytime with **Rotate Ingestion Token**
    - rotate signing secret anytime with **Rotate Webhook Secret**
    - monitor automation in **Ingestion Events**
- Go to **Reports** to load server summary and export findings via:
  - `/v1/reports/summary`
  - `/v1/reports/findings/export?format=json|csv`

Backend API endpoints used by the guided UI:
- `GET /v1/scan-presets`
- `GET/POST /v1/scan-targets`
- `GET/PUT/DELETE /v1/scan-targets/{id}`
- `POST /v1/scan-targets/{id}/run`
- `GET/POST /v1/ingestion/sources`
- `GET/PUT/DELETE /v1/ingestion/sources/{id}`
- `POST /v1/ingestion/sources/{id}/rotate-token`
- `POST /v1/ingestion/sources/{id}/rotate-webhook-secret`
- `GET /v1/ingestion/events`
- `POST /ingest/webhooks/{sourceId}` with `X-USS-Ingest-Token`

## Dedicated UI in Docker (standalone)

```powershell
docker compose -f .\ops\docker-compose.ui.yml up -d ui-dev
```

- UI URL: `http://localhost:5173`
- Default API proxy target inside container: `http://host.docker.internal:8080`

Production-style static container:

```powershell
docker compose -f .\ops\docker-compose.ui.yml up -d ui-prod
```

- UI URL: `http://localhost:5180`
- `/v1/*` and `/auth/*` requests are proxied to `http://host.docker.internal:8080`

## When You Can Run End-to-End

You can run end-to-end as soon as all prerequisites are installed and the 4 services are up.

Typical setup time on a fresh machine:
- Docker-only UI path: 2-6 minutes
- local Node/npm UI path: 10-15 minutes
