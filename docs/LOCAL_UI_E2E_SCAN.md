# Run End-to-End Scan From Dedicated UI

This guide runs the new `ui/` app with the control plane, worker, and PostgreSQL locally.

## Prerequisites

- Docker Desktop (for PostgreSQL)
- Go (for control-plane API/scheduler)
- Rust + Cargo (for worker runtime)
- Node.js 20+ + npm (for dedicated UI)
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

## Use the Dedicated UI

- Open `http://localhost:5173`
- Token: `uss-local-admin-token`
- Go to **Operations** and create a scan job:
  - target_kind: `repo`
  - target: local repo path or allowed target
  - profile: `balanced`
  - tools: `semgrep,gitleaks,trivy`
- Go to **Reports** to load server summary and export findings via:
  - `/v1/reports/summary`
  - `/v1/reports/findings/export?format=json|csv`

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

## When You Can Run End-to-End

You can run end-to-end as soon as all prerequisites are installed and the 4 services are up.

Typical setup time on a fresh machine:
- install Node.js + npm: 5-10 minutes
- `npm install` in `ui/`: 1-3 minutes
- start stack: 1-2 minutes

Estimated total: **~10-15 minutes** from a fresh environment.

If Node/npm is already installed: **~2-5 minutes**.
