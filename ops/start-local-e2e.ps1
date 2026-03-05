param(
    [switch]$SkipUI,
    [switch]$UseDockerUI,
    [switch]$SkipScheduler,
    [string]$WorkerID = "worker-local",
    [string]$WorkerSharedSecret = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-CommandAvailable {
    param([string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$composeFile = Join-Path $repoRoot "ops\docker-compose.postgres.yml"
$uiComposeFile = Join-Path $repoRoot "ops\docker-compose.ui.yml"

if (-not (Test-Path $composeFile)) {
    throw "docker compose file not found: $composeFile"
}
if (-not (Test-Path $uiComposeFile)) {
    throw "ui docker compose file not found: $uiComposeFile"
}

if (-not (Test-CommandAvailable "docker")) {
    throw "docker is required to start local postgres"
}
if (-not (Test-CommandAvailable "go")) {
    throw "go is required to run control-plane services"
}
if (-not (Test-CommandAvailable "cargo")) {
    throw "cargo is required to run worker runtime"
}

Write-Host "Starting local postgres..."
docker compose -f $composeFile up -d | Out-Null

$controlPlaneDir = Join-Path $repoRoot "control-plane"
$workerDir = Join-Path $repoRoot "worker-runtime\crates\uss-worker"
$uiDir = Join-Path $repoRoot "ui"

$apiCommand = "Set-Location '$controlPlaneDir'; go run ./cmd/api"
$schedulerCommand = "Set-Location '$controlPlaneDir'; go run ./cmd/scheduler"

$workerCommand = "Set-Location '$workerDir'; " +
    "`$env:USS_WORKER_DAEMON='true'; " +
    "`$env:USS_WORKER_ID='$WorkerID'; " +
    (if ([string]::IsNullOrWhiteSpace($WorkerSharedSecret)) { "" } else { "`$env:USS_WORKER_SHARED_SECRET='$WorkerSharedSecret'; " }) +
    "cargo run --release"

Start-Process powershell -ArgumentList "-NoExit", "-Command", $apiCommand | Out-Null

if (-not $SkipScheduler) {
    Start-Process powershell -ArgumentList "-NoExit", "-Command", $schedulerCommand | Out-Null
}

Start-Process powershell -ArgumentList "-NoExit", "-Command", $workerCommand | Out-Null

if (-not $SkipUI) {
    if ($UseDockerUI) {
        Write-Host "Starting dedicated UI in Docker..."
        $env:VITE_CONTROL_PLANE_PROXY = "http://host.docker.internal:8080"
        docker compose -f $uiComposeFile up -d ui-dev | Out-Null
    } elseif (Test-CommandAvailable "npm") {
        $uiCommand = "Set-Location '$uiDir'; if (-not (Test-Path node_modules)) { npm install }; npm run dev"
        Start-Process powershell -ArgumentList "-NoExit", "-Command", $uiCommand | Out-Null
    } else {
        Write-Warning "npm not found, starting UI in Docker instead."
        $env:VITE_CONTROL_PLANE_PROXY = "http://host.docker.internal:8080"
        docker compose -f $uiComposeFile up -d ui-dev | Out-Null
    }
}

Write-Host ""
Write-Host "Local E2E stack start requested."
Write-Host "Control Plane API: http://localhost:8080"
Write-Host "Dedicated UI: http://localhost:5173"
Write-Host "Fallback embedded UI: http://localhost:8080/app/"
Write-Host "Default bootstrap token: uss-local-admin-token"
Write-Host ""
Write-Host "After services are up, create a scan job from the UI Operations view."
