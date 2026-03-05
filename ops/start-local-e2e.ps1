param(
    [switch]$SkipUI,
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

if (-not (Test-Path $composeFile)) {
    throw "docker compose file not found: $composeFile"
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
    if (Test-CommandAvailable "npm") {
        $uiCommand = "Set-Location '$uiDir'; if (-not (Test-Path node_modules)) { npm install }; npm run dev"
        Start-Process powershell -ArgumentList "-NoExit", "-Command", $uiCommand | Out-Null
    } else {
        Write-Warning "npm not found, skipping UI startup. Install Node.js 20+ to run dedicated ui/."
    }
}

Write-Host ""
Write-Host "Local E2E stack start requested."
Write-Host "Control Plane API: http://localhost:8080"
Write-Host "Dedicated UI (when npm is installed): http://localhost:5173"
Write-Host "Fallback embedded UI: http://localhost:8080/app/"
Write-Host "Default bootstrap token: uss-local-admin-token"
Write-Host ""
Write-Host "After services are up, create a scan job from the UI Operations view."

