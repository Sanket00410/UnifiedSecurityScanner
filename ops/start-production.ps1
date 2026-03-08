param(
    [switch]$WithObservability,
    [switch]$Rebuild,
    [switch]$Down,
    [switch]$Clean
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-PortAvailable {
    param([int]$Port)

    $getNetTcp = Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue
    if ($null -ne $getNetTcp) {
        try {
            $inUse = Get-NetTCPConnection -LocalPort $Port -ErrorAction Stop | Select-Object -First 1
            if ($null -ne $inUse) {
                return $false
            }
        } catch {
            # Ignore and fall back to socket bind check.
        }
    }

    try {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $Port)
        $listener.Start()
        $listener.Stop()
        return $true
    } catch {
        return $false
    }
}

function Get-FreePortStartingAt {
    param([int]$StartPort)
    for ($port = $StartPort; $port -lt ($StartPort + 200); $port++) {
        if (Test-PortAvailable -Port $port) {
            return $port
        }
    }
    throw "no free port found near $StartPort"
}

function Ensure-PortEnv {
    param(
        [string]$EnvName,
        [int]$DefaultPort
    )

    $current = [Environment]::GetEnvironmentVariable($EnvName, "Process")
    if ($null -ne $current -and $current.Trim().Length -gt 0) {
        return [int]$current
    }

    if (Test-PortAvailable -Port $DefaultPort) {
        [Environment]::SetEnvironmentVariable($EnvName, "$DefaultPort", "Process")
        return $DefaultPort
    }

    $fallback = Get-FreePortStartingAt -StartPort ($DefaultPort + 1)
    [Environment]::SetEnvironmentVariable($EnvName, "$fallback", "Process")
    Write-Warning "$EnvName default port $DefaultPort is busy, using $fallback for this run."
    return $fallback
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$composeFile = Join-Path $repoRoot "ops\production\docker-compose.yml"
if (-not (Test-Path $composeFile)) {
    throw "production compose file not found: $composeFile"
}

Ensure-PortEnv "USS_POSTGRES_PORT" 5432 | Out-Null
Ensure-PortEnv "USS_API_PORT" 8080 | Out-Null
Ensure-PortEnv "USS_GRPC_PORT" 9090 | Out-Null
Ensure-PortEnv "USS_RISK_ENGINE_PORT" 18110 | Out-Null
Ensure-PortEnv "USS_PLATFORM_SERVICES_PORT" 18090 | Out-Null
Ensure-PortEnv "USS_UI_PORT" 5180 | Out-Null
Ensure-PortEnv "USS_PROMETHEUS_PORT" 9091 | Out-Null
Ensure-PortEnv "USS_GRAFANA_PORT" 3000 | Out-Null
Ensure-PortEnv "USS_BLACKBOX_PORT" 9115 | Out-Null

$composeArgs = @("-f", $composeFile)
if ($WithObservability) {
    $composeArgs += @("--profile", "observability")
}

if ($Down) {
    if ($Clean) {
        docker compose @composeArgs down -v
    } else {
        docker compose @composeArgs down
    }
    exit $LASTEXITCODE
}

$upArgs = @("up", "-d")
if ($Rebuild) {
    $upArgs += "--build"
}

docker compose @composeArgs @upArgs
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "Unified Security Scanner started (production compose)."
Write-Host "UI:                 http://localhost:$([Environment]::GetEnvironmentVariable('USS_UI_PORT','Process'))"
Write-Host "Control Plane API:  http://localhost:$([Environment]::GetEnvironmentVariable('USS_API_PORT','Process'))"
Write-Host "Platform Services:  http://localhost:$([Environment]::GetEnvironmentVariable('USS_PLATFORM_SERVICES_PORT','Process'))"
Write-Host "Risk Engine API:    http://localhost:$([Environment]::GetEnvironmentVariable('USS_RISK_ENGINE_PORT','Process'))"
if ($WithObservability) {
    Write-Host "Prometheus:         http://localhost:$([Environment]::GetEnvironmentVariable('USS_PROMETHEUS_PORT','Process'))"
    Write-Host "Grafana:            http://localhost:$([Environment]::GetEnvironmentVariable('USS_GRAFANA_PORT','Process'))"
}
$bootstrapToken = [Environment]::GetEnvironmentVariable("USS_BOOTSTRAP_ADMIN_TOKEN", "Process")
if ([string]::IsNullOrWhiteSpace($bootstrapToken)) {
    $bootstrapToken = "uss-local-admin-token"
}
Write-Host "Bootstrap token:    $bootstrapToken"
Write-Host ""
