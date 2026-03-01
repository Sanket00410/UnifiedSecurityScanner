$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$workerRoot = Join-Path $repoRoot "worker-runtime\crates\uss-worker"
$msvcRoot = "C:\BuildTools\VC\Tools\MSVC"
$sdkRoot = "C:\Program Files (x86)\Windows Kits\10"

if (-not (Test-Path $msvcRoot)) {
    throw "MSVC tools not found at $msvcRoot"
}

if (-not (Test-Path (Join-Path $sdkRoot "Lib"))) {
    throw "Windows SDK not found at $sdkRoot"
}

$msvcVersion = Get-ChildItem $msvcRoot -Directory | Sort-Object Name -Descending | Select-Object -First 1
$sdkVersion = Get-ChildItem (Join-Path $sdkRoot "Lib") -Directory | Sort-Object Name -Descending | Select-Object -First 1

if (-not $msvcVersion) {
    throw "No MSVC toolset version found."
}

if (-not $sdkVersion) {
    throw "No Windows SDK version found."
}

$msvc = $msvcVersion.FullName
$sdk = $sdkRoot
$sdkVer = $sdkVersion.Name

$env:Path = "$msvc\bin\Hostx64\x64;$sdk\bin\$sdkVer\x64;$env:USERPROFILE\.cargo\bin;$env:Path"
$env:INCLUDE = "$msvc\include;$sdk\Include\$sdkVer\ucrt;$sdk\Include\$sdkVer\shared;$sdk\Include\$sdkVer\um;$sdk\Include\$sdkVer\winrt;$sdk\Include\$sdkVer\cppwinrt"
$env:LIB = "$msvc\lib\x64;$sdk\Lib\$sdkVer\ucrt\x64;$sdk\Lib\$sdkVer\um\x64"

Push-Location $workerRoot
try {
    cargo test @args
}
finally {
    Pop-Location
}
