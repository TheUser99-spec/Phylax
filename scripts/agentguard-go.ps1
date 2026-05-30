param(
    [string]$Workspace = "C:\Users\omkde\AgentGuard"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$doctor = Join-Path $PSScriptRoot "agentguard-doctor.ps1"
if (-not (Test-Path $doctor)) {
    Write-Error "agentguard-doctor.ps1 not found at $doctor"
    exit 2
}

Write-Host "AgentGuard GO/NO-GO gate"
Write-Host "Workspace: $Workspace"
Write-Host ""

& powershell -NoProfile -ExecutionPolicy Bypass -File $doctor -Workspace $Workspace
$code = $LASTEXITCODE

if ($code -ne 0) {
    Write-Host ""
    Write-Host "NO-GO: AgentGuard doctor reported failing checks." -ForegroundColor Red
    Write-Host "Fix failures before running AI agents."
    exit $code
}

Write-Host ""
Write-Host "GO: AgentGuard checks passed." -ForegroundColor Green
exit 0

