# AgentGuard Windows Installer
# Run: powershell -ExecutionPolicy Bypass -File install.ps1
param(
    [string]$Version = "0.1.1",
    [switch]$SkipPath = $false
)

$ErrorActionPreference = "Stop"
$InstallDir = "$env:LOCALAPPDATA\AgentGuard"
$BinDir = "$InstallDir\bin"
$Repo = "TheUser99-spec/AgentGuard"

Write-Host "=== AgentGuard Installer v$Version ===" -ForegroundColor Cyan
Write-Host ""

# Create directories
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
New-Item -ItemType Directory -Force -Path "$InstallDir\data" | Out-Null

# Download binaries
Write-Host "[1/3] Downloading agentguard.exe..." -ForegroundColor Yellow
$ExeUrl = "https://github.com/$Repo/releases/download/v$Version/agentguard.exe"
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $ExeUrl -OutFile "$BinDir\agentguard.exe" -UserAgent "agentguard-installer"
} catch {
    # If GitHub release not available yet, build from source hint
    Write-Host "  Release not found on GitHub. If developing locally, build with:" -ForegroundColor DarkYellow
    Write-Host "    cargo build -p agentguard-cli --release" -ForegroundColor DarkYellow
    Write-Host "    cargo build -p agentguard-daemon --release" -ForegroundColor DarkYellow
    Write-Host "  Then copy target/release/agentguard.exe to $BinDir" -ForegroundColor DarkYellow
    # Don't fail - continue for dev installs
}

Write-Host "[2/3] Downloading agentguard-daemon.exe..." -ForegroundColor Yellow
$DaemonUrl = "https://github.com/$Repo/releases/download/v$Version/agentguard-daemon.exe"
try {
    Invoke-WebRequest -Uri $DaemonUrl -OutFile "$BinDir\agentguard-daemon.exe" -UserAgent "agentguard-installer"
} catch {
    Write-Host "  Daemon binary not available from release. Local build required." -ForegroundColor DarkYellow
}

# Add to PATH
if (-not $SkipPath) {
    Write-Host "[3/3] Adding to PATH..." -ForegroundColor Yellow
    $CurrentPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($CurrentPath -notlike "*$BinDir*") {
        [Environment]::SetEnvironmentVariable("Path", "$CurrentPath;$BinDir", "User")
        $env:Path = "$env:Path;$BinDir"
        Write-Host "  Added $BinDir to user PATH" -ForegroundColor Green
    } else {
        Write-Host "  PATH already configured" -ForegroundColor Green
    }
} else {
    Write-Host "[3/3] Skipped PATH (--SkipPath)" -ForegroundColor DarkYellow
}

Write-Host ""
Write-Host "=== Installation complete! ===" -ForegroundColor Green
Write-Host ""
Write-Host "  Quick start:" -ForegroundColor White
Write-Host "    agentguard init          Create agentguard.toml + register project"
Write-Host "    agentguard run           Start daemon + open dashboard"
Write-Host "    agentguard status        Show live status"
Write-Host "    agentguard update        Check for updates"
Write-Host ""
Write-Host "  Installed to: $BinDir" -ForegroundColor DarkGray
Write-Host "  Database at: $env:APPDATA\AgentGuard\agentguard.db" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Restart your terminal or run: refreshenv" -ForegroundColor Yellow
