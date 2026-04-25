# install.ps1 — Windows installer for driftwatch-agent
# Run as Administrator

param(
    [string]$InstallDir = "C:\Program Files\Driftwatch\Agent",
    [string]$BinaryPath = "$PSScriptRoot\driftwatch-agent.exe"
)

$ErrorActionPreference = "Stop"
$ServiceName = "DriftwatchAgent"
$ServiceDisplayName = "Driftwatch Risk Scoring Agent"
$ServiceDescription = "Continuously computes a composite Device Risk Score and emits events to the risk engine."

Write-Host "Installing $ServiceDisplayName..."

# Create install directory
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir | Out-Null
}

# Copy binary
Copy-Item -Path $BinaryPath -Destination "$InstallDir\driftwatch-agent.exe" -Force

# Copy default config
$ConfigDir = "$InstallDir\config"
if (-not (Test-Path $ConfigDir)) {
    New-Item -ItemType Directory -Path $ConfigDir | Out-Null
}
$ConfigSource = Join-Path $PSScriptRoot "..\config\default.toml"
if (Test-Path $ConfigSource) {
    Copy-Item -Path $ConfigSource -Destination "$ConfigDir\default.toml" -Force
}

# Register Windows Service
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "Stopping existing service..."
    Stop-Service -Name $ServiceName -Force
    Remove-Service -Name $ServiceName
}

New-Service `
    -Name $ServiceName `
    -DisplayName $ServiceDisplayName `
    -Description $ServiceDescription `
    -BinaryPathName "`"$InstallDir\driftwatch-agent.exe`"" `
    -StartupType Automatic `
    -ErrorControl Normal

Write-Host "Starting $ServiceName..."
Start-Service -Name $ServiceName

Write-Host "Installation complete."
Write-Host "Service status: $((Get-Service -Name $ServiceName).Status)"
