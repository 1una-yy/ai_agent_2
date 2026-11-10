# Obtain Hermes Agent for governed testing on native Windows (ticket §9B).
# Does NOT pipe-execute. Downloads, hashes, and stops for human review.
# Prefer WSL2 + install-hermes-linux-wsl.sh for the Docker Compose PoC.

param([ValidateSet("review","run-installer")] [string]$Mode = "review")

$ErrorActionPreference = "Stop"
$Dest = Join-Path $PSScriptRoot "_download"
$InstallerUrl = "https://hermes-agent.nousresearch.com/install.ps1"
New-Item -ItemType Directory -Force -Path $Dest | Out-Null

function Record-Env {
  @(
    "date_utc=$([DateTime]::UtcNow.ToString('s'))Z"
    "os=$([System.Environment]::OSVersion.VersionString)"
    "git=$(git --version 2>$null)"
    "docker=$(docker --version 2>$null)"
    "python=$(python --version 2>$null)"
  ) | Tee-Object -FilePath (Join-Path $Dest "environment.txt")
}

if ($Mode -eq "review") {
  Record-Env
  Write-Host "[*] downloading installer (NOT executing)..."
  Invoke-WebRequest -Uri $InstallerUrl -OutFile (Join-Path $Dest "install.ps1")
  $h = Get-FileHash -Algorithm SHA256 (Join-Path $Dest "install.ps1")
  $h.Hash | Tee-Object -FilePath (Join-Path $Dest "install.ps1.sha256")
  Write-Host "`nReview $Dest\install.ps1, record the SHA-256 in docs/, then run:`n  .\install-hermes-windows.ps1 -Mode run-installer"
}
elseif ($Mode -eq "run-installer") {
  $f = Join-Path $Dest "install.ps1"
  if (-not (Test-Path $f)) { throw "run -Mode review first" }
  Write-Host "[*] recorded hash:"; Get-Content (Join-Path $Dest "install.ps1.sha256")
  if ((Read-Host "Proceed to execute this reviewed installer? [y/N]") -ne "y") { throw "aborted" }
  & powershell -ExecutionPolicy Bypass -File $f
  hermes --version
  hermes --help | Select-Object -First 40
}
