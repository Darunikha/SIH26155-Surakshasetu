$ErrorActionPreference = "SilentlyContinue"
if (Test-Path "$env:TEMP\fabric-gateway-service.pid") {
    $procId = Get-Content "$env:TEMP\fabric-gateway-service.pid"
    Stop-Process -Id $procId -Force
    Remove-Item "$env:TEMP\fabric-gateway-service.pid"
}

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $ScriptDir "..\network")
docker compose -f docker-compose.yaml down
Write-Host "Fabric network stopped. Ledger data and crypto material preserved."
