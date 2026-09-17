$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $ScriptDir "..\gateway-service")

$NetworkDir = Resolve-Path (Join-Path $ScriptDir "..\network")
$Org1Dir = Join-Path $NetworkDir "crypto-config\peerOrganizations\org1.securityaudit.com"

$env:PEER_ENDPOINT = "localhost:7051"
$env:PEER_HOST_ALIAS = "peer0.org1.securityaudit.com"
$env:MSP_ID = "Org1MSP"
$env:CERT_PATH = Join-Path $Org1Dir "users\Admin@org1.securityaudit.com\msp\signcerts\Admin@org1.securityaudit.com-cert.pem"
$env:KEY_DIRECTORY_PATH = Join-Path $Org1Dir "users\Admin@org1.securityaudit.com\msp\keystore"
$env:TLS_CERT_PATH = Join-Path $Org1Dir "peers\peer0.org1.securityaudit.com\tls\ca.crt"
$env:CHANNEL_NAME = "securityaudit"
$env:CHAINCODE_NAME = "security-audit-chaincode"
$env:PORT = "4001"

if (-not (Test-Path "dist\index.js")) {
    npm run build
}

Write-Host "Starting Fabric gateway sidecar on port $($env:PORT) ..."
Start-Process -FilePath "node" -ArgumentList "dist/index.js" -RedirectStandardOutput "$env:TEMP\fabric-gateway-service.log" -RedirectStandardError "$env:TEMP\fabric-gateway-service.err.log" -PassThru | ForEach-Object { $_.Id | Out-File "$env:TEMP\fabric-gateway-service.pid" }
Start-Sleep -Seconds 2
try {
    Invoke-RestMethod -Uri "http://localhost:$($env:PORT)/health" -TimeoutSec 5
} catch {
    Write-Host "Gateway sidecar not yet healthy -- check $env:TEMP\fabric-gateway-service.err.log"
}
