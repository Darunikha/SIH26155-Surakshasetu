# Brings up the real local Hyperledger Fabric network (spec section 28) on Windows.
# Mirrors blockchain-up.sh. Requires Docker Desktop with Linux containers.
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $ScriptDir "..\network")

$FabricToolsImage = "hyperledger/fabric-tools:2.5"
$Pwd = (Get-Location).Path

Write-Host "== [1/6] Crypto material =="
if (-not (Test-Path "crypto-config")) {
    docker run --rm -v "${Pwd}:/network" -w /network $FabricToolsImage `
        cryptogen generate --config=/network/crypto-config.yaml --output=/network/crypto-config
} else {
    Write-Host "crypto-config already exists, skipping cryptogen"
}

Write-Host "== [2/6] Channel artifacts =="
New-Item -ItemType Directory -Force -Path "channel-artifacts" | Out-Null
if (-not (Test-Path "channel-artifacts/genesis.block")) {
    docker run --rm -v "${Pwd}:/network" -w /network -e FABRIC_CFG_PATH=/network $FabricToolsImage `
        configtxgen -profile SecurityAuditOrdererGenesis -channelID system-channel -outputBlock /network/channel-artifacts/genesis.block
}
if (-not (Test-Path "channel-artifacts/securityaudit.tx")) {
    docker run --rm -v "${Pwd}:/network" -w /network -e FABRIC_CFG_PATH=/network $FabricToolsImage `
        configtxgen -profile SecurityAuditChannel -outputCreateChannelTx /network/channel-artifacts/securityaudit.tx -channelID securityaudit
}

Write-Host "== [3/6] docker compose up =="
docker compose -f docker-compose.yaml up -d
Write-Host "Waiting for peer/orderer to be ready..."
Start-Sleep -Seconds 10

Write-Host "== [4/6] Create + join channel 'securityaudit' =="
$joinScript = @'
set -e
if ! peer channel getinfo -c securityaudit >/dev/null 2>&1; then
  peer channel create -o orderer.securityaudit.com:7050 -c securityaudit \
    -f /channel-artifacts/securityaudit.tx --outputBlock /channel-artifacts/securityaudit.block \
    --tls --cafile "$ORDERER_CA"
  peer channel join -b /channel-artifacts/securityaudit.block
else
  echo "Channel already joined"
fi
'@
docker exec cli.securityaudit.com bash -c $joinScript

Write-Host "== [5/6] Deploy chaincode =="
& (Join-Path $ScriptDir "deploy-chaincode.ps1")

Write-Host "== [6/6] Start Fabric gateway sidecar =="
& (Join-Path $ScriptDir "gateway-up.ps1")

Write-Host "Fabric network is up. Channel: securityaudit. Chaincode: security-audit-chaincode."
