#!/usr/bin/env bash
# Brings up the real local Hyperledger Fabric network (spec section 28):
# generates crypto material + channel artifacts if missing, starts
# orderer/peer via docker-compose, creates + joins the "securityaudit"
# channel, then packages/installs/approves/commits the chaincode and
# starts the gateway sidecar.
set -euo pipefail
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"
cd "$(dirname "$0")/../network"

FABRIC_TOOLS_IMAGE="hyperledger/fabric-tools:2.5"

echo "== [1/6] Crypto material =="
if [ ! -d "crypto-config" ]; then
  docker run --rm -v "$(pwd)":/network -w /network "$FABRIC_TOOLS_IMAGE" \
    cryptogen generate --config=/network/crypto-config.yaml --output=/network/crypto-config
else
  echo "crypto-config already exists, skipping cryptogen"
fi

echo "== [2/6] Channel artifacts =="
mkdir -p channel-artifacts
if [ ! -f "channel-artifacts/genesis.block" ]; then
  docker run --rm -v "$(pwd)":/network -w /network -e FABRIC_CFG_PATH=/network "$FABRIC_TOOLS_IMAGE" \
    configtxgen -profile SecurityAuditOrdererGenesis -channelID system-channel -outputBlock /network/channel-artifacts/genesis.block
fi
if [ ! -f "channel-artifacts/securityaudit.tx" ]; then
  docker run --rm -v "$(pwd)":/network -w /network -e FABRIC_CFG_PATH=/network "$FABRIC_TOOLS_IMAGE" \
    configtxgen -profile SecurityAuditChannel -outputCreateChannelTx /network/channel-artifacts/securityaudit.tx -channelID securityaudit
fi

echo "== [3/6] docker compose up =="
docker compose -f docker-compose.yaml up -d
echo "Waiting for peer/orderer to be ready..."
sleep 10

echo "== [4/6] Create + join channel 'securityaudit' =="
docker exec cli.securityaudit.com bash -c '
  set -e
  if ! peer channel getinfo -c securityaudit >/dev/null 2>&1; then
    peer channel create -o orderer.securityaudit.com:7050 -c securityaudit \
      -f /channel-artifacts/securityaudit.tx --outputBlock /channel-artifacts/securityaudit.block \
      --tls --cafile "$ORDERER_CA"
    peer channel join -b /channel-artifacts/securityaudit.block
  else
    echo "Channel already joined"
  fi
'

echo "== [5/6] Deploy chaincode =="
bash "$(dirname "$0")/deploy-chaincode.sh"

echo "== [6/6] Start Fabric gateway sidecar =="
bash "$(dirname "$0")/gateway-up.sh"

echo "Fabric network is up. Channel: securityaudit. Chaincode: security-audit-chaincode."
