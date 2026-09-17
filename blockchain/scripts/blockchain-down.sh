#!/usr/bin/env bash
# Stops the Fabric network and gateway sidecar without deleting crypto
# material or chain data (use blockchain-reset.sh for a full wipe).
set -euo pipefail
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"
cd "$(dirname "$0")"

if [ -f /tmp/fabric-gateway-service.pid ]; then
  kill "$(cat /tmp/fabric-gateway-service.pid)" 2>/dev/null || true
  rm -f /tmp/fabric-gateway-service.pid
fi

cd ../network
docker compose -f docker-compose.yaml down
echo "Fabric network stopped. Ledger data and crypto material preserved."
