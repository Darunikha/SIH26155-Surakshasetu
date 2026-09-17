#!/usr/bin/env bash
# Full wipe: stops the network, removes generated crypto material, channel
# artifacts, and chain data volumes. Next blockchain-up.sh starts a
# completely fresh ledger.
set -euo pipefail
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"
cd "$(dirname "$0")"

if [ -f /tmp/fabric-gateway-service.pid ]; then
  kill "$(cat /tmp/fabric-gateway-service.pid)" 2>/dev/null || true
  rm -f /tmp/fabric-gateway-service.pid
fi

cd ../network
docker compose -f docker-compose.yaml down -v
rm -rf crypto-config channel-artifacts
echo "Fabric network fully reset. Run blockchain-up.sh to rebuild from scratch."
