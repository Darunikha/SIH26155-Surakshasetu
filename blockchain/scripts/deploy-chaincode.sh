#!/usr/bin/env bash
# Packages, installs, approves, and commits security-audit-chaincode onto
# the "securityaudit" channel (spec section 28-29). Idempotent: safe to
# re-run after the chaincode source changes (bumps CC_SEQUENCE manually if
# you need to upgrade running code -- see blockchain/README.md).
set -euo pipefail
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

CC_NAME="security-audit-chaincode"
CC_VERSION="1.0"
CC_SEQUENCE="1"
CC_LABEL="${CC_NAME}_${CC_VERSION}"

docker exec cli.securityaudit.com bash -c "
  set -e
  cd /opt/gopath/src/github.com/hyperledger/fabric/peer
  peer lifecycle chaincode package ${CC_LABEL}.tar.gz \
    --path ./chaincode --lang node --label ${CC_LABEL}

  peer lifecycle chaincode install ${CC_LABEL}.tar.gz

  PACKAGE_ID=\$(peer lifecycle chaincode queryinstalled | grep ${CC_LABEL} | sed -n 's/^Package ID: \(.*\), Label:.*\$/\1/p')
  echo \"Installed package ID: \$PACKAGE_ID\"

  peer lifecycle chaincode approveformyorg -o orderer.securityaudit.com:7050 \
    --tls --cafile \"\$ORDERER_CA\" --channelID securityaudit --name ${CC_NAME} \
    --version ${CC_VERSION} --package-id \$PACKAGE_ID --sequence ${CC_SEQUENCE}

  peer lifecycle chaincode checkcommitreadiness --channelID securityaudit --name ${CC_NAME} \
    --version ${CC_VERSION} --sequence ${CC_SEQUENCE} --tls --cafile \"\$ORDERER_CA\" --output json

  peer lifecycle chaincode commit -o orderer.securityaudit.com:7050 \
    --tls --cafile \"\$ORDERER_CA\" --channelID securityaudit --name ${CC_NAME} \
    --version ${CC_VERSION} --sequence ${CC_SEQUENCE} \
    --peerAddresses peer0.org1.securityaudit.com:7051 --tlsRootCertFiles \"\$CORE_PEER_TLS_ROOTCERT_FILE\"

  echo 'Chaincode committed. Querying committed chaincode list:'
  peer lifecycle chaincode querycommitted --channelID securityaudit
"
