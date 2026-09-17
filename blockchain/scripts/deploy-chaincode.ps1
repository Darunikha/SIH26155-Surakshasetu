$ErrorActionPreference = "Stop"

$CcName = "security-audit-chaincode"
$CcVersion = "1.0"
$CcSequence = "1"
$CcLabel = "${CcName}_${CcVersion}"

$deployScript = @"
set -e
cd /opt/gopath/src/github.com/hyperledger/fabric/peer
peer lifecycle chaincode package ${CcLabel}.tar.gz --path ./chaincode --lang node --label ${CcLabel}
peer lifecycle chaincode install ${CcLabel}.tar.gz
PACKAGE_ID=\`$(peer lifecycle chaincode queryinstalled | grep ${CcLabel} | sed -n 's/^Package ID: \(.*\), Label:.*\`$/\1/p')
echo "Installed package ID: \`$PACKAGE_ID"
peer lifecycle chaincode approveformyorg -o orderer.securityaudit.com:7050 --tls --cafile "\`$ORDERER_CA" --channelID securityaudit --name ${CcName} --version ${CcVersion} --package-id \`$PACKAGE_ID --sequence ${CcSequence}
peer lifecycle chaincode checkcommitreadiness --channelID securityaudit --name ${CcName} --version ${CcVersion} --sequence ${CcSequence} --tls --cafile "\`$ORDERER_CA" --output json
peer lifecycle chaincode commit -o orderer.securityaudit.com:7050 --tls --cafile "\`$ORDERER_CA" --channelID securityaudit --name ${CcName} --version ${CcVersion} --sequence ${CcSequence} --peerAddresses peer0.org1.securityaudit.com:7051 --tlsRootCertFiles "\`$CORE_PEER_TLS_ROOTCERT_FILE"
echo 'Chaincode committed.'
peer lifecycle chaincode querycommitted --channelID securityaudit
"@

docker exec cli.securityaudit.com bash -c $deployScript
