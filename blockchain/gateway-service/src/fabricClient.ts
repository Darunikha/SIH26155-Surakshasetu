import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as grpc from '@grpc/grpc-js';
import {
    connect,
    Contract,
    Gateway,
    Identity,
    signers,
} from '@hyperledger/fabric-gateway';

export interface FabricConfig {
    peerEndpoint: string;
    peerHostAlias: string;
    mspId: string;
    certPath: string;
    keyDirectoryPath: string;
    tlsCertPath: string;
    channelName: string;
    chaincodeName: string;
}

export function loadConfigFromEnv(): FabricConfig {
    const required = (name: string): string => {
        const v = process.env[name];
        if (!v) {
            throw new Error(`Missing required environment variable: ${name}`);
        }
        return v;
    };

    return {
        peerEndpoint: process.env.PEER_ENDPOINT || 'localhost:7051',
        peerHostAlias: process.env.PEER_HOST_ALIAS || 'peer0.org1.securityaudit.com',
        mspId: process.env.MSP_ID || 'Org1MSP',
        certPath: required('CERT_PATH'),
        keyDirectoryPath: required('KEY_DIRECTORY_PATH'),
        tlsCertPath: required('TLS_CERT_PATH'),
        channelName: process.env.CHANNEL_NAME || 'securityaudit',
        chaincodeName: process.env.CHAINCODE_NAME || 'security-audit-chaincode',
    };
}

function newGrpcConnection(config: FabricConfig): grpc.Client {
    const tlsRootCert = fs.readFileSync(config.tlsCertPath);
    const credentials = grpc.credentials.createSsl(tlsRootCert);
    return new grpc.Client(config.peerEndpoint, credentials, {
        'grpc.ssl_target_name_override': config.peerHostAlias,
    });
}

function newIdentity(config: FabricConfig): Identity {
    const credentials = fs.readFileSync(config.certPath);
    return { mspId: config.mspId, credentials };
}

function newSigner(config: FabricConfig) {
    const files = fs.readdirSync(config.keyDirectoryPath);
    if (files.length === 0) {
        throw new Error(`No private key files found in ${config.keyDirectoryPath}`);
    }
    const keyPath = path.join(config.keyDirectoryPath, files[0]);
    const privateKeyPem = fs.readFileSync(keyPath);
    const privateKey = crypto.createPrivateKey(privateKeyPem);
    return signers.newPrivateKeySigner(privateKey);
}

export class FabricConnection {
    private client: grpc.Client;
    private gateway: Gateway;
    private contract: Contract;

    constructor(private readonly config: FabricConfig) {
        this.client = newGrpcConnection(config);
        this.gateway = connect({
            client: this.client,
            identity: newIdentity(config),
            signer: newSigner(config),
            evaluateOptions: () => ({ deadline: Date.now() + 5000 }),
            endorseOptions: () => ({ deadline: Date.now() + 15000 }),
            submitOptions: () => ({ deadline: Date.now() + 5000 }),
            commitStatusOptions: () => ({ deadline: Date.now() + 60000 }),
        });
        const network = this.gateway.getNetwork(config.channelName);
        this.contract = network.getContract(config.chaincodeName);
    }

    /** Submits (writes) a transaction. Returns the chaincode's return value
     * plus the actual transaction id. Fabric Gateway's transaction-commit
     * model does not expose a block number to clients -- we never invent
     * one; block_number stays null unless a later qscc lookup adds it. */
    async invoke(functionName: string, args: string[]): Promise<{ transactionId: string; result: string }> {
        const proposal = this.contract.newProposal(functionName, { arguments: args });
        const transaction = await proposal.endorse();
        const transactionId = transaction.getTransactionId();
        const commit = await transaction.submit();
        const status = await commit.getStatus();
        if (!status.successful) {
            throw new Error(`Transaction ${transactionId} failed to commit with status code ${status.code}`);
        }
        const resultBytes = transaction.getResult();
        return { transactionId, result: Buffer.from(resultBytes).toString('utf8') };
    }

    async query(functionName: string, args: string[]): Promise<string> {
        const resultBytes = await this.contract.evaluateTransaction(functionName, ...args);
        return Buffer.from(resultBytes).toString('utf8');
    }

    close(): void {
        this.gateway.close();
        this.client.close();
    }
}
