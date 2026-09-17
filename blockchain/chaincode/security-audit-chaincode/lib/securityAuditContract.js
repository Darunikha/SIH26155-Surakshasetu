'use strict';

const { Contract } = require('fabric-contract-api');

/**
 * Security Audit Provenance chaincode (spec section 29).
 *
 * Only hashes and provenance metadata are ever written here -- never raw
 * configurations, secrets, or documents (spec section 7). Each audit's
 * record accumulates hash fields across multiple calls (compliance hash
 * arrives separately from risk hash, etc.), so writes MERGE into whatever
 * already exists for that audit_id rather than overwrite it.
 */
class SecurityAuditContract extends Contract {

    _auditKey(auditId) {
        return `audit:${auditId}`;
    }

    _deviceIndexKey(deviceId) {
        return `device_index:${deviceId}`;
    }

    async _mergeAuditRecord(ctx, incoming) {
        const key = this._auditKey(incoming.audit_id);
        const existingBytes = await ctx.stub.getState(key);
        let existing = {};
        if (existingBytes && existingBytes.length > 0) {
            existing = JSON.parse(existingBytes.toString('utf8'));
        }

        const merged = { ...existing };
        for (const [field, value] of Object.entries(incoming)) {
            if (value !== null && value !== undefined) {
                merged[field] = value;
            }
        }
        merged.last_updated_tx = ctx.stub.getTxID();
        merged.last_updated_timestamp = incoming.timestamp || merged.last_updated_timestamp;

        await ctx.stub.putState(key, Buffer.from(JSON.stringify(merged)));

        // Maintain a per-device index of audit ids for GetDeviceAuditHistory.
        if (incoming.device_id) {
            const idxKey = this._deviceIndexKey(incoming.device_id);
            const idxBytes = await ctx.stub.getState(idxKey);
            let auditIds = [];
            if (idxBytes && idxBytes.length > 0) {
                auditIds = JSON.parse(idxBytes.toString('utf8'));
            }
            if (!auditIds.includes(incoming.audit_id)) {
                auditIds.push(incoming.audit_id);
                await ctx.stub.putState(idxKey, Buffer.from(JSON.stringify(auditIds)));
            }
        }

        return { transactionId: ctx.stub.getTxID(), record: merged };
    }

    async _parseRecord(recordJson) {
        let record;
        try {
            record = JSON.parse(recordJson);
        } catch (err) {
            throw new Error(`Invalid record JSON: ${err.message}`);
        }
        if (!record.audit_id) {
            throw new Error('record.audit_id is required');
        }
        return record;
    }

    async CreateAuditRecord(ctx, recordJson) {
        const record = await this._parseRecord(recordJson);
        const result = await this._mergeAuditRecord(ctx, record);
        return JSON.stringify(result);
    }

    async GetAuditRecord(ctx, auditId) {
        const bytes = await ctx.stub.getState(this._auditKey(auditId));
        if (!bytes || bytes.length === 0) {
            return JSON.stringify({ record: null });
        }
        return JSON.stringify({ record: JSON.parse(bytes.toString('utf8')) });
    }

    async CreateConfigurationVersion(ctx, recordJson) {
        const record = await this._parseRecord(recordJson);
        const result = await this._mergeAuditRecord(ctx, record);
        return JSON.stringify(result);
    }

    async GetConfigurationVersion(ctx, auditId) {
        return this.GetAuditRecord(ctx, auditId);
    }

    async RecordComplianceHash(ctx, recordJson) {
        const record = await this._parseRecord(recordJson);
        const result = await this._mergeAuditRecord(ctx, record);
        return JSON.stringify(result);
    }

    async RecordRiskHash(ctx, recordJson) {
        const record = await this._parseRecord(recordJson);
        const result = await this._mergeAuditRecord(ctx, record);
        return JSON.stringify(result);
    }

    async RecordRemediationApproval(ctx, recordJson) {
        const record = await this._parseRecord(recordJson);
        const result = await this._mergeAuditRecord(ctx, record);
        return JSON.stringify(result);
    }

    async RecordTrainingMapping(ctx, recordJson) {
        const record = await this._parseRecord(recordJson);
        const result = await this._mergeAuditRecord(ctx, record);
        return JSON.stringify(result);
    }

    async VerifyHash(ctx, auditId, hashField, expectedHash) {
        const bytes = await ctx.stub.getState(this._auditKey(auditId));
        if (!bytes || bytes.length === 0) {
            return JSON.stringify({ verified: false, reason: 'audit record not found on ledger' });
        }
        const record = JSON.parse(bytes.toString('utf8'));
        const actual = record[hashField];
        return JSON.stringify({
            verified: actual === expectedHash,
            field: hashField,
            ledger_value: actual || null,
            expected_value: expectedHash,
        });
    }

    async GetDeviceAuditHistory(ctx, deviceId) {
        const idxBytes = await ctx.stub.getState(this._deviceIndexKey(deviceId));
        if (!idxBytes || idxBytes.length === 0) {
            return JSON.stringify({ device_id: deviceId, audits: [] });
        }
        const auditIds = JSON.parse(idxBytes.toString('utf8'));
        const audits = [];
        for (const auditId of auditIds) {
            const bytes = await ctx.stub.getState(this._auditKey(auditId));
            if (bytes && bytes.length > 0) {
                audits.push(JSON.parse(bytes.toString('utf8')));
            }
        }
        return JSON.stringify({ device_id: deviceId, audits });
    }

    async GetAuditHistory(ctx, auditId) {
        const key = this._auditKey(auditId);
        const iterator = await ctx.stub.getHistoryForKey(key);
        const history = [];
        let result = await iterator.next();
        while (!result.done) {
            const value = result.value;
            let parsed = null;
            try {
                parsed = value.value && value.value.length > 0 ? JSON.parse(value.value.toString('utf8')) : null;
            } catch (err) {
                parsed = null;
            }
            history.push({
                tx_id: value.txId,
                timestamp: value.timestamp,
                is_delete: value.isDelete,
                value: parsed,
            });
            result = await iterator.next();
        }
        await iterator.close();
        return JSON.stringify({ audit_id: auditId, history });
    }
}

module.exports = SecurityAuditContract;
