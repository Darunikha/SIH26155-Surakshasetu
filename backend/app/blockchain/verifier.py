"""Integrity verification (spec sections 31-32).

Recomputes the SHA-256 of the CURRENT MongoDB evidence and compares it
against what is actually recorded on the Fabric ledger. Both sides are
computed fresh on every call -- this never just compares two cached values,
which is the only way a tampering demonstration means anything.
"""
from __future__ import annotations

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.blockchain.exceptions import BlockchainUnavailableError
from app.blockchain.fabric_gateway import FabricGateway
from app.db import Collections
from app.security.hashing import calculate_compliance_hash, calculate_risk_hash


async def verify_audit(db: AsyncIOMotorDatabase, audit_id: str) -> dict:
    scan = await db[Collections.SCANS].find_one({"scan_id": audit_id})
    if not scan:
        return {"verified": False, "status": "NOT_FOUND", "reason": f"No audit/scan found with id {audit_id}"}

    compliance_doc = await db[Collections.COMPLIANCE_RESULTS].find_one({"scan_id": audit_id})
    risk_doc = await db[Collections.RISK_SCORES].find_one({"scan_id": audit_id})

    if not compliance_doc or not risk_doc:
        return {"verified": False, "status": "INSUFFICIENT_EVIDENCE", "reason": "Compliance or risk evidence missing in MongoDB"}

    # Recompute hashes from CURRENT Mongo evidence, stripping Mongo's own
    # volatile bookkeeping fields the same way the original hash did.
    compliance_for_hash = {k: v for k, v in compliance_doc.items() if k not in ("_id", "compliance_hash", "scan_id", "device_id", "created_at")}
    risk_for_hash = {k: v for k, v in risk_doc.items() if k not in ("_id", "risk_hash", "scan_id", "device_id", "timestamp")}

    current_compliance_hash = calculate_compliance_hash(compliance_for_hash)
    current_risk_hash = calculate_risk_hash(risk_for_hash)
    current_configuration_hash = scan.get("configuration_hash")

    gateway = FabricGateway()
    try:
        chain_record = await gateway.evaluate_transaction("GetAuditRecord", [audit_id])
    except BlockchainUnavailableError as exc:
        return {
            "verified": False,
            "status": "BLOCKCHAIN_UNAVAILABLE",
            "reason": str(exc),
            "database_hashes": {
                "configuration_hash": current_configuration_hash,
                "compliance_hash": current_compliance_hash,
                "risk_hash": current_risk_hash,
            },
        }

    record = chain_record.get("record") if isinstance(chain_record, dict) else None
    if not record:
        return {"verified": False, "status": "NOT_FOUND_ON_CHAIN", "reason": "No ledger record for this audit id", "audit_id": audit_id}

    chain_config_hash = record.get("configuration_hash")
    chain_compliance_hash = record.get("compliance_hash")
    chain_risk_hash = record.get("risk_hash")

    mismatches = []
    if chain_config_hash and chain_config_hash != current_configuration_hash:
        mismatches.append("configuration_hash")
    if chain_compliance_hash and chain_compliance_hash != current_compliance_hash:
        mismatches.append("compliance_hash")
    if chain_risk_hash and chain_risk_hash != current_risk_hash:
        mismatches.append("risk_hash")

    if mismatches:
        return {
            "verified": False,
            "status": "INTEGRITY_VIOLATION",
            "audit_id": audit_id,
            "algorithm": "SHA-256",
            "mismatched_fields": mismatches,
            "database_hashes": {
                "configuration_hash": current_configuration_hash,
                "compliance_hash": current_compliance_hash,
                "risk_hash": current_risk_hash,
            },
            "blockchain_hashes": {
                "configuration_hash": chain_config_hash,
                "compliance_hash": chain_compliance_hash,
                "risk_hash": chain_risk_hash,
            },
        }

    return {
        "verified": True,
        "audit_id": audit_id,
        "algorithm": "SHA-256",
        "database_hashes": {
            "configuration_hash": current_configuration_hash,
            "compliance_hash": current_compliance_hash,
            "risk_hash": current_risk_hash,
        },
        "blockchain_hashes": {
            "configuration_hash": chain_config_hash,
            "compliance_hash": chain_compliance_hash,
            "risk_hash": chain_risk_hash,
        },
        "transaction_id": record.get("transaction_id"),
    }
