"""Mandatory blockchain integrity/tampering test (spec sections 32, 58).

This is a REAL integration test: it creates evidence in the live MongoDB,
commits real hashes to a live Hyperledger Fabric ledger through the actual
BlockchainService/FabricGateway/gateway-service chain, then tampers with
the MongoDB evidence directly and asserts the verifier -- which recomputes
hashes fresh and queries the real ledger -- reports INTEGRITY_VIOLATION.

Requires MongoDB (MONGODB_URI) and the Fabric gateway sidecar to be
reachable; skips with a clear message otherwise rather than fabricating a
pass. Run `blockchain/scripts/blockchain-up.sh` first (see docs/blockchain.md).
"""
from __future__ import annotations

import asyncio

import pytest

from app.blockchain.fabric_gateway import FabricGateway
from app.blockchain.service import record_event
from app.blockchain.verifier import verify_audit
from app.db import Collections, connect
from app.security.hashing import calculate_compliance_hash, calculate_configuration_hash
from app.utils.ids import new_audit_id, utcnow_iso


def _fabric_available() -> bool:
    async def _check():
        return await FabricGateway().health_check()

    return asyncio.run(_check())


pytestmark = pytest.mark.integration
requires_fabric = pytest.mark.skipif(
    not _fabric_available(),
    reason="Fabric gateway sidecar is not reachable -- run blockchain/scripts/blockchain-up.sh first",
)


@requires_fabric
@pytest.mark.asyncio
async def test_tampering_is_detected_against_the_real_fabric_ledger():
    db = connect()
    audit_id = new_audit_id()
    device_id = "DEVICE-TAMPER-TEST"

    configuration_hash = calculate_configuration_hash("hostname test\nip ssh version 2\n")
    compliance_payload = {"compliance_score": 72.5, "status_counts": {"PASS": 10, "FAIL": 4}}
    compliance_hash = calculate_compliance_hash(compliance_payload)

    # Seed MongoDB evidence exactly like a real scan would.
    await db[Collections.SCANS].insert_one(
        {
            "scan_id": audit_id,
            "device_id": device_id,
            "configuration_hash": configuration_hash,
            "status": "COMPLETED",
        }
    )
    await db[Collections.COMPLIANCE_RESULTS].insert_one(
        {"scan_id": audit_id, "device_id": device_id, **compliance_payload}
    )
    await db[Collections.RISK_SCORES].insert_one(
        {"scan_id": audit_id, "device_id": device_id, "risk_score": 40.0, "timestamp": utcnow_iso()}
    )

    try:
        # Commit real hashes to the real ledger.
        record_result = await record_event(
            db, audit_id=audit_id, device_id=device_id, actor_id="USER-TEST",
            event_type="AUDIT_COMPLETED", configuration_hash=configuration_hash, compliance_hash=compliance_hash,
        )
        assert record_result["status"] == "CONFIRMED", "Fabric commit did not confirm -- cannot test tampering detection"

        # Step 1: verify BEFORE tampering -- must succeed.
        pre_tamper = await verify_audit(db, audit_id)
        assert pre_tamper["verified"] is True, f"Expected clean verification before tampering: {pre_tamper}"

        # Step 2: tamper with MongoDB evidence directly (bypassing the app layer).
        await db[Collections.COMPLIANCE_RESULTS].update_one(
            {"scan_id": audit_id}, {"$set": {"compliance_score": 99.99}}
        )

        # Step 3: re-verify -- must now detect the mismatch.
        post_tamper = await verify_audit(db, audit_id)
        assert post_tamper["verified"] is False
        assert post_tamper["status"] == "INTEGRITY_VIOLATION"
        assert "compliance_hash" in post_tamper["mismatched_fields"]
        # configuration_hash was never touched -- must still match.
        assert "configuration_hash" not in post_tamper["mismatched_fields"]
    finally:
        await db[Collections.SCANS].delete_one({"scan_id": audit_id})
        await db[Collections.COMPLIANCE_RESULTS].delete_many({"scan_id": audit_id})
        await db[Collections.RISK_SCORES].delete_many({"scan_id": audit_id})
        await db[Collections.BLOCKCHAIN_TRANSACTIONS].delete_many({"audit_id": audit_id})
