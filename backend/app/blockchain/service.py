"""BlockchainService: the only entry point the rest of the app uses to
record or verify provenance. Wraps FabricGateway with idempotency (spec
section 33) and graceful degradation to a MongoDB-backed PENDING queue when
Fabric is unreachable (spec section 34) -- a scan/audit always completes in
Mongo regardless of blockchain availability.
"""
from __future__ import annotations

import logging

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.blockchain.exceptions import BlockchainUnavailableError
from app.blockchain.fabric_gateway import FabricGateway
from app.blockchain.schemas import EventType
from app.db import Collections
from app.utils.ids import new_event_id, utcnow_iso

logger = logging.getLogger("sih26155.blockchain")

_EVENT_TO_FUNCTION: dict[str, str] = {
    "CONFIGURATION_RECEIVED": "CreateAuditRecord",
    "CONFIGURATION_VERSION_CREATED": "CreateConfigurationVersion",
    "COMPLIANCE_COMPLETED": "RecordComplianceHash",
    "RISK_CALCULATED": "RecordRiskHash",
    "REMEDIATION_APPROVED": "RecordRemediationApproval",
    "TRAINING_MAPPING_APPROVED": "RecordTrainingMapping",
    "REPORT_GENERATED": "CreateAuditRecord",
    "AUDIT_COMPLETED": "CreateAuditRecord",
}


def _deterministic_event_id(audit_id: str, event_type: str) -> str:
    """Idempotency key: the same logical event for the same audit always
    maps to the same event_id, so retries/duplicates never double-write."""
    return f"{audit_id}:{event_type}"


async def _build_record_args(
    *,
    event_id: str,
    audit_id: str,
    device_id: str,
    actor_id: str,
    event_type: EventType,
    version: int,
    hashes: dict[str, str | None],
) -> list[str]:
    import json

    record = {
        "event_id": event_id,
        "audit_id": audit_id,
        "device_id": device_id,
        "actor_id": actor_id,
        "event_type": event_type,
        "version": version,
        "schema_version": "1.0",
        "timestamp": utcnow_iso(),
        **hashes,
    }
    return [json.dumps(record, sort_keys=True)]


async def record_event(
    db: AsyncIOMotorDatabase,
    *,
    audit_id: str,
    device_id: str,
    actor_id: str,
    event_type: EventType,
    version: int = 1,
    **hashes: str | None,
) -> dict:
    """Records one provenance event. Idempotent per (audit_id, event_type).
    Never raises -- returns {"status": "CONFIRMED"|"PENDING", ...}."""
    event_id = _deterministic_event_id(audit_id, event_type)

    existing = await db[Collections.BLOCKCHAIN_TRANSACTIONS].find_one({"event_id": event_id})
    if existing and existing.get("status") == "CONFIRMED":
        return {"status": "CONFIRMED", "transaction_id": existing.get("transaction_id"), "event_id": event_id, "idempotent": True}

    function_name = _EVENT_TO_FUNCTION.get(event_type, "CreateAuditRecord")
    args = await _build_record_args(
        event_id=event_id, audit_id=audit_id, device_id=device_id, actor_id=actor_id,
        event_type=event_type, version=version, hashes=hashes,
    )

    base_doc = {
        "event_id": event_id,
        "audit_id": audit_id,
        "device_id": device_id,
        "actor_id": actor_id,
        "event_type": event_type,
        "updated_at": utcnow_iso(),
        **hashes,
    }

    gateway = FabricGateway()
    try:
        result = await gateway.submit_transaction(function_name, args)
        doc = {
            **base_doc,
            "status": "CONFIRMED",
            "transaction_id": result.get("transactionId"),
            "block_number": result.get("blockNumber"),
            "reason": None,
        }
        await db[Collections.BLOCKCHAIN_TRANSACTIONS].update_one(
            {"event_id": event_id}, {"$set": doc, "$setOnInsert": {"created_at": utcnow_iso(), "retry_count": 0}}, upsert=True
        )
        return {"status": "CONFIRMED", "transaction_id": doc["transaction_id"], "block_number": doc["block_number"], "event_id": event_id}
    except BlockchainUnavailableError as exc:
        logger.warning("Fabric unavailable recording %s for %s: %s", event_type, audit_id, exc)
        doc = {
            **base_doc,
            "status": "PENDING",
            "transaction_id": None,
            "block_number": None,
            "reason": str(exc),
        }
        await db[Collections.BLOCKCHAIN_TRANSACTIONS].update_one(
            {"event_id": event_id}, {"$set": doc, "$setOnInsert": {"created_at": utcnow_iso(), "retry_count": 0}}, upsert=True
        )
        await db[Collections.BLOCKCHAIN_PENDING_QUEUE].update_one(
            {"event_id": event_id},
            {
                "$set": {
                    "event_id": event_id, "function_name": function_name, "args": args,
                    "last_attempt_at": utcnow_iso(), "last_error": str(exc),
                },
                "$setOnInsert": {"created_at": utcnow_iso(), "retry_count": 0},
                "$inc": {"attempt_count": 1},
            },
            upsert=True,
        )
        return {"status": "PENDING", "event_id": event_id, "reason": str(exc)}


async def record_audit_completed(
    db: AsyncIOMotorDatabase,
    *,
    audit_id: str,
    device_id: str,
    actor_id: str,
    configuration_hash: str,
    compliance_hash: str,
    risk_hash: str,
) -> dict:
    return await record_event(
        db,
        audit_id=audit_id,
        device_id=device_id,
        actor_id=actor_id,
        event_type="AUDIT_COMPLETED",
        configuration_hash=configuration_hash,
        compliance_hash=compliance_hash,
        risk_hash=risk_hash,
    )


async def retry_pending_transactions(db: AsyncIOMotorDatabase, *, max_batch: int = 20) -> dict:
    """Retries queued transactions (spec section 34). Intended to be called
    periodically by a worker (app/workers/blockchain_retry_worker.py)."""
    gateway = FabricGateway()
    pending = await db[Collections.BLOCKCHAIN_PENDING_QUEUE].find({}).sort("created_at", 1).to_list(length=max_batch)

    retried, confirmed, still_pending = 0, 0, 0
    for item in pending:
        retried += 1
        try:
            result = await gateway.submit_transaction(item["function_name"], item["args"])
            await db[Collections.BLOCKCHAIN_TRANSACTIONS].update_one(
                {"event_id": item["event_id"]},
                {"$set": {
                    "status": "CONFIRMED",
                    "transaction_id": result.get("transactionId"),
                    "block_number": result.get("blockNumber"),
                    "reason": None,
                    "updated_at": utcnow_iso(),
                }},
            )
            await db[Collections.BLOCKCHAIN_PENDING_QUEUE].delete_one({"event_id": item["event_id"]})
            confirmed += 1
        except BlockchainUnavailableError as exc:
            still_pending += 1
            await db[Collections.BLOCKCHAIN_PENDING_QUEUE].update_one(
                {"event_id": item["event_id"]},
                {"$set": {"last_attempt_at": utcnow_iso(), "last_error": str(exc)}, "$inc": {"attempt_count": 1}},
            )

    return {"retried": retried, "confirmed": confirmed, "still_pending": still_pending}
