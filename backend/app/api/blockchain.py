from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.deps import get_request_id
from app.auth.access import accessible_project_filter, require_project_access
from app.auth.dependencies import CurrentUser, get_current_user
from app.blockchain.fabric_gateway import FabricGateway
from app.blockchain.service import record_event
from app.blockchain.verifier import verify_audit
from app.db import Collections, get_db
from app.schemas.common import AppError, ErrorCode, ok

router = APIRouter(prefix="/api/blockchain", tags=["blockchain"])


class RecordEventRequest(BaseModel):
    audit_id: str
    device_id: str
    event_type: str
    configuration_hash: str | None = None
    compliance_hash: str | None = None
    risk_hash: str | None = None
    attack_graph_hash: str | None = None
    remediation_hash: str | None = None
    report_hash: str | None = None


@router.post("/record")
async def record(
    body: RecordEventRequest,
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    db = get_db()
    result = await record_event(
        db,
        audit_id=body.audit_id,
        device_id=body.device_id,
        actor_id=user.user_id,
        event_type=body.event_type,
        configuration_hash=body.configuration_hash,
        compliance_hash=body.compliance_hash,
        risk_hash=body.risk_hash,
        attack_graph_hash=body.attack_graph_hash,
        remediation_hash=body.remediation_hash,
        report_hash=body.report_hash,
    )
    return ok(result, request_id)


class VerifyRequest(BaseModel):
    audit_id: str


@router.post("/verify")
async def verify(
    body: VerifyRequest,
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    db = get_db()
    result = await verify_audit(db, body.audit_id)
    return ok(result, request_id)


@router.get("/audit/{audit_id}")
async def get_audit_transactions(
    audit_id: str,
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    db = get_db()
    scan = await db[Collections.SCANS].find_one({"scan_id": audit_id}, {"_id": 0, "project_id": 1})
    if scan:
        await require_project_access(db, user, scan["project_id"])
    txs = await db[Collections.BLOCKCHAIN_TRANSACTIONS].find({"audit_id": audit_id}, {"_id": 0}).to_list(length=100)
    return ok(txs, request_id)


@router.get("/history/{device_id}")
async def get_device_history(
    device_id: str,
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    db = get_db()
    device = await db[Collections.DEVICES].find_one({"device_id": device_id}, {"_id": 0, "project_id": 1})
    if device:
        await require_project_access(db, user, device["project_id"])
    txs = await db[Collections.BLOCKCHAIN_TRANSACTIONS].find({"device_id": device_id}, {"_id": 0}).sort("created_at", 1).to_list(length=1000)
    return ok(txs, request_id)


@router.get("/status")
async def blockchain_status(
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    """Reports whether Fabric is actually reachable right now, plus
    aggregate counters for the Blockchain Integrity dashboard (spec section 48)."""
    db = get_db()
    gateway = FabricGateway()
    reachable = await gateway.health_check()

    # Scope to devices the user can see -- these counters otherwise aggregate
    # every user's audits/transactions (see app/api/dashboard.py for the same
    # fix and rationale).
    project_filter = await accessible_project_filter(db, user)
    device_scope: dict = {}
    if project_filter:
        accessible_device_ids = await db[Collections.DEVICES].distinct("device_id", project_filter)
        device_scope = {"device_id": {"$in": accessible_device_ids}}

    total = await db[Collections.SCANS].count_documents({**project_filter, "status": "COMPLETED"})
    confirmed = await db[Collections.BLOCKCHAIN_TRANSACTIONS].count_documents(
        {**device_scope, "event_type": "AUDIT_COMPLETED", "status": "CONFIRMED"}
    )
    pending = await db[Collections.BLOCKCHAIN_TRANSACTIONS].count_documents(
        {**device_scope, "event_type": "AUDIT_COMPLETED", "status": "PENDING"}
    )

    return ok(
        {
            "fabric_reachable": reachable,
            "total_audits": total,
            "confirmed_transactions": confirmed,
            "pending_transactions": pending,
        },
        request_id,
    )
