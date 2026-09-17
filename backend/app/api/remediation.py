"""Remediation generation/validation/approval (spec sections 24-25, 37).

Pipeline: AI drafts commands -> syntax validation -> human approval ->
simulation (never real deployment in this prototype) -> re-audit is
triggered separately by starting a new scan.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.ai.exceptions import AIUnavailableError
from app.ai.service import AIService
from app.api.deps import get_request_id
from app.auth.access import require_project_access
from app.auth.dependencies import CurrentUser, get_current_user
from app.auth.roles import APPROVAL_ROLES
from app.db import Collections, get_db
from app.remediation.validator import validate_commands
from app.schemas.common import AppError, ErrorCode, ok
from app.security.hashing import calculate_remediation_hash
from app.utils.ids import new_remediation_id, utcnow_iso

router = APIRouter(prefix="/api/remediation", tags=["remediation"])


class GenerateRemediationRequest(BaseModel):
    finding_id: str


async def _require_remediation_access(db, user: CurrentUser, remediation_id: str) -> dict:
    """A remediation plan has no owner of its own -- it inherits access from
    the device (via project) it was drafted for. Every endpoint keyed by
    remediation_id must call this before reading/mutating the plan."""
    plan = await db[Collections.REMEDIATION_PLANS].find_one({"remediation_id": remediation_id}, {"_id": 0})
    if not plan:
        raise AppError(ErrorCode.NOT_FOUND, "Remediation plan not found", 404)
    device = await db[Collections.DEVICES].find_one({"device_id": plan["device_id"]}, {"_id": 0, "project_id": 1})
    if device:
        await require_project_access(db, user, device["project_id"])
    return plan


@router.post("/generate")
async def generate_remediation(
    body: GenerateRemediationRequest,
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    db = get_db()
    finding = await db[Collections.FINDINGS].find_one({"finding_id": body.finding_id}, {"_id": 0})
    if not finding:
        raise AppError(ErrorCode.NOT_FOUND, "Finding not found", 404)

    device = await db[Collections.DEVICES].find_one({"device_id": finding["device_id"]}, {"_id": 0})
    if device:
        await require_project_access(db, user, device["project_id"])
    vendor = device.get("vendor") or "Unknown"
    platform = device.get("platform") or "Unknown"

    rag_context = ""
    try:
        from app.rag.retriever import retrieve_context

        rag_context = await retrieve_context(finding["control_id"])
    except Exception:
        pass

    ai = AIService()
    try:
        suggestion = await ai.generate_remediation(finding=finding, vendor=vendor, platform=platform, rag_context=rag_context)
    except AIUnavailableError as exc:
        raise AppError(ErrorCode.AI_UNAVAILABLE, str(exc), 503) from exc

    validation_results = validate_commands(vendor, suggestion["suggested_commands"])
    remediation_id = new_remediation_id()
    plan_doc = {
        "remediation_id": remediation_id,
        "finding_id": body.finding_id,
        "device_id": finding["device_id"],
        "vendor": vendor,
        "platform": platform,
        "explanation": suggestion["explanation"],
        "suggested_commands": suggestion["suggested_commands"],
        "validation_results": validation_results,
        "status": "AWAITING_APPROVAL",
        "created_by": user.user_id,
        "created_at": utcnow_iso(),
        "approved_by": None,
        "approved_at": None,
    }
    await db[Collections.REMEDIATION_PLANS].insert_one(dict(plan_doc))
    return ok(plan_doc, request_id)


@router.post("/{remediation_id}/approve")
async def approve_remediation(
    remediation_id: str,
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    if user.role not in APPROVAL_ROLES:
        raise AppError(ErrorCode.FORBIDDEN, "This role cannot approve remediation plans", 403)

    db = get_db()
    plan = await _require_remediation_access(db, user, remediation_id)

    remediation_hash = calculate_remediation_hash(
        {"remediation_id": remediation_id, "commands": plan["suggested_commands"]}
    )
    await db[Collections.REMEDIATION_PLANS].update_one(
        {"remediation_id": remediation_id},
        {"$set": {"status": "APPROVED", "approved_by": user.user_id, "approved_at": utcnow_iso(), "remediation_hash": remediation_hash}},
    )

    try:
        from app.blockchain.service import record_event

        await record_event(
            db, audit_id=plan["finding_id"], device_id=plan["device_id"], actor_id=user.user_id,
            event_type="REMEDIATION_APPROVED", remediation_hash=remediation_hash,
        )
    except Exception:
        pass

    return ok({"remediation_id": remediation_id, "status": "APPROVED"}, request_id)


@router.post("/validate")
async def validate_remediation(
    remediation_id: str,
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    """Simulates the approved remediation (spec section 25: real deployment
    is disabled for this prototype -- status is always explicitly SIMULATED)."""
    db = get_db()
    plan = await _require_remediation_access(db, user, remediation_id)
    if plan["status"] != "APPROVED":
        raise AppError(ErrorCode.VALIDATION_ERROR, "Remediation plan must be approved before simulation", 400)

    all_valid = all(r["valid"] for r in plan["validation_results"])
    await db[Collections.REMEDIATION_PLANS].update_one(
        {"remediation_id": remediation_id},
        {"$set": {"status": "SIMULATED", "simulation_passed": all_valid, "simulated_at": utcnow_iso()}},
    )
    return ok(
        {
            "remediation_id": remediation_id,
            "status": "SIMULATED",
            "simulation_passed": all_valid,
            "note": "No real device configuration was changed -- this prototype only simulates remediation. "
            "Start a new scan after applying changes manually to re-audit.",
        },
        request_id,
    )


@router.get("/{remediation_id}")
async def get_remediation(remediation_id: str, request_id: str = Depends(get_request_id), user: CurrentUser = Depends(get_current_user)):
    db = get_db()
    doc = await _require_remediation_access(db, user, remediation_id)
    return ok(doc, request_id)
