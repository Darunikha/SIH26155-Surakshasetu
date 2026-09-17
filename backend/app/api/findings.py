from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.deps import get_request_id
from app.auth.access import require_project_access
from app.auth.dependencies import CurrentUser, get_current_user
from app.db import Collections, get_db
from app.schemas.common import AppError, ErrorCode, ok

router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.get("/{finding_id}")
async def get_finding(finding_id: str, request_id: str = Depends(get_request_id), user: CurrentUser = Depends(get_current_user)):
    db = get_db()
    finding = await db[Collections.FINDINGS].find_one({"finding_id": finding_id}, {"_id": 0})
    if not finding:
        raise AppError(ErrorCode.NOT_FOUND, "Finding not found", 404)

    device = await db[Collections.DEVICES].find_one({"device_id": finding["device_id"]}, {"_id": 0})
    if device:
        await require_project_access(db, user, device["project_id"])
    graph_doc = await db[Collections.ATTACK_GRAPHS].find_one({"scan_id": finding["scan_id"]}, {"_id": 0})
    related_paths = [
        p for p in (graph_doc.get("potential_attack_paths", []) if graph_doc else [])
        if any(finding["control_id"].startswith(s) or s in (p.get("exposed_services") or []) for s in [finding["control_id"]])
    ]

    remediation = await db[Collections.REMEDIATION_PLANS].find_one({"finding_id": finding_id}, {"_id": 0}, sort=[("created_at", -1)])

    return ok(
        {
            **finding,
            "device": device,
            "related_attack_paths": related_paths,
            "remediation": remediation,
        },
        request_id,
    )
