from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.deps import get_request_id
from app.auth.access import accessible_project_filter, require_project_access
from app.auth.dependencies import CurrentUser, get_current_user
from app.db import Collections, get_db
from app.models.device import AssetContext
from app.schemas.common import AppError, ErrorCode, ok
from app.utils.ids import new_device_id, utcnow_iso

router = APIRouter(prefix="/api/devices", tags=["devices"])


class CreateDeviceRequest(BaseModel):
    project_id: str
    name: str
    asset_context: AssetContext = AssetContext()


@router.post("")
async def create_device(
    body: CreateDeviceRequest,
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    db = get_db()
    project = await db[Collections.PROJECTS].find_one({"project_id": body.project_id})
    if not project:
        raise AppError(ErrorCode.NOT_FOUND, "Project not found", 404)

    device_id = new_device_id()
    now = utcnow_iso()
    doc = {
        "device_id": device_id,
        "project_id": body.project_id,
        "name": body.name,
        "vendor": None,
        "platform": None,
        "asset_context": body.asset_context.model_dump(mode="json"),
        "created_at": now,
        "updated_at": now,
    }
    await db[Collections.DEVICES].insert_one(doc)
    doc.pop("_id", None)
    return ok(doc, request_id)


@router.get("")
async def list_devices(
    project_id: str | None = None,
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    db = get_db()
    if project_id:
        await require_project_access(db, user, project_id)
        query = {"project_id": project_id}
    else:
        query = await accessible_project_filter(db, user)
    devices = await db[Collections.DEVICES].find(query, {"_id": 0}).to_list(length=1000)
    return ok(devices, request_id)


@router.get("/{device_id}")
async def get_device(
    device_id: str,
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    db = get_db()
    device = await db[Collections.DEVICES].find_one({"device_id": device_id}, {"_id": 0})
    if not device:
        raise AppError(ErrorCode.NOT_FOUND, "Device not found", 404)
    return ok(device, request_id)


class UpdateAssetContextRequest(BaseModel):
    asset_context: AssetContext


@router.put("/{device_id}/asset-context")
async def update_asset_context(
    device_id: str,
    body: UpdateAssetContextRequest,
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    """Updating asset context invalidates prior risk scores -- the risk
    engine (spec section 21) recalculates from IR + this context on the next
    scan; we don't mutate historical risk_scores documents."""
    db = get_db()
    result = await db[Collections.DEVICES].update_one(
        {"device_id": device_id},
        {"$set": {"asset_context": body.asset_context.model_dump(mode="json"), "updated_at": utcnow_iso()}},
    )
    if result.matched_count == 0:
        raise AppError(ErrorCode.NOT_FOUND, "Device not found", 404)
    return ok({"device_id": device_id, "updated": True}, request_id)
