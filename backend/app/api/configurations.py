from __future__ import annotations

from fastapi import APIRouter, Depends, UploadFile

from app.api.deps import get_request_id
from app.auth.access import accessible_project_filter, require_project_access
from app.auth.dependencies import CurrentUser, get_current_user
from app.db import Collections, get_db
from app.models.configuration import ProcessingStatus
from app.schemas.common import AppError, ErrorCode, ok
from app.security.hashing import calculate_ir_hash
from app.services.configuration_service import process_upload
from app.utils.ids import new_device_id, utcnow_iso
from app.vendors.registry import parse_configuration

router = APIRouter(prefix="/api/configurations", tags=["configurations"])


async def _resolve_device(db, project_id: str, device_id: str | None, device_name: str | None) -> str:
    if device_id:
        device = await db[Collections.DEVICES].find_one({"device_id": device_id})
        if not device:
            raise AppError(ErrorCode.NOT_FOUND, "Device not found", 404)
        return device_id

    name = device_name or "unnamed-device"
    now = utcnow_iso()
    new_id = new_device_id()
    await db[Collections.DEVICES].insert_one(
        {
            "device_id": new_id,
            "project_id": project_id,
            "name": name,
            "vendor": None,
            "platform": None,
            "asset_context": {
                "criticality": "medium",
                "business_role": "",
                "data_sensitivity": "internal",
                "internet_exposure": False,
                "environment": "production",
                "owner": "",
                "department": "",
            },
            "created_at": now,
            "updated_at": now,
        }
    )
    return new_id


@router.post("/upload")
async def upload_configuration(
    project_id: str,
    file: UploadFile,
    device_id: str | None = None,
    device_name: str | None = None,
    vendor_hint: str | None = None,
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    db = get_db()
    project = await db[Collections.PROJECTS].find_one({"project_id": project_id})
    if not project:
        raise AppError(ErrorCode.NOT_FOUND, "Project not found", 404)

    resolved_device_id = await _resolve_device(db, project_id, device_id, device_name)
    content = await file.read()

    result = await process_upload(
        db,
        project_id=project_id,
        device_id=resolved_device_id,
        filename=file.filename or "unnamed",
        content=content,
        uploaded_by=user.user_id,
        vendor_hint=vendor_hint,
    )

    if result.get("vendor") and result.get("status") == ProcessingStatus.COMPLETED.value:
        await db[Collections.DEVICES].update_one(
            {"device_id": resolved_device_id},
            {"$set": {"vendor": result["vendor"], "platform": result["platform"], "updated_at": utcnow_iso()}},
        )

    return ok({**result, "device_id": resolved_device_id}, request_id)


@router.post("/bulk")
async def bulk_upload_configurations(
    project_id: str,
    files: list[UploadFile],
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    """Bulk upload: each file becomes its own device + configuration record
    (spec section 9 example: uploading cisco-router.cfg, fortigate.conf,
    paloalto.xml creates three separate device/configuration records)."""
    db = get_db()
    project = await db[Collections.PROJECTS].find_one({"project_id": project_id})
    if not project:
        raise AppError(ErrorCode.NOT_FOUND, "Project not found", 404)

    results = []
    for file in files:
        content = await file.read()
        device_name = (file.filename or "unnamed").rsplit(".", 1)[0]
        device_id = await _resolve_device(db, project_id, None, device_name)
        try:
            result = await process_upload(
                db,
                project_id=project_id,
                device_id=device_id,
                filename=file.filename or "unnamed",
                content=content,
                uploaded_by=user.user_id,
            )
            if result.get("vendor") and result.get("status") == ProcessingStatus.COMPLETED.value:
                await db[Collections.DEVICES].update_one(
                    {"device_id": device_id},
                    {"$set": {"vendor": result["vendor"], "platform": result["platform"]}},
                )
            results.append({"filename": file.filename, "device_id": device_id, **result})
        except AppError as exc:
            results.append(
                {
                    "filename": file.filename,
                    "device_id": device_id,
                    "status": "FAILED",
                    "error_message": exc.message,
                }
            )

    return ok({"uploaded": len(results), "results": results}, request_id)


@router.get("")
async def list_configurations(
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
    configs = await db[Collections.CONFIGURATIONS].find(query, {"_id": 0}).to_list(length=1000)

    if configs:
        latest_pairs = [{"configuration_id": c["configuration_id"], "version": c["latest_version"]} for c in configs]
        latest_versions = await db[Collections.CONFIGURATION_VERSIONS].find(
            {"$or": latest_pairs}, {"_id": 0, "security_ir": 0}
        ).to_list(length=len(latest_pairs))
        latest_by_config = {v["configuration_id"]: v for v in latest_versions}
        configs = [{**c, "latest": latest_by_config.get(c["configuration_id"])} for c in configs]

    return ok(configs, request_id)


@router.get("/{configuration_id}")
async def get_configuration(
    configuration_id: str,
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    db = get_db()
    config = await db[Collections.CONFIGURATIONS].find_one({"configuration_id": configuration_id}, {"_id": 0})
    if not config:
        raise AppError(ErrorCode.NOT_FOUND, "Configuration not found", 404)
    latest = await db[Collections.CONFIGURATION_VERSIONS].find_one(
        {"configuration_id": configuration_id, "version": config["latest_version"]}, {"_id": 0}
    )
    return ok({**config, "latest": latest}, request_id)


@router.get("/{configuration_id}/versions")
async def list_versions(
    configuration_id: str,
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    db = get_db()
    versions = (
        await db[Collections.CONFIGURATION_VERSIONS]
        .find({"configuration_id": configuration_id}, {"_id": 0, "security_ir": 0})
        .sort("version", 1)
        .to_list(length=1000)
    )
    return ok(versions, request_id)


@router.get("/{configuration_id}/versions/{version}")
async def get_version(
    configuration_id: str,
    version: int,
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    db = get_db()
    doc = await db[Collections.CONFIGURATION_VERSIONS].find_one(
        {"configuration_id": configuration_id, "version": version}, {"_id": 0}
    )
    if not doc:
        raise AppError(ErrorCode.NOT_FOUND, "Configuration version not found", 404)
    return ok(doc, request_id)


@router.post("/{configuration_id}/versions/{version}/confirm-vendor")
async def confirm_vendor(
    configuration_id: str,
    version: int,
    vendor: str,
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    """Human confirmation step for low-confidence vendor detections (spec
    section 13: an uncertain AI/signature guess never silently becomes
    authoritative)."""
    db = get_db()
    doc = await db[Collections.CONFIGURATION_VERSIONS].find_one(
        {"configuration_id": configuration_id, "version": version}
    )
    if not doc:
        raise AppError(ErrorCode.NOT_FOUND, "Configuration version not found", 404)

    storage_id = doc["storage_id"]
    from app.ingestion.storage import read_upload

    raw = read_upload(storage_id)
    from app.ingestion.validation import decode_text

    _, text = decode_text(raw)

    update: dict = {"vendor": vendor, "vendor_confidence": 1.0, "vendor_detection_method": "human_confirmed"}
    try:
        ir = parse_configuration(vendor, text)
    except NotImplementedError as exc:
        update["status"] = ProcessingStatus.FAILED.value
        update["error_message"] = str(exc)
    except Exception as exc:
        update["status"] = ProcessingStatus.FAILED.value
        update["error_message"] = f"Parser failure: {exc}"
    else:
        ir_dict = ir.model_dump(mode="json")
        update["security_ir"] = ir_dict
        update["ir_hash"] = calculate_ir_hash(ir_dict)
        update["software_version"] = ir.device.version
        update["status"] = ProcessingStatus.COMPLETED.value

    await db[Collections.CONFIGURATION_VERSIONS].update_one(
        {"configuration_id": configuration_id, "version": version}, {"$set": update}
    )
    if update["status"] == ProcessingStatus.COMPLETED.value:
        await db[Collections.DEVICES].update_one(
            {"device_id": doc["device_id"]}, {"$set": {"vendor": vendor, "updated_at": utcnow_iso()}}
        )

    return ok({"configuration_id": configuration_id, "version": version, **update}, request_id)
