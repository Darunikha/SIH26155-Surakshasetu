from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.deps import get_request_id
from app.auth.access import accessible_project_filter
from app.auth.dependencies import CurrentUser, get_current_user
from app.db import Collections, get_db
from app.schemas.common import ok
from app.utils.ids import new_project_id, utcnow_iso

router = APIRouter(prefix="/api/projects", tags=["projects"])


class CreateProjectRequest(BaseModel):
    name: str
    description: str = ""


@router.post("")
async def create_project(
    body: CreateProjectRequest,
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    db = get_db()
    project_id = new_project_id()
    doc = {
        "project_id": project_id,
        "name": body.name,
        "description": body.description,
        "owner_id": user.user_id,
        "created_at": utcnow_iso(),
    }
    await db[Collections.PROJECTS].insert_one(doc)
    doc.pop("_id", None)
    return ok(doc, request_id)


@router.get("")
async def list_projects(
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    db = get_db()
    query = await accessible_project_filter(db, user)
    projects = await db[Collections.PROJECTS].find(query, {"_id": 0}).to_list(length=500)
    return ok(projects, request_id)
