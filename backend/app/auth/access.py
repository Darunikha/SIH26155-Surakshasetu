"""Project-level access scoping (spec section 50: RBAC).

There is no team/organization concept in this system -- every project has a
single owner. To avoid leaking one user's uploaded configurations, findings,
and audit history to a completely unrelated account on the same deployment,
non-admin roles only see projects they own; ADMIN sees everything (platform
oversight). This is applied at the project level and propagated to
devices/configurations/scans via their project_id.
"""
from __future__ import annotations

from app.auth.dependencies import CurrentUser
from app.auth.roles import Role
from app.db import Collections
from app.schemas.common import AppError, ErrorCode


async def accessible_project_filter(db, user: CurrentUser) -> dict:
    """Returns a MongoDB filter fragment restricting to projects the user may
    see. Admins get an empty filter (no restriction)."""
    if user.role == Role.ADMIN:
        return {}
    project_ids = await db[Collections.PROJECTS].distinct("project_id", {"owner_id": user.user_id})
    return {"project_id": {"$in": project_ids}}


async def require_project_access(db, user: CurrentUser, project_id: str) -> None:
    """Raises AppError(FORBIDDEN) if the user cannot access this specific project."""
    if user.role == Role.ADMIN:
        return
    project = await db[Collections.PROJECTS].find_one({"project_id": project_id}, {"_id": 0, "owner_id": 1})
    if not project or project.get("owner_id") != user.user_id:
        raise AppError(ErrorCode.FORBIDDEN, f"Project {project_id} is not accessible to this user", 403)
