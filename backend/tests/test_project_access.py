"""Regression test for a real bug found during E2E testing: /api/projects
returned every user's projects to any authenticated account (no owner
scoping). accessible_project_filter/require_project_access close that gap;
this locks the fix in against the live database."""
from __future__ import annotations

import pytest

from app.auth.access import accessible_project_filter, require_project_access
from app.auth.dependencies import CurrentUser
from app.auth.roles import Role
from app.db import Collections, connect
from app.schemas.common import AppError
from app.utils.ids import new_project_id, utcnow_iso

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_non_admin_only_sees_own_projects():
    db = connect()
    owner_a = CurrentUser(user_id="USER-TEST-A", email="a@test.com", role=Role.SECURITY_ANALYST)
    owner_b = CurrentUser(user_id="USER-TEST-B", email="b@test.com", role=Role.SECURITY_ANALYST)

    project_a = new_project_id()
    project_b = new_project_id()
    await db[Collections.PROJECTS].insert_one(
        {"project_id": project_a, "name": "A's project", "description": "", "owner_id": owner_a.user_id, "created_at": utcnow_iso()}
    )
    await db[Collections.PROJECTS].insert_one(
        {"project_id": project_b, "name": "B's project", "description": "", "owner_id": owner_b.user_id, "created_at": utcnow_iso()}
    )

    try:
        filter_a = await accessible_project_filter(db, owner_a)
        visible_to_a = await db[Collections.PROJECTS].distinct("project_id", filter_a)
        assert project_a in visible_to_a
        assert project_b not in visible_to_a

        # Owner A must not be able to directly access B's project either.
        with pytest.raises(AppError):
            await require_project_access(db, owner_a, project_b)

        # Owner A can access their own project without error.
        await require_project_access(db, owner_a, project_a)
    finally:
        await db[Collections.PROJECTS].delete_many({"project_id": {"$in": [project_a, project_b]}})


@pytest.mark.asyncio
async def test_admin_sees_all_projects_unrestricted():
    db = connect()
    admin = CurrentUser(user_id="USER-TEST-ADMIN", email="admin@test.com", role=Role.ADMIN)
    filter_admin = await accessible_project_filter(db, admin)
    assert filter_admin == {}
