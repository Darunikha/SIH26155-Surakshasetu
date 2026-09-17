"""Duplicate upload detection by configuration hash (spec section 9)."""
from __future__ import annotations

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.db import Collections


async def find_duplicate_version(
    db: AsyncIOMotorDatabase, device_id: str, configuration_hash: str
) -> dict | None:
    return await db[Collections.CONFIGURATION_VERSIONS].find_one(
        {"device_id": device_id, "configuration_hash": configuration_hash}
    )
