"""Safe on-disk storage for uploaded configuration files.

Files are stored under a generated, collision-resistant id -- never under
the user-supplied filename -- so path traversal and filename collisions are
structurally impossible.
"""
from __future__ import annotations

import uuid

from app.config import get_settings


def store_upload(content: bytes, extension: str) -> str:
    """Persist `content` to disk and return its generated storage id
    (filename, not a path -- callers resolve via `resolve_path`)."""
    storage_id = f"{uuid.uuid4().hex}{extension}"
    path = get_settings().upload_storage_path / storage_id
    path.write_bytes(content)
    return storage_id


def resolve_path(storage_id: str):
    return get_settings().upload_storage_path / storage_id


def read_upload(storage_id: str) -> bytes:
    return resolve_path(storage_id).read_bytes()
