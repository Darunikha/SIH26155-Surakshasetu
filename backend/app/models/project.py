from __future__ import annotations

from pydantic import BaseModel


class ProjectDocument(BaseModel):
    project_id: str
    name: str
    description: str = ""
    owner_id: str
    created_at: str
