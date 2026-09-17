from __future__ import annotations

from pydantic import BaseModel, EmailStr

from app.auth.roles import Role


class UserDocument(BaseModel):
    user_id: str
    email: EmailStr
    password_hash: str
    full_name: str
    role: Role
    created_at: str


class UserPublic(BaseModel):
    user_id: str
    email: EmailStr
    full_name: str
    role: Role
