"""FastAPI dependencies for authentication and role-based access control."""
from __future__ import annotations

from fastapi import Depends, Header
from pydantic import BaseModel

from app.auth.roles import Role
from app.auth.security import decode_access_token
from app.schemas.common import AppError, ErrorCode


class CurrentUser(BaseModel):
    user_id: str
    email: str
    role: Role


async def get_current_user(authorization: str | None = Header(default=None)) -> CurrentUser:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise AppError(ErrorCode.UNAUTHORIZED, "Missing or malformed Authorization header", 401)

    token = authorization.split(" ", 1)[1].strip()
    payload = decode_access_token(token)
    if not payload:
        raise AppError(ErrorCode.UNAUTHORIZED, "Invalid or expired token", 401)

    try:
        role = Role(payload["role"])
    except ValueError as exc:
        raise AppError(ErrorCode.UNAUTHORIZED, "Invalid role in token", 401) from exc

    return CurrentUser(user_id=payload["sub"], email=payload["email"], role=role)


def require_roles(*allowed: Role):
    async def _dep(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if user.role not in allowed:
            raise AppError(
                ErrorCode.FORBIDDEN,
                f"Role '{user.role.value}' is not permitted to perform this action",
                403,
            )
        return user

    return _dep
