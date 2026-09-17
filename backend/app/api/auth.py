from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, EmailStr

from app.api.deps import get_request_id
from app.auth.roles import Role
from app.auth.security import create_access_token, hash_password, verify_password
from app.db import Collections, get_db
from app.schemas.common import AppError, ErrorCode, ok
from app.utils.ids import new_user_id, utcnow_iso

router = APIRouter(prefix="/api/auth", tags=["auth"])


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    role: Role = Role.VIEWER


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


@router.post("/register")
async def register(body: RegisterRequest, request_id: str = Depends(get_request_id)):
    db = get_db()
    existing = await db[Collections.USERS].find_one({"email": body.email})
    if existing:
        raise AppError(ErrorCode.CONFLICT, "A user with this email already exists", 409)

    # Self-registration must never grant ADMIN -- that role sees every user's
    # projects (app/auth/access.py), so a client-supplied role of "admin" here
    # would be an unauthenticated privilege escalation. Admin status can only
    # be granted by an existing admin, out-of-band (e.g. directly in the DB);
    # there is no self-service or API path to it.
    requested_role = body.role if body.role != Role.ADMIN else Role.VIEWER

    user_id = new_user_id()
    doc = {
        "user_id": user_id,
        "email": body.email,
        "password_hash": hash_password(body.password),
        "full_name": body.full_name,
        "role": requested_role.value,
        "created_at": utcnow_iso(),
    }
    await db[Collections.USERS].insert_one(doc)
    token = create_access_token(user_id=user_id, email=body.email, role=requested_role.value)
    return ok(
        {
            "token": token,
            "user": {
                "user_id": user_id,
                "email": body.email,
                "full_name": body.full_name,
                "role": requested_role.value,
            },
        },
        request_id,
    )


@router.post("/login")
async def login(body: LoginRequest, request_id: str = Depends(get_request_id)):
    db = get_db()
    user = await db[Collections.USERS].find_one({"email": body.email})
    if not user or not verify_password(body.password, user["password_hash"]):
        raise AppError(ErrorCode.UNAUTHORIZED, "Invalid email or password", 401)

    token = create_access_token(user_id=user["user_id"], email=user["email"], role=user["role"])
    return ok(
        {
            "token": token,
            "user": {
                "user_id": user["user_id"],
                "email": user["email"],
                "full_name": user["full_name"],
                "role": user["role"],
            },
        },
        request_id,
    )
