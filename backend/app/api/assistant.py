from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.ai.exceptions import AIUnavailableError
from app.ai.service import AIService
from app.ai.tool_registry import TOOLS, describe_tools
from app.api.deps import get_request_id
from app.auth.dependencies import CurrentUser, get_current_user
from app.db import get_db
from app.schemas.common import AppError, ErrorCode, ok

router = APIRouter(prefix="/api/assistant", tags=["assistant"])


@router.get("/tools")
async def list_tools(request_id: str = Depends(get_request_id), user: CurrentUser = Depends(get_current_user)):
    return ok(describe_tools(), request_id)


class ChatRequest(BaseModel):
    messages: list[dict]


@router.post("/chat")
async def chat(body: ChatRequest, request_id: str = Depends(get_request_id), user: CurrentUser = Depends(get_current_user)):
    ai = AIService()
    try:
        reply = await ai.chat(body.messages)
    except AIUnavailableError as exc:
        raise AppError(ErrorCode.AI_UNAVAILABLE, str(exc), 503) from exc
    return ok({"role": "assistant", "content": reply}, request_id)


class InvokeToolRequest(BaseModel):
    tool_name: str
    arguments: dict[str, Any] = {}
    approved: bool = False


@router.post("/tools/invoke")
async def invoke_tool(
    body: InvokeToolRequest,
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    tool = TOOLS.get(body.tool_name)
    if not tool:
        raise AppError(ErrorCode.NOT_FOUND, f"Unknown tool '{body.tool_name}'", 404)

    if tool.requires_approval and not body.approved:
        return ok(
            {
                "status": "REQUIRES_APPROVAL",
                "tool_name": tool.name,
                "risk_level": tool.risk_level.value,
                "message": f"'{tool.name}' is a {tool.risk_level.value.lower()}-risk action and requires explicit human "
                "approval. Resubmit with approved=true to proceed.",
            },
            request_id,
        )

    db = get_db()
    # Actor context tools may need (e.g. start_scan's triggered_by) is
    # supplied from the authenticated session, never trusted from the caller.
    context_defaults = {"triggered_by": user.user_id, "user_id": user.user_id, "uploaded_by": user.user_id}
    call_args = {**{k: v for k, v in context_defaults.items() if k not in body.arguments}, **body.arguments}
    try:
        result = await tool.handler(db=db, **call_args)
    except TypeError as exc:
        raise AppError(ErrorCode.VALIDATION_ERROR, f"Invalid arguments for tool '{tool.name}': {exc}", 400) from exc
    except ValueError as exc:
        raise AppError(ErrorCode.NOT_FOUND, str(exc), 404) from exc
    except NotImplementedError as exc:
        raise AppError(ErrorCode.VALIDATION_ERROR, str(exc), 400) from exc

    return ok({"status": "EXECUTED", "tool_name": tool.name, "result": result}, request_id)
