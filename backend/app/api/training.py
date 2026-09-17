"""Adaptive learning / Training UI backend (spec sections 16, 47).

Unknown configuration patterns captured during normalization are surfaced
here for human review. AI may propose a category (via /api/training/unknown
lazily calling the AI service), but only a human CONFIRM persists a mapping
-- an AI suggestion never becomes authoritative on its own (spec section 16).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.ai.exceptions import AIUnavailableError
from app.ai.service import AIService
from app.api.deps import get_request_id
from app.auth.dependencies import CurrentUser, get_current_user
from app.db import Collections, get_db
from app.rag.embedder import embed
from app.schemas.common import AppError, ErrorCode, ok
from app.utils.ids import new_training_mapping_id, utcnow_iso

router = APIRouter(tags=["training"])


@router.get("/api/training/unknown")
async def list_unknown_patterns(
    vendor: str | None = None,
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    db = get_db()
    query = {"status": "pending_review"}
    if vendor:
        query["vendor"] = vendor
    patterns = await db[Collections.UNKNOWN_PATTERNS].find(query, {"_id": 0}).sort("occurrence_count", -1).to_list(length=500)
    return ok(patterns, request_id)


class SuggestRequest(BaseModel):
    vendor: str
    raw_line: str


@router.post("/api/training/suggest")
async def ai_suggest(
    body: SuggestRequest,
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    """Asks the local LLM to propose a category/meaning for an unknown
    command. Returns AI_UNAVAILABLE if Ollama isn't connected -- never a
    fabricated suggestion."""
    db = get_db()
    ai = AIService()
    try:
        suggestion = await ai.interpret_unknown_syntax(raw_line=body.raw_line, vendor=body.vendor, db=db)
    except AIUnavailableError as exc:
        raise AppError(ErrorCode.AI_UNAVAILABLE, str(exc), 503) from exc

    await db[Collections.UNKNOWN_PATTERNS].update_one(
        {"vendor": body.vendor, "raw_line": body.raw_line},
        {"$set": {"ai_suggestion": suggestion}},
    )
    return ok(suggestion, request_id)


class ConfirmMappingRequest(BaseModel):
    vendor: str
    raw_line: str
    category: str
    ir_field_path: str  # e.g. "management.session_timeout_seconds"
    meaning: str
    decision: str = "confirm"  # confirm | reject | edit


@router.post("/api/training/mapping")
async def confirm_mapping(
    body: ConfirmMappingRequest,
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    db = get_db()
    mapping_id = new_training_mapping_id()
    mapping_doc = {
        "mapping_id": mapping_id,
        "vendor": body.vendor,
        "raw_line": body.raw_line,
        "category": body.category,
        "ir_field_path": body.ir_field_path,
        "meaning": body.meaning,
        "decision": body.decision,
        "confirmed_by": user.user_id,
        "confirmed_at": utcnow_iso(),
    }
    await db[Collections.TRAINING_MAPPINGS].insert_one(dict(mapping_doc))

    if body.decision == "confirm":
        await db[Collections.UNKNOWN_PATTERNS].update_many(
            {"vendor": body.vendor, "raw_line": body.raw_line},
            {"$set": {"status": "confirmed", "confirmed_mapping_id": mapping_id}},
        )
        # Embedding is what lets this confirmation generalize to future
        # *similar* (not just identical) unknown lines -- see
        # app/ai/similar_mappings.py. embed() has its own graceful fallback
        # and practically never raises, but this confirmation is a real
        # human-in-the-loop action that must succeed either way, so a failure
        # here degrades to storing the example without an embedding rather
        # than blocking the confirmation.
        try:
            line_embedding = embed(body.raw_line)
        except Exception:
            line_embedding = None

        await db[Collections.TRAINING_EXAMPLES].insert_one(
            {
                "vendor": body.vendor,
                "raw_line": body.raw_line,
                "category": body.category,
                "ir_field_path": body.ir_field_path,
                "meaning": body.meaning,
                "source": "human_confirmed",
                "embedding": line_embedding,
                "created_at": utcnow_iso(),
            }
        )
    elif body.decision == "reject":
        await db[Collections.UNKNOWN_PATTERNS].update_many(
            {"vendor": body.vendor, "raw_line": body.raw_line}, {"$set": {"status": "rejected"}}
        )

    try:
        from app.blockchain.service import record_event

        await record_event(
            db, audit_id=mapping_id, device_id="N/A", actor_id=user.user_id,
            event_type="TRAINING_MAPPING_APPROVED",
        )
    except Exception:
        pass

    return ok(mapping_doc, request_id)


class FeedbackRequest(BaseModel):
    mapping_id: str
    feedback: str
    correct: bool


@router.post("/api/training/feedback")
async def training_feedback(
    body: FeedbackRequest,
    request_id: str = Depends(get_request_id),
    user: CurrentUser = Depends(get_current_user),
):
    db = get_db()
    await db[Collections.TRAINING_MAPPINGS].update_one(
        {"mapping_id": body.mapping_id},
        {"$push": {"feedback": {"user_id": user.user_id, "text": body.feedback, "correct": body.correct, "at": utcnow_iso()}}},
    )
    return ok({"mapping_id": body.mapping_id, "recorded": True}, request_id)
