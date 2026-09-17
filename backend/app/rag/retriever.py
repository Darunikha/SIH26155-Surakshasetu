"""Retrieval for AI explanation/remediation prompts (spec section 39):
finding -> control -> relevant knowledge -> context string. Falls back to
the local authored knowledge document directly (no vector search) if
Pinecone is unavailable, so remediation generation still gets some grounding
context even without network access -- still never fabricated, since it's
reading real authored content either way.
"""
from __future__ import annotations

from app.rag.embedder import embed
from app.rag.ingest import load_documents


async def retrieve_context(control_id: str, top_k: int = 2) -> str:
    try:
        from app.rag.pinecone_client import query

        vector = embed(control_id)
        matches = query(vector, top_k=top_k)
        if matches:
            return "\n\n".join(f"- {m['metadata'].get('text', '')}" for m in matches)
    except Exception:
        pass

    # Fallback: direct lookup in the authored knowledge base by control_id.
    for doc in load_documents():
        if doc["control_id"] == control_id:
            return f"- {doc['text']}"
    return ""
