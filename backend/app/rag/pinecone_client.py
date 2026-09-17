"""Pinecone vector store client for the security knowledge base (spec
section 39). Uses the API key from settings/.env -- never hard-coded."""
from __future__ import annotations

from app.config import get_settings
from app.rag.embedder import embedding_dimension

_pc_client = None
_index = None


def _get_pinecone_client():
    global _pc_client
    if _pc_client is None:
        from pinecone import Pinecone

        settings = get_settings()
        if not settings.pinecone_api_key:
            raise RuntimeError("PINECONE_API_KEY is not configured")
        _pc_client = Pinecone(api_key=settings.pinecone_api_key)
    return _pc_client


def get_index():
    global _index
    if _index is not None:
        return _index

    from pinecone import ServerlessSpec

    settings = get_settings()
    pc = _get_pinecone_client()
    existing = [i["name"] for i in pc.list_indexes()]
    if settings.pinecone_index_name not in existing:
        pc.create_index(
            name=settings.pinecone_index_name,
            dimension=embedding_dimension(),
            metric="cosine",
            spec=ServerlessSpec(cloud=settings.pinecone_cloud, region=settings.pinecone_region),
        )
    _index = pc.Index(settings.pinecone_index_name)
    return _index


def upsert_documents(documents: list[dict]) -> int:
    """documents: [{"id": str, "values": list[float], "metadata": dict}]"""
    index = get_index()
    index.upsert(vectors=documents)
    return len(documents)


def query(vector: list[float], top_k: int = 3) -> list[dict]:
    index = get_index()
    result = index.query(vector=vector, top_k=top_k, include_metadata=True)
    return [
        {"id": m["id"], "score": m["score"], "metadata": m.get("metadata", {})}
        for m in result.get("matches", [])
    ]
