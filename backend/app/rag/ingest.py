"""One-time (or re-run-on-change) ingestion of the authored knowledge base
into Pinecone (spec section 39). Run as: `python -m app.rag.ingest`."""
from __future__ import annotations

import json
from pathlib import Path

from app.rag.embedder import embed_batch
from app.rag.pinecone_client import upsert_documents

KNOWLEDGE_FILE = Path(__file__).resolve().parents[3] / "rag" / "knowledge" / "controls_knowledge.json"


def load_documents() -> list[dict]:
    with open(KNOWLEDGE_FILE, encoding="utf-8") as f:
        return json.load(f)


def run_ingest() -> int:
    docs = load_documents()
    texts = [f"{d['title']}: {d['text']}" for d in docs]
    vectors = embed_batch(texts)

    records = [
        {
            "id": d["control_id"],
            "values": vec,
            "metadata": {"control_id": d["control_id"], "title": d["title"], "text": d["text"]},
        }
        for d, vec in zip(docs, vectors)
    ]
    return upsert_documents(records)


if __name__ == "__main__":
    count = run_ingest()
    print(f"Ingested {count} knowledge documents into Pinecone.")
