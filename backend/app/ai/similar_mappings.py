"""Retrieval of previously human-confirmed unknown-syntax mappings, keyed by
semantic similarity of the raw config line -- not just an exact-line lookup.

This is what closes the adaptive-learning loop end-to-end (spec sections 16,
47): a human confirming one line's meaning should measurably help future
*similar* (not just identical) unknown lines, without spending another LLM
call or waiting on another human confirmation.

Degrades gracefully: if Mongo has no confirmed examples yet for this vendor,
or embeddings can't be computed, this simply finds nothing and the caller
(app/ai/service.py's interpret_unknown_syntax) falls through to its existing
LLM-prompt path -- never raises, never fabricates a match.
"""
from __future__ import annotations

from app.db import Collections
from app.rag.embedder import embed, embedding_backend_name

# Real sentence-transformers embeddings are genuinely semantic, so a high bar
# (0.85 cosine) is a defensible "this is essentially the same question"
# threshold -- false positives above that are rare.
#
# The fallback hashing embedder (app/rag/embedder.py) is bag-of-words token
# overlap, not semantic similarity: it can still recognize "the same line
# with one token changed" (most tokens still land in the same hash buckets),
# but it has no notion of synonyms or paraphrasing, so its scores for
# genuinely-similar-but-differently-worded lines run systematically lower
# than a real embedding model's would. A lower bar (0.60) is used for it so
# the retrieval step isn't effectively dead whenever sentence-transformers
# isn't installed/cached -- it still only fires on lines that share most of
# their vocabulary, which is a real (if weaker) similarity signal.
SIMILARITY_THRESHOLD_SEMANTIC = 0.85
SIMILARITY_THRESHOLD_FALLBACK = 0.60


def _threshold() -> float:
    return SIMILARITY_THRESHOLD_FALLBACK if "fallback" in embedding_backend_name() else SIMILARITY_THRESHOLD_SEMANTIC


def _cosine(a: list[float], b: list[float]) -> float:
    # app/rag/embedder.py's embed() always returns L2-normalized vectors, so
    # a plain dot product is already cosine similarity.
    return sum(x * y for x, y in zip(a, b))


async def find_similar_confirmed_mapping(db, *, vendor: str, raw_line: str) -> dict | None:
    """Returns the best-matching human-confirmed TRAINING_EXAMPLES document
    for this (vendor, raw_line) if its similarity clears the threshold for
    the currently active embedding backend, else None.

    Only examples with a stored `embedding` are considered -- examples
    written before this field existed are simply skipped, not treated as an
    error.
    """
    examples = (
        await db[Collections.TRAINING_EXAMPLES]
        .find({"vendor": vendor, "embedding": {"$exists": True, "$ne": None}}, {"_id": 0})
        .to_list(length=1000)
    )
    if not examples:
        return None

    try:
        query_vector = embed(raw_line)
    except Exception:
        return None

    threshold = _threshold()
    best_score = 0.0
    best_example: dict | None = None
    for example in examples:
        score = _cosine(query_vector, example["embedding"])
        if score > best_score:
            best_score = score
            best_example = example

    if best_example is not None and best_score >= threshold:
        return {**best_example, "similarity_score": round(best_score, 4)}
    return None
