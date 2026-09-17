"""Pluggable embedding backend for RAG (spec section 39).

Prefers `sentence-transformers` (all-MiniLM-L6-v2) when installed/cached.
Otherwise falls back to a deterministic local hashing-vector embedder so
the RAG pipeline is genuinely functional offline too -- this fallback is
weaker than a real embedding model and is clearly labeled as such; it is
NOT a substitute for a real embedding model in production.
"""
from __future__ import annotations

import hashlib
import math
import re

_FALLBACK_DIM = 256

_sentence_transformer_model = None
_sentence_transformer_checked = False


def _try_load_sentence_transformer():
    global _sentence_transformer_model, _sentence_transformer_checked
    if _sentence_transformer_checked:
        return _sentence_transformer_model
    _sentence_transformer_checked = True
    try:
        from sentence_transformers import SentenceTransformer

        _sentence_transformer_model = SentenceTransformer("all-MiniLM-L6-v2")
    except Exception:
        _sentence_transformer_model = None
    return _sentence_transformer_model


def embedding_backend_name() -> str:
    return "sentence-transformers/all-MiniLM-L6-v2" if _try_load_sentence_transformer() else "local-hashing-fallback"


def embedding_dimension() -> int:
    model = _try_load_sentence_transformer()
    if model is not None:
        return model.get_sentence_embedding_dimension()
    return _FALLBACK_DIM


_WORD_RE = re.compile(r"[a-z0-9]+")


def _hashing_embed(text: str) -> list[float]:
    """Deterministic bag-of-words hashing embedding: each token hashes into
    one of _FALLBACK_DIM buckets, then the vector is L2-normalized. Weaker
    semantically than a trained model, but fully deterministic, dependency-free,
    and genuinely functional for exact/near-term keyword retrieval."""
    vector = [0.0] * _FALLBACK_DIM
    tokens = _WORD_RE.findall(text.lower())
    for token in tokens:
        bucket = int(hashlib.sha256(token.encode("utf-8")).hexdigest(), 16) % _FALLBACK_DIM
        vector[bucket] += 1.0

    norm = math.sqrt(sum(v * v for v in vector))
    if norm > 0:
        vector = [v / norm for v in vector]
    return vector


def embed(text: str) -> list[float]:
    model = _try_load_sentence_transformer()
    if model is not None:
        return model.encode(text, normalize_embeddings=True).tolist()
    return _hashing_embed(text)


def embed_batch(texts: list[str]) -> list[list[float]]:
    model = _try_load_sentence_transformer()
    if model is not None:
        return model.encode(texts, normalize_embeddings=True).tolist()
    return [_hashing_embed(t) for t in texts]
