"""Local text embeddings: bge-small-en-v1.5 through fastembed, offline only.

:class:`FastEmbedEmbedder` loads the model from the local cache
(``data/models/fastembed``) with ``local_files_only=True`` after setting
``HF_HUB_OFFLINE`` / ``TRANSFORMERS_OFFLINE``, so it never downloads. If the
model is not in the cache it raises :class:`EmbeddingUnavailable`; callers
report that instead of falling back to anything else.

Queries use fastembed's ``query_embed`` (bge's retrieval instruction prefix),
documents ``passage_embed``. Vectors are L2-normalised, so cosine similarity
is a dot product.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Protocol

import numpy as np

DEFAULT_MODEL = "BAAI/bge-small-en-v1.5"
DEFAULT_CACHE = Path(__file__).resolve().parents[3] / "data" / "models" / "fastembed"
DIM = 384

Matrix = np.ndarray[Any, np.dtype[np.float32]]


class EmbeddingUnavailable(Exception):
    """The local embedding model could not be loaded (it is never downloaded)."""


class Embedder(Protocol):
    model_id: str
    dim: int

    def embed_passages(self, texts: Sequence[str]) -> Matrix: ...

    def embed_query(self, text: str) -> Matrix: ...


def normalize(m: Any) -> Matrix:
    arr = np.asarray(m, dtype=np.float32)
    if arr.ndim == 1:
        arr = arr[None, :]
    norms = np.linalg.norm(arr, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    out: Matrix = arr / norms
    return out


class FastEmbedEmbedder:
    def __init__(self, cache_dir: str | Path = DEFAULT_CACHE, model: str = DEFAULT_MODEL) -> None:
        os.environ["HF_HUB_OFFLINE"] = "1"
        os.environ["TRANSFORMERS_OFFLINE"] = "1"
        try:
            from fastembed import TextEmbedding

            self._model = TextEmbedding(model, cache_dir=str(cache_dir), local_files_only=True)
        except Exception as exc:  # any load failure: report it, never download
            raise EmbeddingUnavailable(f"cannot load {model} from {cache_dir} offline: {exc}") from exc
        self.model_id = model
        self.dim = DIM

    def embed_passages(self, texts: Sequence[str]) -> Matrix:
        return normalize(list(self._model.passage_embed(list(texts))))

    def embed_query(self, text: str) -> Matrix:
        return normalize(list(self._model.query_embed([text])))
