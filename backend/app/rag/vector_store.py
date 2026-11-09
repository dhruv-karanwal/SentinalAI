"""Vector table behind one interface: SQLite fallback (default) or pgvector (``lite`` profile).

Rows: ``(collection, item_id, text, meta, embedding)``. Collections keep the
ATT&CK index (``attack``) apart from agent vector memory (``memory:<session>``).

- :class:`SqliteVectorStore`: a table in ``data/platform/vectors.db``;
  float32 blobs, exact cosine search with numpy (vectors are normalised).
  Exact search over ~1-2k chunks is milliseconds; no ANN index needed.
- :class:`PgVectorStore`: PostgreSQL + pgvector (``SENTINEL_DB_URL``),
  ``vector(dim)`` column, ``<=>`` cosine distance. psycopg and pgvector are
  imported lazily; integration tests run only with the compose services.

Ties in score are broken by ``item_id`` so results are deterministic.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import numpy as np

from app.rag.embedding import Matrix


@dataclass(frozen=True)
class VectorItem:
    item_id: str
    text: str
    meta: dict[str, Any]


@dataclass(frozen=True)
class Hit:
    item_id: str
    score: float
    text: str
    meta: dict[str, Any]


class VectorStore(Protocol):
    def upsert(self, collection: str, items: list[VectorItem], vectors: Matrix) -> int: ...

    def search(self, collection: str, vector: Matrix, k: int) -> list[Hit]: ...

    def count(self, collection: str) -> int: ...

    def clear(self, collection: str) -> None: ...


class SqliteVectorStore:
    def __init__(self, path: str | Path = ":memory:") -> None:
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.RLock()
        with self._lock:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS vectors (collection TEXT NOT NULL, item_id TEXT NOT NULL, "
                "text TEXT NOT NULL, meta TEXT NOT NULL, dim INTEGER NOT NULL, embedding BLOB NOT NULL, "
                "PRIMARY KEY (collection, item_id))")
            self._conn.commit()

    def upsert(self, collection: str, items: list[VectorItem], vectors: Matrix) -> int:
        if len(items) != len(vectors):
            raise ValueError("items and vectors differ in length")
        with self._lock:
            self._conn.executemany(
                "INSERT OR REPLACE INTO vectors VALUES (?, ?, ?, ?, ?, ?)",
                [(collection, it.item_id, it.text, json.dumps(it.meta, sort_keys=True),
                  int(v.shape[0]), np.asarray(v, dtype=np.float32).tobytes())
                 for it, v in zip(items, vectors)])
            self._conn.commit()
        return len(items)

    def search(self, collection: str, vector: Matrix, k: int) -> list[Hit]:
        with self._lock:
            rows = self._conn.execute("SELECT item_id, text, meta, embedding FROM vectors "
                                      "WHERE collection = ?", (collection,)).fetchall()
        if not rows or k < 1:
            return []
        mat = np.stack([np.frombuffer(r[3], dtype=np.float32) for r in rows])
        q = np.asarray(vector, dtype=np.float32).reshape(-1)
        scores = mat @ q
        order = sorted(range(len(rows)), key=lambda i: (-float(scores[i]), rows[i][0]))[:k]
        return [Hit(rows[i][0], float(scores[i]), rows[i][1], json.loads(rows[i][2])) for i in order]

    def count(self, collection: str) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) FROM vectors WHERE collection = ?",
                                     (collection,)).fetchone()
        return int(row[0])

    def clear(self, collection: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM vectors WHERE collection = ?", (collection,))
            self._conn.commit()


class PgVectorStore:  # pragma: no cover - needs the docker-compose `lite` profile
    def __init__(self, dsn: str, dim: int) -> None:
        import psycopg
        from pgvector.psycopg import register_vector

        self._conn = psycopg.connect(dsn, autocommit=True)
        self._conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
        register_vector(self._conn)
        self._conn.execute(
            f"CREATE TABLE IF NOT EXISTS rag_vectors (collection TEXT NOT NULL, item_id TEXT NOT NULL, "
            f"text TEXT NOT NULL, meta JSONB NOT NULL, embedding vector({int(dim)}) NOT NULL, "
            f"PRIMARY KEY (collection, item_id))")

    def upsert(self, collection: str, items: list[VectorItem], vectors: Matrix) -> int:
        with self._conn.cursor() as cur:
            cur.executemany(
                "INSERT INTO rag_vectors VALUES (%s, %s, %s, %s, %s) ON CONFLICT (collection, item_id) "
                "DO UPDATE SET text = EXCLUDED.text, meta = EXCLUDED.meta, embedding = EXCLUDED.embedding",
                [(collection, it.item_id, it.text, json.dumps(it.meta), np.asarray(v, dtype=np.float32))
                 for it, v in zip(items, vectors)])
        return len(items)

    def search(self, collection: str, vector: Matrix, k: int) -> list[Hit]:
        q = np.asarray(vector, dtype=np.float32).reshape(-1)
        rows = self._conn.execute(
            "SELECT item_id, text, meta, 1 - (embedding <=> %s) AS score FROM rag_vectors "
            "WHERE collection = %s ORDER BY embedding <=> %s, item_id LIMIT %s",
            (q, collection, q, k)).fetchall()
        return [Hit(r[0], float(r[3]), r[1], r[2] if isinstance(r[2], dict) else json.loads(r[2]))
                for r in rows]

    def count(self, collection: str) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM rag_vectors WHERE collection = %s",
                                 (collection,)).fetchone()
        return int(row[0]) if row else 0

    def clear(self, collection: str) -> None:
        self._conn.execute("DELETE FROM rag_vectors WHERE collection = %s", (collection,))


def open_vector_store(data_dir: str | Path, dim: int) -> VectorStore:
    """pgvector when SENTINEL_DB_URL is set (lite profile), else the SQLite fallback table."""
    dsn = os.environ.get("SENTINEL_DB_URL")
    if dsn:
        return PgVectorStore(dsn, dim)
    return SqliteVectorStore(Path(data_dir) / "vectors.db")
