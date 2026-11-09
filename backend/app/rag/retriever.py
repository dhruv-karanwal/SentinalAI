"""ATT&CK retriever: index the chunks, search by text, evaluate on the frozen relevance set.

``search`` returns distinct techniques (a technique's chunks count once, at
their best score), ranked by cosine similarity, ties by technique id.

Relevance evaluation (:func:`evaluate`) reads the hand-written set in
``experiments/rag/attack_relevance_set.json`` (committed before the first
retrieval run and never edited after seeing results) and reports recall@k
for k = 1, 3, 5: the share of queries with at least one expected technique
id among the top-k distinct techniques.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.intel.attack import AttackKB
from app.rag.chunks import attack_chunks
from app.rag.embedding import Embedder
from app.rag.vector_store import VectorItem, VectorStore

ATTACK_COLLECTION = "attack"
DEFAULT_RELEVANCE_SET = Path(__file__).resolve().parents[3] / "experiments" / "rag" / "attack_relevance_set.json"
RECALL_KS = (1, 3, 5)


class AttackRetriever:
    def __init__(self, store: VectorStore, embedder: Embedder, collection: str = ATTACK_COLLECTION):
        self.store = store
        self.embedder = embedder
        self.collection = collection

    def index(self, kb: AttackKB, batch: int = 64) -> int:
        chunks = attack_chunks(kb)
        self.store.clear(self.collection)
        n = 0
        for i in range(0, len(chunks), batch):
            part = chunks[i:i + batch]
            vecs = self.embedder.embed_passages([c.text for c in part])
            n += self.store.upsert(self.collection, [
                VectorItem(c.chunk_id, c.text, {"technique_id": c.technique_id, "name": c.name,
                                                 "tactics": list(c.tactics)}) for c in part], vecs)
        return n

    def search(self, text: str, k: int = 5) -> list[dict[str, Any]]:
        if not text.strip() or k < 1:
            return []
        hits = self.store.search(self.collection, self.embedder.embed_query(text)[0], k * 4)
        best: dict[str, dict[str, Any]] = {}
        for h in hits:
            tid = str(h.meta["technique_id"])
            if tid not in best or h.score > best[tid]["score"]:
                best[tid] = {"technique_id": tid, "name": h.meta["name"], "tactics": h.meta["tactics"],
                             "score": h.score, "chunk_id": h.item_id, "text": h.text}
        ranked = sorted(best.values(), key=lambda r: (-r["score"], r["technique_id"]))
        return ranked[:k]


def load_relevance_set(path: str | Path = DEFAULT_RELEVANCE_SET) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    queries = data["queries"]
    if len(queries) < 20:
        raise ValueError("the relevance set needs at least 20 queries")
    ids = [q["id"] for q in queries]
    if len(set(ids)) != len(ids):
        raise ValueError("relevance set query ids repeat")
    for q in queries:
        if not q["text"].strip() or not q["expected"]:
            raise ValueError(f"query {q['id']} needs text and expected ids")
    return dict(data)


def evaluate(retriever: AttackRetriever, relevance: dict[str, Any],
             kb: AttackKB | None = None) -> dict[str, Any]:
    kmax = max(RECALL_KS)
    per_query = []
    for q in relevance["queries"]:
        expected = set(q["expected"])
        unknown = sorted(e for e in expected if kb is not None and kb.get(e) is None)
        got = [r["technique_id"] for r in retriever.search(q["text"], kmax)]
        rank = next((i + 1 for i, t in enumerate(got) if t in expected), None)
        per_query.append({"id": q["id"], "rank": rank, "retrieved": got,
                          "expected": sorted(expected), "expected_not_in_kb": unknown})
    n = len(per_query)
    recall = {f"recall@{k}": sum(1 for p in per_query if p["rank"] is not None and p["rank"] <= k) / n
              for k in RECALL_KS}
    return {"relevance_set": relevance.get("name"), "queries": n, **recall,
            "hits": {f"@{k}": sum(1 for p in per_query if p["rank"] is not None and p["rank"] <= k)
                     for k in RECALL_KS},
            "per_query": per_query}
