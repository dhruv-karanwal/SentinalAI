"""ATT&CK retriever: index the chunks, search by text, evaluate on the frozen relevance set.

``search`` returns distinct techniques (a technique's chunks count once, at
their best score), ties by technique id. Modes (C1 fix, 2026-11-10):

- ``dense`` (the C1 original): cosine similarity of bge-small vectors;
- ``lexical``: BM25 over the chunk texts (:mod:`app.rag.lexical`), only
  techniques with at least one query term, score divided by the best;
- ``hybrid``: ``alpha * dense' + (1 - alpha) * lexical'`` per technique,
  where ``dense'`` is the min-max normalised cosine over every technique
  and ``lexical'`` the BM25 score divided by the query's best (0 without a
  term). ``alpha = 0.5`` (:data:`DEFAULT_ALPHA`), equal weights, chosen
  before the run and not tuned on the relevance set.

The chunks already hold the technique id, name and tactics in their text
(:mod:`app.rag.chunks`), so both scores see them.

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
from app.rag.lexical import Bm25Index
from app.rag.vector_store import VectorItem, VectorStore

ATTACK_COLLECTION = "attack"
DEFAULT_RELEVANCE_SET = Path(__file__).resolve().parents[3] / "experiments" / "rag" / "attack_relevance_set.json"
RECALL_KS = (1, 3, 5)
MODES = ("dense", "lexical", "hybrid")
DEFAULT_ALPHA = 0.5


class AttackRetriever:
    def __init__(self, store: VectorStore, embedder: Embedder, collection: str = ATTACK_COLLECTION,
                 *, mode: str = "dense", kb: AttackKB | None = None, alpha: float = DEFAULT_ALPHA):
        if mode not in MODES:
            raise ValueError(f"unknown retrieval mode {mode!r}; known: {', '.join(MODES)}")
        if not 0.0 <= alpha <= 1.0:
            raise ValueError("alpha must be in [0, 1]")
        if mode != "dense" and kb is None:
            raise ValueError(f"mode {mode!r} needs the ATT&CK KB for the lexical index")
        self.store = store
        self.embedder = embedder
        self.collection = collection
        self.mode = mode
        self.alpha = alpha
        self._chunks = {c.chunk_id: c for c in attack_chunks(kb)} if kb is not None else {}
        self._bm25 = Bm25Index({cid: c.text for cid, c in self._chunks.items()}) if kb is not None else None

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
        if self.mode != "dense":
            return self._search_blended(text, k)
        hits = self.store.search(self.collection, self.embedder.embed_query(text)[0], k * 4)
        best: dict[str, dict[str, Any]] = {}
        for h in hits:
            tid = str(h.meta["technique_id"])
            if tid not in best or h.score > best[tid]["score"]:
                best[tid] = {"technique_id": tid, "name": h.meta["name"], "tactics": h.meta["tactics"],
                             "score": h.score, "chunk_id": h.item_id, "text": h.text}
        ranked = sorted(best.values(), key=lambda r: (-r["score"], r["technique_id"]))
        return ranked[:k]

    def _search_blended(self, text: str, k: int) -> list[dict[str, Any]]:
        assert self._bm25 is not None
        chunk_of: dict[str, str] = {}
        lex: dict[str, float] = {}
        for cid, score in self._bm25.scores(text).items():
            tid = self._chunks[cid].technique_id
            if score > lex.get(tid, -1.0):
                lex[tid], chunk_of[tid] = score, cid
        top_lex = max(lex.values(), default=0.0)
        lex_n = {t: v / top_lex for t, v in lex.items()} if top_lex > 0 else {}
        dense: dict[str, float] = {}
        dense_chunk: dict[str, str] = {}
        if self.mode == "hybrid":
            n = self.store.count(self.collection)
            for h in self.store.search(self.collection, self.embedder.embed_query(text)[0], n):
                tid = str(h.meta["technique_id"])
                if tid not in dense or h.score > dense[tid]:
                    dense[tid], dense_chunk[tid] = h.score, h.item_id
            lo, hi = min(dense.values(), default=0.0), max(dense.values(), default=0.0)
            dense = {t: ((v - lo) / (hi - lo) if hi > lo else 0.0) for t, v in dense.items()}
            scores = {t: self.alpha * dense.get(t, 0.0) + (1 - self.alpha) * lex_n.get(t, 0.0)
                      for t in set(dense) | set(lex_n)}
        else:
            scores = lex_n
        ranked = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))[:k]
        out = []
        for tid, score in ranked:
            # the excerpt: the chunk with the best dense score, else the best lexical one
            # (fix 2026-11-12: chunk_id is the chosen chunk, not a leftover loop variable that was
            # unbound when BM25 matched nothing)
            chosen = dense_chunk[tid] if tid in dense_chunk else chunk_of[tid]
            c = self._chunks[chosen]
            out.append({"technique_id": tid, "name": c.name, "tactics": list(c.tactics),
                        "score": round(score, 6), "chunk_id": chosen, "text": c.text})
        return out


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
