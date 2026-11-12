"""Wave C (C1): ATT&CK chunks, local embeddings, vector table, retriever, search_attack tool.

No network and no model: every agent test uses FakeClient. ``HashEmbedder``
below is a deterministic bag-of-words test double for unit tests only; the
real bge-small model is exercised by ``test_bge_small_loads_offline`` when
the local cache is present.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from app.agent.rag_tool import AttackSearchTool
from app.intel.attack import AttackKB
from app.rag.chunks import attack_chunks, clean
from app.rag.embedding import DEFAULT_CACHE, EmbeddingUnavailable, FastEmbedEmbedder, normalize
from app.rag.retriever import (
    DEFAULT_RELEVANCE_SET,
    AttackRetriever,
    evaluate,
    load_relevance_set,
)
from app.rag.vector_store import SqliteVectorStore, VectorItem

REPO = Path(__file__).resolve().parents[2]
REAL_STIX = REPO / "data" / "raw" / "mitre" / "enterprise-attack.json"
# sha256 of the relevance set as committed BEFORE the first retrieval run (LF line endings).
# It must never change after results are seen; a new set gets a new file and constant.
RELEVANCE_SET_SHA256 = "f86df5d450d4324312e3f28968e6d5a0678c2a527e364297ccfacde205e5b8e2"


class HashEmbedder:
    """Deterministic bag-of-words embedding for tests (not a model)."""

    model_id = "test-hash"
    dim = 64

    def _vec(self, text: str) -> np.ndarray[Any, Any]:
        v = np.zeros(self.dim, dtype=np.float32)
        for tok in re.findall(r"[a-z0-9]+", text.lower()):
            v[int(hashlib.md5(tok.encode()).hexdigest(), 16) % self.dim] += 1.0
        return v

    def embed_passages(self, texts: Any) -> Any:
        return normalize(np.stack([self._vec(t) for t in texts]))

    def embed_query(self, text: str) -> Any:
        return normalize(self._vec(text))


@pytest.fixture()
def kb(samples_dir: Path) -> AttackKB:
    return AttackKB.from_stix(samples_dir / "synthetic_attack_stix.json")


@pytest.fixture()
def retriever(kb: AttackKB) -> AttackRetriever:
    r = AttackRetriever(SqliteVectorStore(), HashEmbedder())
    r.index(kb)
    return r


# ---------------------------------------------------------------- RAG

def test_chunks_carry_id_name_tactics_description(kb: AttackKB) -> None:
    chunks = attack_chunks(kb)
    assert {c.technique_id for c in chunks} == set(kb.techniques)
    first = next(c for c in chunks if c.technique_id == "T1110")
    assert first.text.startswith("T1110 Brute Force\nTactics: Credential Access")
    assert "(Citation:" not in first.text
    assert clean("Adversaries guess. (Citation: Foo 2020) More.") == "Adversaries guess. More."


def test_long_descriptions_split_at_paragraphs(kb: AttackKB) -> None:
    from app.rag.chunks import _pieces
    text = "\n\n".join(["a" * 50, "b" * 50, "c" * 50])
    assert _pieces(text, 110) == ["a" * 50 + "\n\n" + "b" * 50, "c" * 50]
    assert _pieces("one. two. three.", 6) == ["one.", "two.", "three."]


def test_sqlite_vector_table_roundtrip_and_ties() -> None:
    store = SqliteVectorStore()
    vecs = normalize(np.array([[1, 0], [1, 0], [0, 1]], dtype=np.float32))
    store.upsert("c", [VectorItem("b", "B", {}), VectorItem("a", "A", {}), VectorItem("z", "Z", {})], vecs)
    hits = store.search("c", normalize(np.array([1, 0]))[0], 2)
    assert [h.item_id for h in hits] == ["a", "b"]  # equal scores: by item id
    assert store.count("c") == 3 and store.search("other", vecs[0], 3) == []
    store.clear("c")
    assert store.count("c") == 0


def test_retriever_dedupes_techniques(retriever: AttackRetriever) -> None:
    got = retriever.search("password guessing brute force", 3)
    ids = [g["technique_id"] for g in got]
    assert len(ids) == len(set(ids)) and ids
    assert retriever.search("   ", 3) == []


def test_evaluate_recall_at_k(retriever: AttackRetriever, kb: AttackKB) -> None:
    rel = {"name": "t", "queries": [
        {"id": "a", "text": "brute force password guessing", "expected": ["T1110", "T1110.001"]},
        {"id": "b", "text": "zzzz", "expected": ["T9999"]}]}
    res = evaluate(retriever, rel, kb)
    assert res["queries"] == 2 and res["recall@5"] == 0.5
    assert res["per_query"][1]["expected_not_in_kb"] == ["T9999"]


def test_relevance_set_is_valid_and_frozen() -> None:
    data = load_relevance_set()
    assert len(data["queries"]) >= 20
    text = DEFAULT_RELEVANCE_SET.read_bytes().replace(b"\r\n", b"\n")
    assert hashlib.sha256(text).hexdigest() == RELEVANCE_SET_SHA256


def test_relevance_set_rejects_small_sets(tmp_path: Path) -> None:
    p = tmp_path / "r.json"
    p.write_text(json.dumps({"queries": [{"id": "a", "text": "x", "expected": ["T1"]}]}), "utf-8")
    with pytest.raises(ValueError, match="20"):
        load_relevance_set(p)


@pytest.mark.skipif(not REAL_STIX.exists(), reason="real ATT&CK bundle not present")
def test_relevance_set_ids_exist_in_the_real_bundle() -> None:
    kb = AttackKB.from_stix(REAL_STIX)
    missing = [e for q in load_relevance_set()["queries"] for e in q["expected"] if kb.get(e) is None]
    assert missing == []


@pytest.mark.skipif(not (DEFAULT_CACHE / "models--Qdrant--bge-small-en-v1.5-onnx-Q").exists(),
                    reason="local bge-small cache not present")
def test_bge_small_loads_offline() -> None:
    emb = FastEmbedEmbedder()
    v = emb.embed_passages(["ssh brute force", "web scan"])
    assert v.shape == (2, 384) and np.allclose(np.linalg.norm(v, axis=1), 1.0, atol=1e-5)


def test_missing_model_is_reported_not_downloaded(tmp_path: Path) -> None:
    with pytest.raises(EmbeddingUnavailable):
        FastEmbedEmbedder(cache_dir=tmp_path / "empty")


def test_search_attack_tool_errors_empty_and_no_echo(retriever: AttackRetriever, kb: AttackKB) -> None:
    tool = AttackSearchTool(retriever)
    assert "error" in json.loads(tool({}))
    assert "error" in json.loads(tool({"text": "x", "k": 9}))
    assert "error" in json.loads(tool({"text": "x", "extra": 1}))
    empty = AttackSearchTool(type("R", (), {"search": lambda self, t, k=5: []})())
    assert json.loads(empty({"text": "anything"})) == {"techniques": [], "note": "no matching technique"}
    query = "QUERYMARKER brute force password"
    out = tool({"text": query, "k": 2})
    assert "QUERYMARKER" not in out
    texts = {c.text for c in attack_chunks(kb)}
    for t in json.loads(out)["techniques"]:
        assert any(t["excerpt"] in full for full in texts)  # only KB content


# ---------------------------------------------------------------- C1 fix: hybrid retrieval


def test_bm25_tokenizer_and_scores() -> None:
    from app.rag.lexical import Bm25Index, tokenize
    assert tokenize("The SSH brute-force of T1110.001!") == ["ssh", "brute", "force", "t1110", "001"]
    idx = Bm25Index({"a": "ssh brute force password", "b": "web shell upload", "c": "ssh login"})
    s = idx.scores("ssh brute force")
    assert set(s) == {"a", "c"}  # documents with no query term get no score
    assert s["a"] > s["c"] > 0
    assert idx.scores("the of") == {}  # stopwords only
    assert idx.scores("ssh brute force") == s  # deterministic


def test_hybrid_mode_validates_and_blends(kb: AttackKB) -> None:
    from app.rag.retriever import DEFAULT_ALPHA, MODES
    assert MODES == ("dense", "lexical", "hybrid") and DEFAULT_ALPHA == 0.5
    with pytest.raises(ValueError):
        AttackRetriever(SqliteVectorStore(), HashEmbedder(), mode="bm25")
    with pytest.raises(ValueError):
        AttackRetriever(SqliteVectorStore(), HashEmbedder(), mode="hybrid", alpha=1.5)
    store = SqliteVectorStore()
    dense = AttackRetriever(store, HashEmbedder())
    dense.index(kb)
    for mode in MODES:
        r = AttackRetriever(store, HashEmbedder(), mode=mode, kb=kb)
        got = r.search("password guessing brute force", 3)
        ids = [g["technique_id"] for g in got]
        assert ids and len(ids) == len(set(ids))
        assert all(0.0 <= g["score"] <= 1.0 for g in got) or mode == "dense"
        assert got == r.search("password guessing brute force", 3)
        assert r.search("  ", 3) == []
    with pytest.raises(ValueError):
        AttackRetriever(store, HashEmbedder(), mode="hybrid")  # lexical modes need the KB


def test_hybrid_is_the_convex_blend_of_normalized_scores(kb: AttackKB) -> None:
    store = SqliteVectorStore()
    AttackRetriever(store, HashEmbedder()).index(kb)
    q = "password guessing brute force"
    one = {g["technique_id"]: g for g in AttackRetriever(store, HashEmbedder(), mode="hybrid", kb=kb,
                                                         alpha=1.0).search(q, 3)}
    dense = [g["technique_id"] for g in AttackRetriever(store, HashEmbedder()).search(q, 3)]
    assert list(one) == dense  # alpha = 1 is the dense ranking
    lex = [g["technique_id"] for g in AttackRetriever(store, HashEmbedder(), mode="lexical",
                                                      kb=kb).search(q, 3)]
    zero = [g["technique_id"] for g in AttackRetriever(store, HashEmbedder(), mode="hybrid", kb=kb,
                                                       alpha=0.0).search(q, 3)]
    assert zero[:len(lex)] == lex  # alpha = 0 ranks like lexical


def test_hybrid_query_without_lexical_match_and_chunk_ids(kb: AttackKB) -> None:
    # pilot crash 2026-11-12: a query with no BM25 match raised UnboundLocalError ('cid'), and
    # chunk_id named the last BM25 chunk instead of the chunk the excerpt came from
    store = SqliteVectorStore()
    AttackRetriever(store, HashEmbedder()).index(kb)
    hybrid = AttackRetriever(store, HashEmbedder(), mode="hybrid", kb=kb)
    hits = hybrid.search("zzqx qqvv", 3)  # no token of the synthetic bundle
    assert hits and all(h["score"] >= 0 for h in hits)
    chunks = {c.chunk_id: c for c in attack_chunks(kb)}
    for mode in ("hybrid", "lexical"):
        r = AttackRetriever(store, HashEmbedder(), mode=mode, kb=kb)
        for h in r.search("credential access brute force password", 3):
            c = chunks[h["chunk_id"]]
            assert c.technique_id == h["technique_id"] and c.text == h["text"]
    assert AttackRetriever(store, HashEmbedder(), mode="lexical", kb=kb).search("zzqx qqvv", 3) == []
