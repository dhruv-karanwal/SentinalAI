"""BM25 lexical scores over ATT&CK chunk texts (C1 fix, 2026-11-10). Pure Python, no new dependency.

Why: dense bge-small retrieval missed queries whose wording matches the
technique *name* or exact terms (``"brute force"``, ``"web shell"``); a
lexical score catches those. It is blended with the dense score in
:class:`app.rag.retriever.AttackRetriever` (``mode="hybrid"``).

Okapi BM25 with the textbook constants ``k1 = 1.5``, ``b = 0.75`` (fixed,
not tuned). Tokens: lower-case ``[a-z0-9]+`` runs, minus a short English
stopword list. A document with no query term gets no score (absent from the
result), so "no lexical evidence" is never confused with a low score.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Mapping

K1 = 1.5
B = 0.75
_TOKEN = re.compile(r"[a-z0-9]+")
STOPWORDS = frozenset(
    "a an and are as at be by for from has have in into is it its of on or that the this to was "
    "were which with".split())


def tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN.findall(text.lower()) if t not in STOPWORDS]


class Bm25Index:
    def __init__(self, docs: Mapping[str, str]) -> None:
        self._tf: dict[str, Counter[str]] = {d: Counter(tokenize(t)) for d, t in docs.items()}
        self._len = {d: sum(c.values()) for d, c in self._tf.items()}
        n = len(self._tf)
        self._avg = (sum(self._len.values()) / n) if n else 0.0
        df: Counter[str] = Counter()
        for c in self._tf.values():
            df.update(c.keys())
        self._idf = {t: math.log(1 + (n - f + 0.5) / (f + 0.5)) for t, f in df.items()}
        self._postings: dict[str, list[str]] = {}
        for d in sorted(self._tf):
            for t in self._tf[d]:
                self._postings.setdefault(t, []).append(d)

    def scores(self, query: str) -> dict[str, float]:
        out: dict[str, float] = {}
        for term in dict.fromkeys(tokenize(query)):  # distinct terms, query order
            idf = self._idf.get(term)
            if idf is None:
                continue
            for d in self._postings[term]:
                f = self._tf[d][term]
                norm = K1 * (1 - B + B * self._len[d] / self._avg) if self._avg else K1
                out[d] = out.get(d, 0.0) + idf * f * (K1 + 1) / (f + norm)
        return out
