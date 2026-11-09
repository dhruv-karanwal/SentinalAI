"""The ``search_attack`` agent tool: ATT&CK retrieval over the local vector table.

Input: ``{"text": "<description>", "k": 1..5}``. Output JSON:
``{"techniques": [{"technique_id", "name", "tactics", "score", "excerpt"}]}``.
The output holds only ATT&CK knowledge-base content (excerpts are exact
substrings of a chunk) and never echoes the query, so it cannot carry case
data or labels; ``tests/test_wave_c.py`` checks this. Empty retrieval is
``{"techniques": [], "note": "no matching technique"}``; bad arguments come
back as ``{"error": ...}`` and never raise.
"""

from __future__ import annotations

import json
from typing import Any, Protocol

MAX_K = 5
EXCERPT_CHARS = 400


class Retriever(Protocol):
    def search(self, text: str, k: int = 5) -> list[dict[str, Any]]: ...


class AttackSearchTool:
    name = "search_attack"

    def __init__(self, retriever: Retriever) -> None:
        self.retriever = retriever

    def __call__(self, arguments: dict[str, Any]) -> str:
        extra = set(arguments) - {"text", "k"}
        if extra:
            return json.dumps({"error": f"unknown argument(s): {', '.join(sorted(extra))}"})
        text = arguments.get("text")
        if not isinstance(text, str) or not text.strip():
            return json.dumps({"error": "text (a non-empty string) is required"})
        k = arguments.get("k", 3)
        if isinstance(k, bool) or not isinstance(k, int) or not 1 <= k <= MAX_K:
            return json.dumps({"error": f"k must be an integer from 1 to {MAX_K}"})
        results = self.retriever.search(text, k)
        if not results:
            return json.dumps({"techniques": [], "note": "no matching technique"})
        return json.dumps({"techniques": [
            {"technique_id": r["technique_id"], "name": r["name"], "tactics": list(r["tactics"]),
             "score": round(float(r["score"]), 4), "excerpt": str(r["text"])[:EXCERPT_CHARS]}
            for r in results]})
