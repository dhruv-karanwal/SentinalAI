"""Tools and shared memory of the multi-agent graph (Wave C).

The graph's agents reach data only through this layer:

- the M5 :class:`~app.agent.tools.CaseToolkit` (opaque ids, time offsets,
  masked timestamps, no labels) for ``list_alerts``, ``get_alert``,
  ``search_alerts``, ``get_raw_log``;
- ``search_attack`` (:mod:`app.agent.rag_tool`): ATT&CK knowledge only;
- ``recall_notes`` / ``search_notes``: the case's shared notes.

Shared memory (:class:`CaseMemory`): every note an agent writes goes to the
repository ``memory`` table (``Repository.remember``; shared context) and,
when a vector store and embedder are given, to the vector table collection
``memory:<session>`` (vector memory; ``search_notes`` ranks by similarity,
otherwise by substring match). The session id is an opaque hash of the
toolkit salt, never the case id. Note text is time-masked
(:func:`~app.agent.tools.mask_times`) and capped at ``NOTE_MAX_CHARS``;
alert ids in notes are the opaque ids the agent saw.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from app.agent.rag_tool import AttackSearchTool
from app.agent.tools import TOOL_NAMES as CASE_TOOLS
from app.agent.tools import CaseToolkit, mask_times
from app.rag.embedding import Embedder
from app.rag.vector_store import VectorItem, VectorStore
from app.storage.repository import Repository

NOTE_MAX_CHARS = 2000
MEMORY_TOOLS = ("recall_notes", "search_notes")
ALL_TOOLS = (*CASE_TOOLS, "search_attack", *MEMORY_TOOLS)


def session_id_for(salt: str) -> str:
    return "mem-" + hashlib.sha256(salt.encode()).hexdigest()[:16]


@dataclass
class CaseMemory:
    session_id: str
    repo: Repository | None = None
    vectors: VectorStore | None = None
    embedder: Embedder | None = None
    notes: list[dict[str, Any]] = field(default_factory=list)
    writes: list[dict[str, Any]] = field(default_factory=list)  # every value written, for audits/tests

    @property
    def collection(self) -> str:
        return f"memory:{self.session_id}"

    def write(self, agent: str, text: str, alert_ids: Sequence[str]) -> dict[str, Any]:
        clean = mask_times(text)[:NOTE_MAX_CHARS]
        note: dict[str, Any] = {"n": len(self.notes) + 1, "agent": agent, "text": clean,
                                "alert_ids": [str(a) for a in alert_ids][:50]}
        self.notes.append(note)
        self.writes.append(note)
        if self.repo is not None:
            self.repo.remember(self.session_id, "note", note)
        if self.vectors is not None and self.embedder is not None:
            vec = self.embedder.embed_passages([clean])
            self.vectors.upsert(self.collection, [VectorItem(f"note-{note['n']:03d}", clean,
                                                             {"agent": agent, "n": note["n"]})], vec)
        return note

    def recall(self) -> list[dict[str, Any]]:
        return list(self.notes)

    def search(self, text: str, k: int = 3) -> list[dict[str, Any]]:
        if self.vectors is not None and self.embedder is not None:
            hits = self.vectors.search(self.collection, self.embedder.embed_query(text)[0], k)
            by_n = {n["n"]: n for n in self.notes}
            return [by_n[int(h.meta["n"])] for h in hits if int(h.meta["n"]) in by_n]
        needle = text.lower()
        return [n for n in self.notes if needle in n["text"].lower()][:k]


class MultiAgentToolkit:
    def __init__(self, case: CaseToolkit, memory: CaseMemory,
                 attack: AttackSearchTool | None = None) -> None:
        self.case = case
        self.memory = memory
        self.attack = attack

    def brief(self, final: bool = True) -> str:
        return self.case.brief(final)

    def call(self, name: str, arguments: Mapping[str, Any], allowed: Sequence[str]) -> str:
        if name not in allowed:
            return json.dumps({"error": f"tool {name!r} is not available to this agent; "
                                        f"available: {', '.join(allowed)}"})
        if not isinstance(arguments, Mapping):
            return json.dumps({"error": "arguments must be a JSON object"})
        if name in CASE_TOOLS:
            return self.case.call(name, arguments)
        if name == "search_attack":
            if self.attack is None:
                return json.dumps({"techniques": [], "note": "ATT&CK retrieval is not available"})
            return self.attack(dict(arguments))
        if name == "recall_notes":
            return json.dumps({"notes": self.memory.recall()}, ensure_ascii=False)
        if name == "search_notes":
            text = arguments.get("text")
            if not isinstance(text, str) or not text.strip():
                return json.dumps({"error": "text (a non-empty string) is required"})
            return json.dumps({"notes": self.memory.search(text)}, ensure_ascii=False)
        return json.dumps({"error": f"unknown tool {name!r}"})
