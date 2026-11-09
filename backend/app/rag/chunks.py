"""Chunk the approved ATT&CK bundle for retrieval.

One technique gives one or more chunks. Each chunk text is
``"<id> <name>\\nTactics: ...\\n<part of the description>"`` plus
``"Detection: ..."`` when the bundle carries ``x_mitre_detection``. The local
bundle (x_mitre_version 20.1) carries no detection text for techniques (it
moved to separate detection objects), so in practice chunks hold name,
tactics and description; the code still includes detection text when present.

Descriptions longer than ``max_chars`` are split at paragraph boundaries
(never inside a paragraph unless one paragraph alone is longer, then at
sentence ends). ``(Citation: ...)`` markers are removed: they name
sources, not behaviour, and add noise to the embedding.

The KB holds no labels of any dataset, so nothing here can leak ground truth.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.intel.attack import AttackKB, Technique

_CITATION = re.compile(r"\s*\(Citation:[^)]*\)")
_SENTENCE = re.compile(r"(?<=[.!?])\s+")


@dataclass(frozen=True)
class Chunk:
    chunk_id: str
    technique_id: str
    name: str
    tactics: tuple[str, ...]
    text: str


def clean(text: str) -> str:
    return _CITATION.sub("", text).strip()


def _pieces(text: str, max_chars: int) -> list[str]:
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    units: list[str] = []
    for p in paragraphs:
        if len(p) <= max_chars:
            units.append(p)
        else:
            units.extend(s for s in _SENTENCE.split(p) if s)
    out: list[str] = []
    cur = ""
    for u in units:
        if cur and len(cur) + 2 + len(u) > max_chars:
            out.append(cur)
            cur = u
        else:
            cur = f"{cur}\n\n{u}" if cur else u
    if cur:
        out.append(cur)
    return out or [""]


def technique_chunks(t: Technique, kb: AttackKB, max_chars: int = 1200) -> list[Chunk]:
    tactics = tuple(kb.tactics.get(x, x) for x in t.tactics)
    head = f"{t.technique_id} {t.name}\nTactics: {', '.join(tactics) or 'none'}"
    detection = clean(t.detection)
    chunks = []
    for i, piece in enumerate(_pieces(clean(t.description), max_chars)):
        body = f"{head}\n{piece}".rstrip()
        if detection and i == 0:
            body += f"\nDetection: {detection[:max_chars]}"
        chunks.append(Chunk(f"{t.technique_id}#{i}", t.technique_id, t.name, tactics, body))
    return chunks


def attack_chunks(kb: AttackKB, max_chars: int = 1200) -> list[Chunk]:
    out: list[Chunk] = []
    for tid in sorted(kb.techniques):
        out.extend(technique_chunks(kb.techniques[tid], kb, max_chars))
    return out
