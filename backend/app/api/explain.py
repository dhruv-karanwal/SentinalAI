"""Explain mode of ``POST /copilot/ask``: the console's help chat (2026-11-13).

The floating help chat asks "what is this term / chart / finding?". It goes through the existing
copilot route and the same client (``services.extras["copilot_client"]``, the model named by
``SENTINEL_LLM_MODEL``), so a pilot running on the same local model is not made to reload it.
Unlike the investigation mode it is **one** chat request with a short answer:

- grounded only in what the console sends (the glossary entries that match the question and a
  plain-text summary of the screen) plus, when an incident is named, platform facts of that
  incident read from the core store (severity, times, counts, detectors, entities; no labels);
- ``MAX_OUTPUT_TOKENS`` (<= 300), temperature 0, no streaming;
- one request at a time (``MODEL_LOCK``; a second concurrent question gets 429 instead of queueing
  behind the pilot's requests);
- the model is told to say "not shown on this screen" rather than guess.

Answers are a help feature: never study results, never executed, rendered as plain text.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping, Sequence
from typing import Any

MAX_OUTPUT_TOKENS = 300
MAX_CONTEXT_CHARS = 6000
MAX_GLOSSARY_TERMS = 8
MAX_FIELD_CHARS = 600
MODEL_LOCK = threading.Lock()

SYSTEM_PROMPT = (
    "You explain the SentinelAI security operations console to a reader who is new to it. "
    "Answer only from the GLOSSARY, SCREEN and INCIDENT sections of the user message. "
    "If the answer is not in them, reply exactly: \"That is not shown on this screen, so I will not "
    "guess.\" and name the glossary term or screen that might help. Never invent numbers, hosts, "
    "dates or results. Plain sentences, at most 120 words, no Markdown, no lists of more than 4 items."
)


def _cut(text: object, limit: int = MAX_FIELD_CHARS) -> str:
    s = " ".join(str(text or "").split())
    return s if len(s) <= limit else s[: limit - 1] + "…"


def incident_facts(inc: Mapping[str, Any]) -> str:
    """Platform facts of one stored incident (no labels: the core store holds none)."""
    detail = inc.get("detail") or {}
    dets = detail.get("detectors") or {}
    ents = detail.get("entities") or []
    det_text = ", ".join(f"{k} {v}" for k, v in sorted(dets.items())) or "none recorded"
    return (f"incident {inc.get('incident_id')}: severity {inc.get('severity')}, status "
            f"{inc.get('status') or 'open'}, first seen {inc.get('first_ts')}, last seen "
            f"{inc.get('last_ts')} (dataset time), {len(inc.get('alert_ids') or [])} alerts, "
            f"detectors {det_text}, triage rule {detail.get('severity_row') or 'not recorded'}, "
            f"entities {', '.join(str(e) for e in ents[:6]) or 'none'}"
            f"{f' (+{len(ents) - 6} more)' if len(ents) > 6 else ''}.")


def build_messages(question: str, screen: str | None, context: str | None,
                   glossary: Sequence[Mapping[str, Any]], incident: str | None) -> list[dict[str, str]]:
    parts = []
    terms = list(glossary)[:MAX_GLOSSARY_TERMS]
    if terms:
        parts.append("GLOSSARY:\n" + "\n".join(
            f"TERM: {_cut(t.get('term'), 80)}. {_cut(t.get('definition'))} Why it matters here: {_cut(t.get('why'))}"
            for t in terms))
    if screen or context:
        parts.append(f"SCREEN: {_cut(screen, 80) or 'unknown'}\n{_cut(context, MAX_CONTEXT_CHARS)}")
    if incident:
        parts.append(f"INCIDENT: {incident}")
    if not parts:
        parts.append("GLOSSARY: (none sent)\nSCREEN: (none sent)")
    parts.append(f"QUESTION: {_cut(question, 500)}")
    return [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": "\n\n".join(parts)}]


def sources(glossary: Sequence[Any], screen: str | None, context: str | None, incident: str | None) -> list[str]:
    out = []
    if glossary:
        out.append("glossary")
    if screen or context:
        out.append("screen")
    if incident:
        out.append("incident")
    return out
