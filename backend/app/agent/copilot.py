"""Analyst copilot (Wave D): one question about one incident, answered with the M5 case tools.

Reuses the M5 pieces unchanged: :class:`CaseToolkit` (opaque alert ids,
time offsets, ``<TIME>`` masks, no labels), the bounded
:func:`~app.agent.agent.investigate` loop with the ``agent`` budgets, the
strict JSON protocol and the evidence verifier. The only addition is the
analyst's question at the end of the case brief (:class:`CopilotToolkit`),
so the investigation prompt and its config hash do not change.

The answer is the final reply's findings; cited ids and claims go through
:func:`verify_answer` against the incident's alerts, and only the kept ones
are returned as support; the dropped citations and claims are returned separately, each
claim with the verifier's reason, so the console can mark them instead of hiding them. Copilot answers are a demo
feature: they are never study results and never execute anything.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import Any

from app.agent.agent import investigate
from app.agent.client import ChatClient
from app.agent.config import AgentSettings
from app.agent.tools import CaseToolkit, mask_times
from app.agent.verifier import verify_answer
from app.schemas.alert import Alert

MAX_QUESTION_CHARS = 2000


class CopilotToolkit(CaseToolkit):
    def __init__(self, alerts: Sequence[Alert], question: str, **kwargs: Any) -> None:
        super().__init__(alerts, **kwargs)
        self._question = mask_times(question.strip())

    def brief(self) -> str:
        return (super().brief() + f"\nAnalyst question: {self._question}\nAnswer it in the findings "
                "of your final JSON (summary text), citing the alert ids that support each finding.")


def ask(client: ChatClient, alerts: Sequence[Alert], question: str, settings: AgentSettings,
        salt: str) -> dict[str, Any]:
    if not question.strip() or len(question) > MAX_QUESTION_CHARS:
        raise ValueError(f"question must be 1-{MAX_QUESTION_CHARS} characters")
    if not alerts:
        raise ValueError("the incident has no stored alerts")
    ordered = sorted(alerts, key=lambda a: (a.timestamp, a.source_file, a.source_line))
    span = (ordered[-1].timestamp - ordered[0].timestamp).total_seconds()
    kit = CopilotToolkit(ordered, question, window_start=ordered[0].timestamp,
                         window_seconds=max(1.0, span),
                         id_salt=hashlib.sha256(salt.encode()).hexdigest()[:16],
                         page_size=settings.agent.list_page_size,
                         max_output_chars=settings.agent.max_tool_output_chars)
    run = investigate(client, kit, settings.agent, settings.model)
    checked = verify_answer(run.cited_alert_ids, run.claims, ordered)
    findings = (run.final or {}).get("findings", [])
    return {"status": run.status, "parse_status": run.parse_status, "verdict": run.verdict,
            "answer": [str(f.get("summary", "")) for f in findings],
            "cited_alert_ids": checked.cited, "verification": checked.summary(),
            "claims": [{"record_id": c.record_id, "kind": c.kind, "field": c.field, "value": c.value}
                       for c in checked.claims],
            "dropped_citations": list(checked.dropped_citations),
            "dropped_claims": list(checked.dropped_claims),
            "tool_calls": run.tool_calls, "input_tokens": run.input_tokens,
            "output_tokens": run.output_tokens, "error": run.error,
            "note": "copilot answer: verified citations only; a demo feature, not a study result"}
