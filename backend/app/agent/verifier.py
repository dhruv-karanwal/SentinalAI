"""Alert-evidence verifier: keep only what the case's alert records support (Wave C).

Applied identically to the M5 single agent and to the multi-agent graph in
the matched-budget runner. It checks a final answer against the alerts the
case's toolkit was built from:

- a cited alert id must be one of the case's alerts (an id the toolkit did
  not know already arrives as ``unknown:<id>``); others are **dropped and
  counted** (``dropped_citations``);
- every claim is checked with the existing claim kinds
  (:mod:`app.evaluation.metrics`): ``field_value`` = exact value of a
  flattened record field, ``quote`` = exact substring (>= 8 chars) of one
  of the alert's raw log lines. Unsupported claims are **dropped and
  counted** with a reason (``dropped_claims``), never kept silently.

The verifier reads alert records only (no labels): the same indices the
case scorer uses (``alert_claim_index``, ``alert_quote_index``).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from app.evaluation.case_scoring import alert_claim_index, alert_quote_index
from app.evaluation.metrics import CLAIM_QUOTE, QUOTE_MIN_CHARS, Claim
from app.schemas.alert import Alert


@dataclass
class VerifiedAnswer:
    cited: list[str]
    claims: list[Claim]
    dropped_citations: list[str] = field(default_factory=list)
    dropped_claims: list[dict[str, Any]] = field(default_factory=list)
    checked_claims: int = 0

    def summary(self) -> dict[str, int]:
        return {"citations_kept": len(self.cited), "citations_dropped": len(self.dropped_citations),
                "claims_checked": self.checked_claims, "claims_kept": len(self.claims),
                "claims_dropped": len(self.dropped_claims)}


def _reason(claim: Claim, index: dict[str, dict[str, str]], quotes: dict[str, list[str]]) -> str | None:
    """None when supported, else why not."""
    if claim.record_id not in index:
        return "alert not in case"
    if claim.kind == CLAIM_QUOTE:
        if len(claim.value) < QUOTE_MIN_CHARS:
            return "quote too short"
        if not any(claim.value in line for line in quotes.get(claim.record_id, [])):
            return "quote not in the alert's log lines"
        return None
    record = index[claim.record_id]
    if claim.field not in record:
        return "field not in record"
    if str(record[claim.field]).strip() != claim.value.strip():
        return "value differs from record"
    return None


def verify_answer(cited: Sequence[str], claims: Sequence[Claim], alerts: Sequence[Alert]) -> VerifiedAnswer:
    ids = {a.alert_id for a in alerts}
    index, quotes = alert_claim_index(alerts), alert_quote_index(alerts)
    kept_cited = [c for c in dict.fromkeys(cited) if c in ids]
    dropped_cited = [c for c in dict.fromkeys(cited) if c not in ids]
    kept: list[Claim] = []
    dropped: list[dict[str, Any]] = []
    for claim in claims:
        reason = _reason(claim, index, quotes)
        if reason is None:
            kept.append(claim)
        else:
            dropped.append({"record_id": claim.record_id, "kind": claim.kind, "field": claim.field,
                            "reason": reason})
    return VerifiedAnswer(kept_cited, kept, dropped_cited, dropped, len(claims))
