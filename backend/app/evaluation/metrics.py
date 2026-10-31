"""Deterministic, judge-free metrics (see docs/research-methodology.md).

Why no LLM judge: core metrics must be reproducible and checkable against
ground truth, so each one is computed from event IDs and field values only.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class TriageScores:
    tp: int
    fp: int
    fn: int
    tn: int

    @property
    def precision(self) -> float | None:
        d = self.tp + self.fp
        return self.tp / d if d else None

    @property
    def recall(self) -> float | None:
        d = self.tp + self.fn
        return self.tp / d if d else None

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None or p + r == 0:
            return None
        return 2 * p * r / (p + r)

    @property
    def false_negative_rate(self) -> float | None:
        r = self.recall
        return None if r is None else 1.0 - r


def triage_scores(
    predicted_attack: Mapping[str, bool], truth_attack: Mapping[str, bool]
) -> TriageScores:
    """Compare per-item attack verdicts with ground truth.

    Both mappings must cover exactly the same item ids; a mismatch is a
    caller bug and raises rather than silently scoring a subset.
    """
    if predicted_attack.keys() != truth_attack.keys():
        raise ValueError("predicted and truth must cover the same item ids")
    tp = fp = fn = tn = 0
    for key, truth in truth_attack.items():
        pred = predicted_attack[key]
        if pred and truth:
            tp += 1
        elif pred:
            fp += 1
        elif truth:
            fn += 1
        else:
            tn += 1
    return TriageScores(tp, fp, fn, tn)


def attack_step_coverage(
    steps: Mapping[str, Collection[str]], cited_ids: Iterable[str]
) -> float | None:
    """Fraction of attack steps with at least one cited id.

    ``steps`` maps a step name to the labelled ids (event ids, or alert ids
    in the AIT-ADS study) that belong to it. Returns ``None`` when there are
    no steps (nothing to cover).
    """
    if not steps:
        return None
    cited = set(cited_ids)
    covered = sum(1 for ids in steps.values() if cited & set(ids))
    return covered / len(steps)


@dataclass(frozen=True)
class Claim:
    """A claim an agent made: record ``record_id`` has ``field == value``.

    The record is a log event or, in the AIT-ADS study (which has no
    log-event IDs), an alert: ``record_id`` is then the ``alert_id`` and the
    fields are the alert record's own (see app.evaluation.case_scoring).
    ``event_id`` is kept as an alias for existing callers.
    """

    record_id: str
    field: str
    value: str

    @property
    def event_id(self) -> str:
        return self.record_id

    @classmethod
    def about_alert(cls, alert_id: str, field: str, value: str) -> Claim:
        return cls(alert_id, field, value)


def unsupported_claim_rate(
    claims: Iterable[Claim], log_index: Mapping[str, Mapping[str, str]]
) -> float | None:
    """Fraction of claims whose record id or field value is absent from the index.

    ``log_index`` maps a record id (event id or alert id) to its fields.

    Values are compared as stripped strings; no fuzzy matching, so a claim
    is supported only if the log says exactly that. ``None`` for no claims.
    """
    total = unsupported = 0
    for c in claims:
        total += 1
        record = log_index.get(c.record_id)
        if record is None or c.field not in record:
            unsupported += 1
        elif str(record[c.field]).strip() != c.value.strip():
            unsupported += 1
    return unsupported / total if total else None
