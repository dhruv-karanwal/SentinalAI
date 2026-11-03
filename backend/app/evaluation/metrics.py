"""Deterministic, judge-free metrics (see docs/research-methodology.md).

Why no LLM judge: core metrics must be reproducible and checkable against
ground truth, so each one is computed from event IDs and field values only.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping, Sequence
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


CLAIM_FIELD_VALUE = "field_value"
CLAIM_QUOTE = "quote"
CLAIM_KINDS = (CLAIM_FIELD_VALUE, CLAIM_QUOTE)
QUOTE_MIN_CHARS = 8


@dataclass(frozen=True)
class Claim:
    """A claim an agent made about record ``record_id``.

    Two kinds:

    - ``field_value`` (default): the record's ``field`` equals ``value``,
      compared as stripped strings.
    - ``quote``: ``value`` occurs verbatim in one of the record's raw log
      lines: exact, case-sensitive substring, at least ``QUOTE_MIN_CHARS``
      characters, no whitespace or case normalization. ``field`` is
      informational for quotes.

    The record is a log event or, in the AIT-ADS study (which has no
    log-event IDs), an alert: ``record_id`` is then the ``alert_id`` (see
    app.evaluation.case_scoring). ``event_id`` is kept as an alias for
    existing callers, and positional ``Claim(id, field, value)`` still makes
    a field-value claim.
    """

    record_id: str
    field: str
    value: str
    kind: str = CLAIM_FIELD_VALUE

    def __post_init__(self) -> None:
        if self.kind not in CLAIM_KINDS:
            raise ValueError(f"claim kind must be one of {', '.join(CLAIM_KINDS)}, got {self.kind!r}")

    @property
    def event_id(self) -> str:
        return self.record_id

    @classmethod
    def about_alert(cls, alert_id: str, field: str, value: str) -> Claim:
        return cls(alert_id, field, value)

    @classmethod
    def quote(cls, record_id: str, text: str) -> Claim:
        return cls(record_id, "raw_log_line", text, kind=CLAIM_QUOTE)


def _supported(claim: Claim, log_index: Mapping[str, Mapping[str, str]],
               quote_index: Mapping[str, Sequence[str]] | None) -> bool:
    if claim.kind == CLAIM_QUOTE:
        lines = (quote_index or {}).get(claim.record_id)
        return (lines is not None and len(claim.value) >= QUOTE_MIN_CHARS
                and any(claim.value in line for line in lines))
    record = log_index.get(claim.record_id)
    return (record is not None and claim.field in record
            and str(record[claim.field]).strip() == claim.value.strip())


def unsupported_claims(
    claims: Iterable[Claim],
    log_index: Mapping[str, Mapping[str, str]],
    *,
    quote_index: Mapping[str, Sequence[str]] | None = None,
) -> tuple[int, int]:
    """``(unsupported, total)`` claims; see :func:`unsupported_claim_rate`."""
    total = unsupported = 0
    for claim in claims:
        total += 1
        unsupported += not _supported(claim, log_index, quote_index)
    return unsupported, total


def unsupported_claim_rate(
    claims: Iterable[Claim],
    log_index: Mapping[str, Mapping[str, str]],
    *,
    quote_index: Mapping[str, Sequence[str]] | None = None,
) -> float | None:
    """Fraction of claims not supported by the records. ``None`` for no claims.

    ``log_index`` maps a record id (event id or alert id) to its fields;
    ``quote_index`` maps it to its raw log lines (needed for quote claims;
    without it every quote is unsupported). No fuzzy matching: a claim is
    supported only if the record says exactly that.
    """
    unsupported, total = unsupported_claims(claims, log_index, quote_index=quote_index)
    return unsupported / total if total else None
