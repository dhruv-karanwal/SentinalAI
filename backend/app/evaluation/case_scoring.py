"""Deterministic case-level scoring (no LLM).

Given the alerts an agent cites for a case (and the claims it makes), a
case is scored on:

- ``coverage_time``: attack-step coverage where the case's phase counts as
  covered when at least one cited alert of the case lies inside the phase
  interval (and therefore inside the case window). This is
  :func:`attack_step_coverage` with alert ids as the labelled ids.
- ``coverage_event``: the same, but only cited alerts with an attack
  event_label count (sensitivity analysis). Event-label values (``dirb``,
  ``escalated_sudo_command``, ...) do not map one-to-one onto phase names,
  so this asks "an event-labelled attack alert inside the phase", not "the
  phase's own label".
- ``citation_precision_event``: fraction of the distinct cited ids that are
  case alerts with an attack event_label; ``citation_precision_time``:
  fraction inside the case's phase interval (0 for benign cases, which have
  no phase). Ids that are not alerts of the case count in the denominator:
  citing something the agent never saw is a wrong citation.
- ``unsupported_claim_rate``: :func:`unsupported_claim_rate` with
  ``Claim.record_id = alert_id`` against the case's own alert records.
  Field-value claims use the flattened record (canonical fields,
  ``raw_alert.*``, ``evidence.log_lines.<i>``); quote claims must be exact
  substrings (>= 8 chars, case-sensitive) of the alert's raw log lines
  (``evidence.log_lines``). A claim about an alert outside the case is
  unsupported: the agent never saw it.
- ``load``: the number of alerts in the case after the cap.

Benign cases have no attack step, so both coverages are ``None``. Cited ids
that are not alerts of the case are counted (``cited_not_in_case``) and
never count towards coverage.
"""

from __future__ import annotations

import json
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from app.evaluation.metrics import Claim, attack_step_coverage, unsupported_claims
from app.schemas.alert import Alert

if TYPE_CHECKING:  # type-only: app.study.cases imports this module
    from app.study.cases import Case, CaseAlerts


def flatten_record(data: Any, prefix: str = "") -> dict[str, str]:
    """Dotted-path -> string for every scalar leaf; ``None`` leaves are skipped.

    Strings are kept as-is; other scalars use their JSON spelling (``true``,
    ``3``, ``1.5``) so claims compare against one canonical text.
    """
    flat: dict[str, str] = {}
    if isinstance(data, Mapping):
        items: Iterable[tuple[str, Any]] = ((str(k), v) for k, v in data.items())
    elif isinstance(data, list):
        items = ((str(i), v) for i, v in enumerate(data))
    else:
        if data is not None:
            flat[prefix] = data if isinstance(data, str) else json.dumps(data)
        return flat
    for key, value in items:
        flat.update(flatten_record(value, f"{prefix}.{key}" if prefix else key))
    return flat


def alert_claim_index(alerts: Iterable[Alert]) -> dict[str, dict[str, str]]:
    """Field-value claim index over alert records (``alert_id`` -> flattened fields)."""
    return {a.alert_id: flatten_record(a.model_dump(mode="json")) for a in alerts}


def alert_quote_index(alerts: Iterable[Alert]) -> dict[str, list[str]]:
    """Quote claim index: ``alert_id`` -> the raw log lines the alert carries."""
    return {a.alert_id: list(a.evidence.log_lines) for a in alerts}


@dataclass(frozen=True)
class CaseScore:
    case_id: str
    variant: str
    load: int
    coverage_time: float | None
    coverage_event: float | None
    citation_precision_event: float | None
    citation_precision_time: float | None
    unsupported_claim_rate: float | None
    cited: int  # distinct ids cited
    cited_not_in_case: int
    cited_event_attack: int
    cited_in_phase: int
    claims: int
    unsupported_claims: int


def score_case(
    case: Case,
    view: CaseAlerts,
    cited_alert_ids: Collection[str],
    *,
    claims: Iterable[Claim] = (),
    claim_index: Mapping[str, Mapping[str, str]] | None = None,
    quote_index: Mapping[str, Sequence[str]] | None = None,
) -> CaseScore:
    by_id = {e.alert_id: e for e in view.entries}
    distinct = list(dict.fromkeys(cited_alert_ids))
    cited = [by_id[i] for i in distinct if i in by_id]
    attack_case = case.kind == "attack"  # CaseKind is a StrEnum

    def inside(entry: Any) -> bool:
        return attack_case and case.start <= entry.timestamp < case.end

    if attack_case:
        phase_alerts = [e for e in view.entries if inside(e)]
        time_steps = {case.phase: {e.alert_id for e in phase_alerts}}
        event_steps = {case.phase: {e.alert_id for e in phase_alerts if e.event_attack}}
        coverage_time = attack_step_coverage(time_steps, [e.alert_id for e in cited])
        coverage_event = attack_step_coverage(event_steps, [e.alert_id for e in cited])
    else:
        coverage_time = coverage_event = None

    event_hits = sum(bool(e.event_attack) for e in cited)
    phase_hits = sum(inside(e) for e in cited)
    claim_list = list(claims)
    index = {k: v for k, v in (claim_index or {}).items() if k in by_id}
    quotes = {k: v for k, v in (quote_index or {}).items() if k in by_id}
    unsupported, total = unsupported_claims(claim_list, index, quote_index=quotes)
    return CaseScore(
        case_id=case.case_id,
        variant=view.variant,
        load=len(view.entries),
        coverage_time=coverage_time,
        coverage_event=coverage_event,
        citation_precision_event=event_hits / len(distinct) if distinct else None,
        citation_precision_time=phase_hits / len(distinct) if distinct else None,
        unsupported_claim_rate=unsupported / total if total else None,
        cited=len(distinct),
        cited_not_in_case=len(distinct) - len(cited),
        cited_event_attack=event_hits,
        cited_in_phase=phase_hits,
        claims=total,
        unsupported_claims=unsupported,
    )
