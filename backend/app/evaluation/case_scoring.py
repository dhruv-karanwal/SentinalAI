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
- ``unsupported_claim_rate``: :func:`unsupported_claim_rate` with
  ``Claim.record_id = alert_id`` against an index of the case's own alert
  records: canonical fields, ``raw_alert.*`` and ``evidence.log_lines.<i>``
  (whole raw log lines). A claim about an alert outside the case is
  unsupported: the agent never saw it.
- ``load``: the number of alerts in the case after the cap.

Benign cases have no attack step, so both coverages are ``None``. Cited ids
that are not alerts of the case are counted (``cited_not_in_case``) and
never count towards coverage.
"""

from __future__ import annotations

import json
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from app.evaluation.metrics import Claim, attack_step_coverage, unsupported_claim_rate
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
    """Claim index over alert records (``alert_id`` -> flattened fields)."""
    return {a.alert_id: flatten_record(a.model_dump(mode="json")) for a in alerts}


@dataclass(frozen=True)
class CaseScore:
    case_id: str
    variant: str
    load: int
    coverage_time: float | None
    coverage_event: float | None
    unsupported_claim_rate: float | None
    cited: int
    cited_not_in_case: int
    claims: int


def score_case(
    case: Case,
    view: CaseAlerts,
    cited_alert_ids: Collection[str],
    *,
    claims: Iterable[Claim] = (),
    claim_index: Mapping[str, Mapping[str, str]] | None = None,
) -> CaseScore:
    case_ids = {e.alert_id for e in view.entries}
    cited = [i for i in cited_alert_ids if i in case_ids]
    if case.kind == "attack":  # CaseKind is a StrEnum
        phase_alerts = [e for e in view.entries if case.start <= e.timestamp < case.end]
        time_steps = {case.phase: {e.alert_id for e in phase_alerts}}
        event_steps = {case.phase: {e.alert_id for e in phase_alerts if e.event_attack}}
        coverage_time = attack_step_coverage(time_steps, cited)
        coverage_event = attack_step_coverage(event_steps, cited)
    else:
        coverage_time = coverage_event = None
    claim_list = list(claims)
    index = {k: v for k, v in (claim_index or {}).items() if k in case_ids}
    return CaseScore(
        case_id=case.case_id,
        variant=view.variant,
        load=len(view.entries),
        coverage_time=coverage_time,
        coverage_event=coverage_event,
        unsupported_claim_rate=unsupported_claim_rate(claim_list, index),
        cited=len(cited_alert_ids),
        cited_not_in_case=len(cited_alert_ids) - len(cited),
        claims=len(claim_list),
    )
