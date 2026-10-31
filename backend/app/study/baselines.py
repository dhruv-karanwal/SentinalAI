"""Deterministic, non-LLM baseline "agents": the reference points an LLM must beat.

Each baseline reads only what an agent would see (the case's alerts, in
time order) and returns the alert ids it cites. None of them looks at
labels. Rules (k = ``baselines.top_k``, default 5):

- ``cite-all``: every alert of the case. Its coverage is the case ceiling.
- ``cite-none``: nothing. Coverage 0; precision and claim rate undefined.
- ``cite-top-k-wazuh-level``: Wazuh alerts ranked by ``rule.level``
  (descending; ties by time, then source line), then the case's non-Wazuh
  alerts in time order, first k. It is the "triage by Wazuh severity"
  analyst. Non-Wazuh alerts are used only when the case has fewer than k
  Wazuh alerts, so the baseline always cites min(k, load) alerts.
- ``cite-top-k-detector-order``: alerts ranked by detector in
  ``baselines.detector_order`` (default aminer, wazuh, suricata; set from
  the M3 *dev* triage precision, a documented dev-derived choice), ties by
  time, first k.
- ``cite-aminer-only``: every AMiner alert of the case (no k limit).

Claims (:func:`baseline_claims`): for each cited alert, one field-value
claim on ``rule_id`` (or ``rule_name`` when the alert has no rule id) and
one quote claim of the first ``quote_chars`` characters of its first raw
log line when that is at least 8 characters long. Copied from the record,
they are supported by construction; their unsupported-claim rate checks the
claim machinery on real records and is the floor an LLM agent must match.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from typing import TYPE_CHECKING

from app.evaluation.metrics import QUOTE_MIN_CHARS, Claim
from app.schemas.alert import Alert, Detector
from app.study.config import BaselineConfig
from app.study.variants import PoolEntry

if TYPE_CHECKING:  # type-only: app.study.cases runs the baselines
    from app.study.cases import CaseAlerts

BASELINE_NAMES = ("cite-all", "cite-none", "cite-top-k-wazuh-level",
                  "cite-top-k-detector-order", "cite-aminer-only")


def _time_key(entry: PoolEntry) -> tuple[object, ...]:
    return (entry.timestamp, entry.source_file, entry.source_line)


def _wazuh_level_key(entry: PoolEntry) -> tuple[object, ...]:
    if entry.detector is Detector.WAZUH:
        level = entry.severity if entry.severity is not None else -1
        return (0, -level, *_time_key(entry))
    return (1, 0, *_time_key(entry))


def baseline_citations(name: str, view: CaseAlerts, config: BaselineConfig) -> list[str]:
    entries = list(view.entries)  # time-ordered
    k = config.top_k
    rules: dict[str, Callable[[], list[PoolEntry]]] = {
        "cite-all": lambda: entries,
        "cite-none": lambda: [],
        "cite-top-k-wazuh-level": lambda: sorted(entries, key=_wazuh_level_key)[:k],
        "cite-top-k-detector-order": lambda: sorted(
            entries, key=lambda e: (config.detector_order.index(e.detector.value), *_time_key(e)))[:k],
        "cite-aminer-only": lambda: [e for e in entries if e.detector is Detector.AMINER],
    }
    if name not in rules:
        raise ValueError(f"unknown baseline {name!r}; choose from {', '.join(BASELINE_NAMES)}")
    return [e.alert_id for e in rules[name]()]


def baseline_claims(alerts: Iterable[Alert], *, quote_chars: int) -> list[Claim]:
    claims: list[Claim] = []
    for alert in alerts:
        if alert.rule_id is not None:
            claims.append(Claim.about_alert(alert.alert_id, "rule_id", alert.rule_id))
        elif alert.rule_name is not None:
            claims.append(Claim.about_alert(alert.alert_id, "rule_name", alert.rule_name))
        lines: Sequence[str] = alert.evidence.log_lines
        if lines and len(lines[0][:quote_chars]) >= QUOTE_MIN_CHARS:
            claims.append(Claim.quote(alert.alert_id, lines[0][:quote_chars]))
    return claims
