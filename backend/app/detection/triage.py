"""Triage and correlation (Wave B3): alerts -> incidents, label-free and deterministic.

Pipeline
--------
1. **Dedup (existing, kept):** alert ids are unique in the store (the
   consumer drops repeats) and ``DEFAULT_EVALUATION_SELECTION`` excludes
   AMiner training-mode alerts and Wazuh copies of Suricata alerts
   (``duplicate_of_suricata``). Aggregates stay: they are detector output.
2. **Entities** an alert carries (never derived beyond what it carries):
   ``host:<host_ip>`` and ``ip:<source ip>`` where the source IP is
   Wazuh ``data.srcip`` or Suricata ``data.src_ip``. Destination IPs are not
   entities: every inbound alert would otherwise chain through the server.
3. **Grouping:** per entity, alerts in time order; two consecutive alerts
   are linked when their gap is ``<= gap_seconds`` (exactly at the gap
   joins, just over splits). Links are merged with union-find, so alerts of
   different detectors that share an entity end up in one incident
   (cross-detector merge). An alert with no entity is its own incident.

   **Default gap: 300 s.** Chosen before looking at any result and not
   tuned on labels: a short window keeps a burst of related alerts on one
   entity together while letting a quiet period of five minutes split
   activity. It is a parameter (``TriageConfig.gap_seconds``, CLI
   ``--gap-seconds``, API ``gap_seconds``); report it with every number.
4. **Severity** from the first matching row of :data:`SEVERITY_TABLE`.
   Inputs only: detector level class, ATT&CK mapping (B1 ``map_alert``),
   IOC match (``IocStore``; empty unless a local indicator file is given,
   since the feeds are disabled), group size, number of agreeing detectors.
   No labels, no ML.

Detector level classes (``level_class``), from each detector's own scale:

=========  ===========================  ===========  ==========
detector   high                         medium       low
=========  ===========================  ===========  ==========
wazuh      ``rule.level`` >= 12         7 .. 11      <= 6
suricata   ``alert.severity`` == 1      2            >= 3
sigma      level critical / high        medium       low / informational
aminer     (no severity: class ``none``)
=========  ===========================  ===========  ==========

Wazuh's rule classification calls level 12 a "high importance event" and
7-11 the bad-word / first-time-seen / error / integrity bands; Suricata
priority 1 is its highest. These classes exist only inside triage;
``Alert.severity`` is never rescaled.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from typing import Any

from app.intel.attack import map_alert
from app.intel.ioc import IocStore
from app.platform.enrichment import enrich
from app.schemas.alert import DEFAULT_EVALUATION_SELECTION, Alert, AlertSelection, Detector
from app.storage.repository import Repository

DEFAULT_GAP_SECONDS = 300
LEVEL_ORDER = ("none", "low", "medium", "high")


@dataclass(frozen=True)
class TriageConfig:
    gap_seconds: int = DEFAULT_GAP_SECONDS
    selection: AlertSelection = field(default=DEFAULT_EVALUATION_SELECTION)

    def __post_init__(self) -> None:
        if self.gap_seconds < 1:
            raise ValueError("gap_seconds must be >= 1")


def level_class(alert: Alert) -> str:
    if alert.detector is Detector.WAZUH and alert.severity is not None:
        return "high" if alert.severity >= 12 else "medium" if alert.severity >= 7 else "low"
    if alert.detector is Detector.SURICATA and alert.severity is not None:
        return "high" if alert.severity <= 1 else "medium" if alert.severity == 2 else "low"
    if alert.detector is Detector.SIGMA:
        sigma = alert.raw_alert.get("sigma")
        level = sigma.get("level") if isinstance(sigma, dict) else None
        if level in ("critical", "high"):
            return "high"
        if level == "medium":
            return "medium"
        return "low" if level else "none"
    return "none"


def _src_ip(alert: Alert) -> str | None:
    data = alert.raw_alert.get("data")
    if not isinstance(data, dict):
        return None
    key = {Detector.WAZUH: "srcip", Detector.SURICATA: "src_ip"}.get(alert.detector)
    value = data.get(key) if key else None
    return str(value) if value not in (None, "") else None


def entities(alert: Alert) -> list[str]:
    out = []
    if alert.host_ip is not None:
        out.append(f"host:{alert.host_ip}")
    src = _src_ip(alert)
    if src is not None:
        out.append(f"ip:{src}")
    return out


def _time_key(alert: Alert) -> tuple[Any, ...]:
    return (alert.timestamp, alert.source_file, alert.source_line, alert.alert_id)


def group_alerts(alerts: Iterable[Alert], gap_seconds: int) -> list[list[Alert]]:
    items = sorted(alerts, key=_time_key)
    parent = list(range(len(items)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    by_entity: dict[str, list[int]] = {}
    for i, a in enumerate(items):
        for e in entities(a):
            by_entity.setdefault(e, []).append(i)
    for idx in by_entity.values():  # already time-ordered
        for prev, cur in zip(idx, idx[1:]):
            gap = (items[cur].timestamp - items[prev].timestamp).total_seconds()
            if gap <= gap_seconds:
                ra, rb = find(prev), find(cur)
                if ra != rb:
                    parent[max(ra, rb)] = min(ra, rb)
    comps: dict[int, list[Alert]] = {}
    for i, a in enumerate(items):
        comps.setdefault(find(i), []).append(a)
    return [comps[k] for k in sorted(comps)]


@dataclass(frozen=True)
class IncidentFeatures:
    size: int
    detectors: int
    max_level: str
    attack_mapped: bool
    ioc_match: bool


@dataclass(frozen=True)
class SeverityRow:
    row_id: str
    severity: str
    rule: str
    test: Callable[[IncidentFeatures], bool]


def _level_at_least(f: IncidentFeatures, level: str) -> bool:
    return LEVEL_ORDER.index(f.max_level) >= LEVEL_ORDER.index(level)


# First matching row wins. Every row has a test (tests/test_triage.py).
SEVERITY_TABLE: tuple[SeverityRow, ...] = (
    SeverityRow("H1", "High", "an indicator of compromise matched", lambda f: f.ioc_match),
    SeverityRow("H2", "High", ">= 3 detectors agree", lambda f: f.detectors >= 3),
    SeverityRow("H3", "High", "a high-level alert, and ATT&CK-mapped or >= 2 detectors agree",
                lambda f: f.max_level == "high" and (f.attack_mapped or f.detectors >= 2)),
    SeverityRow("M1", "Medium", "a high-level alert", lambda f: f.max_level == "high"),
    SeverityRow("M2", "Medium", "ATT&CK-mapped and >= 2 detectors agree",
                lambda f: f.attack_mapped and f.detectors >= 2),
    SeverityRow("M3", "Medium", "a medium-level alert in a group of >= 10 alerts",
                lambda f: _level_at_least(f, "medium") and f.size >= 10),
    SeverityRow("L1", "Low", "anything else", lambda f: True),
)


def severity(features: IncidentFeatures) -> tuple[str, str]:
    for row in SEVERITY_TABLE:
        if row.test(features):
            return row.severity, row.row_id
    raise AssertionError("the last severity row matches everything")


def incident_features(alerts: list[Alert], iocs: IocStore | None = None) -> IncidentFeatures:
    levels = [level_class(a) for a in alerts]
    ioc = bool(iocs) and any(iocs.match_alert(a, enrich(a)) for a in alerts) if iocs else False
    return IncidentFeatures(
        size=len(alerts), detectors=len({a.detector for a in alerts}),
        max_level=max(levels, key=LEVEL_ORDER.index) if levels else "none",
        attack_mapped=any(map_alert(a) for a in alerts), ioc_match=ioc)


def incident_id(scenario: str, alert_ids: Iterable[str]) -> str:
    body = scenario + "\n" + "\n".join(sorted(alert_ids))
    return "inc-" + hashlib.sha256(body.encode()).hexdigest()[:24]


def build_incidents(alerts: Iterable[Alert], scenario: str, config: TriageConfig,
                    iocs: IocStore | None = None) -> list[dict[str, Any]]:
    kept: list[Alert] = []
    excluded = 0
    for a in alerts:
        if config.selection.accepts(a):
            kept.append(a)
        else:
            excluded += 1
    out = []
    for members in group_alerts(kept, config.gap_seconds):
        feats = incident_features(members, iocs)
        sev, row = severity(feats)
        ids = [a.alert_id for a in members]
        out.append({
            "incident_id": incident_id(scenario, ids), "scenario": scenario,
            "first_ts": members[0].timestamp.isoformat(), "last_ts": members[-1].timestamp.isoformat(),
            "severity": sev, "alert_ids": ids,
            "detail": {
                "severity_row": row, "features": asdict(feats), "gap_seconds": config.gap_seconds,
                "detectors": dict(sorted(Counter(a.detector.value for a in members).items())),
                "entities": sorted({e for a in members for e in entities(a)}),
                "excluded_by_selection": excluded,
                "timeline": [{"ts": a.timestamp.isoformat(), "alert_id": a.alert_id,
                              "detector": a.detector.value, "rule_id": a.rule_id,
                              "rule_name": a.rule_name, "level": level_class(a)} for a in members],
            },
        })
    return out


def summarize(incidents: list[dict[str, Any]]) -> dict[str, Any]:
    sizes = Counter(len(i["alert_ids"]) for i in incidents)
    buckets: Counter[str] = Counter()
    for n, c in sizes.items():
        buckets[("1" if n == 1 else "2-9" if n < 10 else "10-99" if n < 100 else
                 "100-999" if n < 1000 else ">=1000")] += c
    return {
        "incidents": len(incidents),
        "alerts": sum(len(i["alert_ids"]) for i in incidents),
        "size_distribution": {str(k): v for k, v in sorted(sizes.items())},
        "size_buckets": dict(buckets),
        "largest": max(sizes) if sizes else 0,
        "severity": dict(sorted(Counter(i["severity"] for i in incidents).items())),
        "severity_rows": dict(sorted(Counter(i["detail"]["severity_row"] for i in incidents).items())),
        "cross_detector": sum(1 for i in incidents if i["detail"]["features"]["detectors"] >= 2),
    }


def build_and_store(repo: Repository, scenario: str, config: TriageConfig,
                    extra_alerts: Iterable[Alert] = (), iocs: IocStore | None = None) -> dict[str, Any]:
    """Build incidents from the scenario's stored alerts (+ extra ones) and write them."""
    stored = list(repo.iter_alert_models(scenario))
    extra = list(extra_alerts)
    incidents = build_incidents(stored + extra, scenario, config, iocs)
    with repo.db.transaction():
        # A rebuild replaces earlier incidents of the scenario, except ones a report refers to.
        repo.db.execute("DELETE FROM incidents WHERE scenario = ? AND incident_id NOT IN "
                        "(SELECT incident_id FROM reports)", (scenario,))
        for inc in incidents:
            repo.put_incident(inc)
    summary = summarize(incidents)
    summary.update({"scenario": scenario, "gap_seconds": config.gap_seconds,
                    "stored_alerts_read": len(stored), "extra_alerts": len(extra),
                    "excluded_by_selection": len(stored) + len(extra) - summary["alerts"]})
    return summary
