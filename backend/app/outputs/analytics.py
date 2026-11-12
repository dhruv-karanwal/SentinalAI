"""Console analytics (Wave D, UI v2): label-free aggregates over the stored alerts and incidents.

Every number the overview, entity, incident-graph, executive and report charts show comes from
here. Inputs are core-area rows only (alerts with their enrichment and record, incidents,
approvals, audit entries); nothing reads the truth area, so no aggregate can carry a label
(``tests/test_detection_labels.py`` lists this module in ``LABEL_FREE``).

- ``Fact``: the few fields of a stored alert the charts need (time, detector, rule, native
  severity, host, source IP from the enrichment, ATT&CK ids from the deterministic B1 mapping,
  the Suricata-duplicate flag, IOC match when an indicator list is loaded, else ``None``).
- ``AlertIndex``: the facts of one scenario in (time, id) order with filtering, facet counts,
  time bins, the ATT&CK matrix, top entities, the detector comparison and the kill chain.
  The API keeps one index per scenario in memory and rebuilds it when the stored count changes.
- Incident helpers: queue summary (severity x status, age in the queue, oldest unreviewed
  High), incident analysis (entity graph, tactic lanes, the triage rule in words), executive
  summary (severity trend by first-seen day, top risks, time to review from the audit log).

"Age in queue" and "time to review" are measured from ``created_utc`` (when triage stored the
incident), because the alert times are the 2022 dataset replay; the UI says so.
"""

from __future__ import annotations

import math
from bisect import bisect_left
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from statistics import median
from typing import Any

from app.intel.attack import AttackKB, technique_ids
from app.outputs.graph_layout import layout

TACTIC_ORDER: tuple[str, ...] = (
    "reconnaissance", "resource-development", "initial-access", "execution", "persistence",
    "privilege-escalation", "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control", "exfiltration", "impact",
)
TACTIC_NAMES: dict[str, str] = {
    "reconnaissance": "Reconnaissance", "resource-development": "Resource Development",
    "initial-access": "Initial Access", "execution": "Execution", "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation", "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access", "discovery": "Discovery",
    "lateral-movement": "Lateral Movement", "collection": "Collection",
    "command-and-control": "Command and Control", "exfiltration": "Exfiltration",
    "impact": "Impact",
}
UNKNOWN_TACTIC = "unknown"
DETECTOR_ORDER: tuple[str, ...] = ("wazuh", "suricata", "aminer", "sigma")
SEVERITIES: tuple[str, ...] = ("High", "Medium", "Low")
STATUSES: tuple[str, ...] = ("open", "investigating", "contained", "closed")
BIN_STEPS: tuple[int, ...] = (1, 5, 10, 30, 60, 300, 600, 900, 1800, 3600, 7200, 10800, 21600,
                              43200, 86400)
AGE_BUCKETS: tuple[tuple[str, float], ...] = (("< 1 h", 3600.0), ("1-24 h", 86400.0),
                                              ("1-7 d", 7 * 86400.0), ("> 7 d", math.inf))
FACETS: tuple[str, ...] = ("detector", "level", "rule_id", "technique", "host")
MAX_GRAPH_NODES = 500
GRAPH_SHOWN = 60  # the console and the report draw the first 60 nodes
GRAPH_W, GRAPH_H = 480.0, 320.0
EXPORT_COLUMNS: tuple[str, ...] = ("ts", "alert_id", "detector", "rule_id", "rule_name", "severity",
                                   "host_ip", "src_ip", "techniques")


def _epoch(ts: str | datetime) -> float:
    if isinstance(ts, datetime):
        return ts.timestamp()
    return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()


def iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace("+00:00", "Z")


def bin_seconds(span: float, target: int = 120) -> int:
    """The smallest step in ``BIN_STEPS`` that gives at most ``target`` bins (whole days beyond)."""
    span = max(0.0, span)
    for step in BIN_STEPS:
        if span / step <= target:
            return step
    return 86400 * math.ceil(span / (86400 * target))


# ---- facts ------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Fact:
    alert_id: str
    ts: float
    detector: str
    kind: str
    rule_id: str | None
    rule_name: str | None
    severity: int | None
    host: str | None
    src: str | None
    techniques: tuple[str, ...]
    duplicate: bool
    ioc: bool | None

    def level(self) -> str:
        return "none" if self.severity is None else str(self.severity)

    def export_row(self) -> dict[str, Any]:
        return {"ts": iso(self.ts), "alert_id": self.alert_id, "detector": self.detector,
                "rule_id": self.rule_id, "rule_name": self.rule_name, "severity": self.severity,
                "host_ip": self.host, "src_ip": self.src, "techniques": ";".join(self.techniques)}


def _src_ip(enrichment: Mapping[str, Any]) -> str | None:
    net = enrichment.get("network")
    src = net.get("src") if isinstance(net, dict) else None
    if isinstance(src, dict) and src.get("valid"):
        return str(src.get("value"))
    return None


def fact_from_row(row: Mapping[str, Any], ioc: bool | None = None) -> Fact:
    """A stored alert row (``Repository`` shape: decoded ``record`` and ``enrichment``)."""
    record = row.get("record") or {}
    raw = record.get("raw_alert") if isinstance(record, dict) else None
    detector = str(row["detector"])
    sev = row.get("severity")
    return Fact(alert_id=str(row["alert_id"]), ts=_epoch(row["ts"]), detector=detector,
                kind=str(row.get("kind") or "event"), rule_id=row.get("rule_id"),
                rule_name=row.get("rule_name"), severity=None if sev is None else int(sev),
                host=row.get("host_ip"), src=_src_ip(row.get("enrichment") or {}),
                techniques=tuple(technique_ids(detector, raw if isinstance(raw, dict) else {})),
                duplicate=bool(record.get("duplicate_of_suricata")) if isinstance(record, dict) else False,
                ioc=ioc)


def tactics_of(tid: str, kb: AttackKB | None) -> tuple[str, ...]:
    if kb is None:
        return ()
    tech = kb.get(tid) or kb.parent(tid)
    return tech.tactics if tech else ()


def technique_name(tid: str, kb: AttackKB | None) -> str | None:
    tech = kb.get(tid) if kb else None
    return tech.name if tech else None


# ---- filters ----------------------------------------------------------------------------------

@dataclass(frozen=True)
class AlertFilter:
    detector: str | None = None
    level: str | None = None
    rule_id: str | None = None
    technique: str | None = None
    host: str | None = None
    ip: str | None = None
    since: float | None = None
    until: float | None = None

    def matches(self, f: Fact, skip: str | None = None) -> bool:
        if self.detector is not None and skip != "detector" and f.detector != self.detector:
            return False
        if self.level is not None and skip != "level" and f.level() != self.level:
            return False
        if self.rule_id is not None and skip != "rule_id" and f.rule_id != self.rule_id:
            return False
        if self.technique is not None and skip != "technique" and not any(
                t == self.technique or t.startswith(self.technique + ".") for t in f.techniques):
            return False
        if self.host is not None and skip != "host" and f.host != self.host:
            return False
        if self.ip is not None and f.src != self.ip and f.host != self.ip:
            return False
        return True

    def describe(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v is not None}


def _facet_value(f: Fact, facet: str) -> list[str]:
    if facet == "detector":
        return [f.detector]
    if facet == "level":
        return [f.level()]
    if facet == "rule_id":
        return [f.rule_id] if f.rule_id is not None else ["none"]
    if facet == "technique":
        return list(f.techniques) or ["unmapped"]
    return [f.host] if f.host is not None else ["none"]


# ---- index ------------------------------------------------------------------------------------

class AlertIndex:
    """Facts of one scenario, sorted by (time, alert id)."""

    def __init__(self, scenario: str, facts: Iterable[Fact], *, ioc_loaded: bool = False) -> None:
        self.scenario = scenario
        self.facts = sorted(facts, key=lambda f: (f.ts, f.alert_id))
        self.times = [f.ts for f in self.facts]
        self.by_id = {f.alert_id: f for f in self.facts}
        self.ioc_loaded = ioc_loaded

    def __len__(self) -> int:
        return len(self.facts)

    def _window(self, flt: AlertFilter) -> Sequence[Fact]:
        lo = 0 if flt.since is None else bisect_left(self.times, flt.since)
        hi = len(self.facts) if flt.until is None else bisect_left(self.times, flt.until)
        return self.facts[lo:hi]

    def select(self, flt: AlertFilter) -> list[Fact]:
        return [f for f in self._window(flt) if flt.matches(f)]

    def facets(self, flt: AlertFilter, top: int = 12) -> dict[str, Any]:
        window = self._window(flt)
        out: dict[str, Any] = {}
        names: dict[str, Counter[str]] = defaultdict(Counter)
        for facet in FACETS:
            counts: Counter[str] = Counter()
            for f in window:
                if flt.matches(f, skip=facet):
                    counts.update(_facet_value(f, facet))
                    if facet == "rule_id" and f.rule_id is not None and f.rule_name:
                        names[f.rule_id][f.rule_name] += 1
            ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
            values = []
            for value, n in ranked[:top]:
                label = names[value].most_common(1)[0][0] if facet == "rule_id" and names[value] else None
                values.append({"value": value, "count": n, "label": label})
            out[facet] = {"values": values, "distinct": len(counts), "shown": len(values)}
        return out

    def timeseries(self, flt: AlertFilter, target: int = 120, start: float | None = None,
                   end: float | None = None) -> dict[str, Any]:
        rows = self.select(flt)
        lo = start if start is not None else (flt.since if flt.since is not None else
                                              (rows[0].ts if rows else None))
        hi = end if end is not None else (flt.until if flt.until is not None else
                                          (rows[-1].ts if rows else None))
        return bin_facts(rows, lo, hi, target)

    def attack_matrix(self, kb: AttackKB | None, flt: AlertFilter | None = None) -> dict[str, Any]:
        rows = self.select(flt) if flt else self.facts
        per_tech: Counter[str] = Counter()
        mapped = 0
        for f in rows:
            if f.techniques:
                mapped += 1
                per_tech.update(set(f.techniques))
        columns: dict[str, list[dict[str, Any]]] = {t: [] for t in TACTIC_ORDER}
        columns[UNKNOWN_TACTIC] = []
        for tid, n in per_tech.items():
            cell = {"technique_id": tid, "name": technique_name(tid, kb), "alerts": n}
            tactics = [t for t in tactics_of(tid, kb) if t in columns] or [UNKNOWN_TACTIC]
            for tac in tactics:
                columns[tac].append(cell)
        tactics_out = []
        for tac in (*TACTIC_ORDER, UNKNOWN_TACTIC):
            cells = sorted(columns[tac], key=lambda c: (-c["alerts"], c["technique_id"]))
            if tac == UNKNOWN_TACTIC and not cells:
                continue
            tactics_out.append({"tactic": tac, "name": kb.tactics.get(tac, TACTIC_NAMES.get(tac, tac))
                                if kb else TACTIC_NAMES.get(tac, "Tactic not in the local ATT&CK bundle"),
                                "alerts": sum(1 for f in rows if any(tac in tactics_of(t, kb) for t in f.techniques))
                                if tac != UNKNOWN_TACTIC else sum(c["alerts"] for c in cells),
                                "techniques": cells})
        return {"tactics": tactics_out, "alerts": len(rows), "mapped_alerts": mapped,
                "unmapped_alerts": len(rows) - mapped, "kb_loaded": kb is not None,
                "kb_version": kb.version if kb else None}

    def entities(self, incidents: Sequence[Mapping[str, Any]], top: int = 10) -> dict[str, Any]:
        worst: dict[str, int] = {}
        in_incidents: Counter[str] = Counter()
        for inc in incidents:
            rank = _sev_rank(str(inc.get("severity")))
            for ent in (inc.get("detail") or {}).get("entities", []):
                in_incidents[ent] += 1
                worst[ent] = min(worst.get(ent, 9), rank)
        out: dict[str, Any] = {}
        for kind, attr in (("host", "host"), ("ip", "src")):
            counts: Counter[str] = Counter()
            by_det: dict[str, Counter[str]] = defaultdict(Counter)
            for f in self.facts:
                value = getattr(f, attr)
                if value is not None:
                    counts[value] += 1
                    by_det[value][f.detector] += 1
            ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:top]
            out[kind] = {"distinct": len(counts), "rows": [
                {"value": v, "alerts": n, "by_detector": dict(by_det[v]),
                 "severity": SEVERITIES[worst[f"{kind}:{v}"]] if worst.get(f"{kind}:{v}", 9) < 3 else None,
                 "incidents": in_incidents[f"{kind}:{v}"]} for v, n in ranked]}
        return out

    def detector_comparison(self) -> list[dict[str, Any]]:
        rows = []
        present = Counter(f.detector for f in self.facts)
        for det in [d for d in DETECTOR_ORDER if d in present] + sorted(set(present) - set(DETECTOR_ORDER)):
            facts = [f for f in self.facts if f.detector == det]
            n = len(facts)
            mapped = sum(1 for f in facts if f.techniques)
            dup = sum(1 for f in facts if f.duplicate)
            ioc = sum(1 for f in facts if f.ioc) if self.ioc_loaded else None
            rows.append({"detector": det, "alerts": n, "mapped": mapped, "mapped_share": mapped / n,
                         "ioc": ioc, "ioc_share": None if ioc is None else ioc / n,
                         "duplicates": dup, "duplicate_share": dup / n,
                         "aggregates": sum(1 for f in facts if f.kind == "aggregate")})
        return rows

    def search_values(self, q: str, limit: int = 10) -> dict[str, list[dict[str, Any]]]:
        """Exact or prefix matches on IPs (host or source) and rule ids."""
        ips: Counter[str] = Counter()
        rules: Counter[str] = Counter()
        names: dict[str, str] = {}
        for f in self.facts:
            for v in (f.host, f.src):
                if v is not None and v.startswith(q):
                    ips[v] += 1
            if f.rule_id is not None and f.rule_id.startswith(q):
                rules[f.rule_id] += 1
                if f.rule_name:
                    names.setdefault(f.rule_id, f.rule_name)
        def rank(c: Counter[str]) -> list[tuple[str, int]]:
            return sorted(c.items(), key=lambda kv: (kv[0] != q, -kv[1], kv[0]))[:limit]

        return {"ips": [{"value": v, "alerts": n} for v, n in rank(ips)],
                "rules": [{"value": v, "alerts": n, "label": names.get(v)} for v, n in rank(rules)]}


def _run_key(f: Fact) -> tuple[Any, ...]:
    return (f.detector, f.rule_id, f.rule_name, f.severity, f.host, f.src)


def alert_runs(rows: Sequence[Fact]) -> list[dict[str, Any]]:
    """Consecutive alerts (time order) that repeat the same detector, rule, level, host and source IP,
    collapsed into one row with a count. Nothing is dropped: the counts add up to ``len(rows)``."""
    out: list[dict[str, Any]] = []
    i = 0
    while i < len(rows):
        j = i
        key = _run_key(rows[i])
        while j + 1 < len(rows) and _run_key(rows[j + 1]) == key:
            j += 1
        a, b = rows[i], rows[j]
        out.append({"first_alert_id": a.alert_id, "last_alert_id": b.alert_id, "count": j - i + 1,
                    "detector": a.detector, "rule_id": a.rule_id, "rule_name": a.rule_name,
                    "severity": a.severity, "host_ip": a.host, "src_ip": a.src,
                    "techniques": list(a.techniques), "first_ts": iso(a.ts), "last_ts": iso(b.ts)})
        i = j + 1
    return out


def bin_facts(rows: Sequence[Fact], lo: float | None, hi: float | None, target: int = 120) -> dict[str, Any]:
    if lo is None or hi is None:
        return {"start": None, "end": None, "bin_seconds": None, "bins": 0, "series": {}, "total": 0}
    step = bin_seconds(hi - lo, target)
    start = math.floor(lo / step) * step
    n = max(1, math.floor((hi - start) / step) + 1)
    series: dict[str, list[int]] = {}
    for f in rows:
        i = int((f.ts - start) // step)
        if 0 <= i < n:
            series.setdefault(f.detector, [0] * n)[i] += 1
    ordered = {d: series[d] for d in DETECTOR_ORDER if d in series}
    ordered.update({d: series[d] for d in sorted(series) if d not in ordered})
    return {"start": iso(start), "end": iso(start + n * step), "bin_seconds": step, "bins": n,
            "series": ordered, "total": sum(sum(v) for v in ordered.values())}


def kill_chain(rows: Iterable[Fact], kb: AttackKB | None) -> list[dict[str, Any]]:
    """Tactics in ATT&CK order with the alerts behind each; a tactic with 0 alerts is a gap."""
    stats: dict[str, dict[str, Any]] = {t: {"alerts": 0, "techniques": Counter(), "first": None,
                                            "last": None} for t in TACTIC_ORDER}
    for f in rows:
        seen: set[str] = set()
        for tid in f.techniques:
            for tac in tactics_of(tid, kb):
                if tac not in stats:
                    continue
                s = stats[tac]
                s["techniques"][tid] += 1
                if tac in seen:
                    continue
                seen.add(tac)
                s["alerts"] += 1
                s["first"] = f.ts if s["first"] is None else min(s["first"], f.ts)
                s["last"] = f.ts if s["last"] is None else max(s["last"], f.ts)
    return [{"tactic": t, "name": TACTIC_NAMES[t], "alerts": s["alerts"],
             "techniques": [{"technique_id": k, "name": technique_name(k, kb), "alerts": v}
                            for k, v in sorted(s["techniques"].items(), key=lambda kv: (-kv[1], kv[0]))],
             "first_ts": iso(s["first"]) if s["first"] is not None else None,
             "last_ts": iso(s["last"]) if s["last"] is not None else None}
            for t, s in stats.items()]


# ---- incidents --------------------------------------------------------------------------------

def _sev_rank(sev: str) -> int:
    return SEVERITIES.index(sev) if sev in SEVERITIES else 3


def incident_row(inc: Mapping[str, Any]) -> dict[str, Any]:
    """An incident without its timeline (the list endpoints' summary shape)."""
    detail = dict(inc.get("detail") or {})
    timeline = detail.pop("timeline", None)
    return {"incident_id": inc["incident_id"], "scenario": inc["scenario"], "first_ts": str(inc["first_ts"]),
            "last_ts": str(inc["last_ts"]), "severity": inc["severity"], "status": inc.get("status"),
            "alerts": len(inc.get("alert_ids") or timeline or []), "created_utc": str(inc.get("created_utc")),
            "detail": detail}


def main_entities(alert_ids: Sequence[str], by_id: Mapping[str, Fact]) -> dict[str, Any]:
    """The host and the source IP with the most alerts in an incident (ties: smallest value), so a
    list can name an incident by its main entity. The stored ``entities`` list is sorted by value."""
    hosts: Counter[str] = Counter()
    srcs: Counter[str] = Counter()
    for aid in alert_ids:
        f = by_id.get(aid)
        if f is None:
            continue
        if f.host:
            hosts[f.host] += 1
        if f.src:
            srcs[f.src] += 1

    def top(c: Counter[str]) -> str | None:
        return min(c.items(), key=lambda kv: (-kv[1], kv[0]))[0] if c else None

    return {"main_host": top(hosts), "main_ip": top(srcs)}


def with_main_entities(rows: list[dict[str, Any]], incidents: Mapping[str, Mapping[str, Any]],
                       by_id: Mapping[str, Fact]) -> list[dict[str, Any]]:
    """``incident_row``-shaped rows with ``detail.main_host`` / ``detail.main_ip`` added."""
    out = []
    for r in rows:
        inc = incidents.get(r["incident_id"]) or {}
        out.append({**r, "detail": {**r.get("detail", {}), **main_entities(inc.get("alert_ids") or [], by_id)}})
    return out


def queue_summary(incidents: Sequence[Mapping[str, Any]], approvals: Sequence[Mapping[str, Any]],
                  now: float) -> dict[str, Any]:
    grid = {s: {st: 0 for st in STATUSES} for s in SEVERITIES}
    ages = {s: {label: 0 for label, _ in AGE_BUCKETS} for s in SEVERITIES}
    oldest: dict[str, Any] | None = None
    for inc in incidents:
        sev, status = str(inc["severity"]), str(inc.get("status") or "open")
        if sev not in grid:
            continue
        grid[sev][status if status in STATUSES else "open"] += 1
        if status == "closed":
            continue
        age = max(0.0, now - _epoch(str(inc["created_utc"])))
        label = next(lbl for lbl, limit in AGE_BUCKETS if age < limit)
        ages[sev][label] += 1
        if sev == "High" and status == "open" and (oldest is None or age > oldest["age_seconds"]):
            oldest = {"incident_id": inc["incident_id"], "created_utc": str(inc["created_utc"]),
                      "age_seconds": age, "alerts": len(inc.get("alert_ids") or [])}
    return {"by_severity_status": grid, "age_in_queue": ages, "age_buckets": [b for b, _ in AGE_BUCKETS],
            "open_by_severity": {s: sum(v for st, v in grid[s].items() if st != "closed") for s in SEVERITIES},
            "oldest_unreviewed_high": oldest,
            "pending_approvals": sum(1 for a in approvals if a.get("status") == "pending"),
            "incidents": sum(sum(v.values()) for v in grid.values())}


def incident_starts(incidents: Sequence[Mapping[str, Any]], limit: int = 80) -> dict[str, Any]:
    """Start times of High and Medium incidents (axis markers); Low ones are only counted."""
    marked = sorted((i for i in incidents if i["severity"] in ("High", "Medium")),
                    key=lambda i: (_sev_rank(str(i["severity"])), str(i["first_ts"])))[:limit]
    return {"markers": sorted(({"incident_id": i["incident_id"], "ts": str(i["first_ts"]),
                                "severity": i["severity"]} for i in marked), key=lambda m: m["ts"]),
            "low_not_marked": sum(1 for i in incidents if i["severity"] == "Low"),
            "omitted": max(0, sum(1 for i in incidents if i["severity"] in ("High", "Medium")) - limit)}


def severity_rule(row_id: str | None) -> dict[str, Any] | None:
    from app.detection.triage import SEVERITY_TABLE

    for row in SEVERITY_TABLE:
        if row.row_id == row_id:
            return {"row": row.row_id, "severity": row.severity, "rule": row.rule}
    return None


def entity_graph(rows: Iterable[Fact]) -> dict[str, Any]:
    """Hosts and source IPs as nodes; an edge per (source IP, host) pair with counts per detector."""
    nodes: Counter[str] = Counter()
    node_det: dict[str, Counter[str]] = defaultdict(Counter)
    edges: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    for f in rows:
        host = f"host:{f.host}" if f.host else None
        src = f"ip:{f.src}" if f.src and f.src != f.host else None
        for node in (host, src):
            if node:
                nodes[node] += 1
                node_det[node][f.detector] += 1
        if host and src:
            edges[(src, host)][f.detector] += 1
    ranked = sorted(nodes.items(), key=lambda kv: (-kv[1], kv[0]))
    kept = {n for n, _ in ranked[:MAX_GRAPH_NODES]}
    return {"nodes": [{"id": n, "kind": n.split(":", 1)[0], "value": n.split(":", 1)[1], "alerts": c,
                       "by_detector": dict(node_det[n])} for n, c in ranked[:MAX_GRAPH_NODES]],
            "edges": sorted(({"source": s, "target": t, "alerts": sum(c.values()), "by_detector": dict(c)}
                             for (s, t), c in edges.items() if s in kept and t in kept),
                            key=lambda e: (-e["alerts"], e["source"], e["target"])),
            "nodes_total": len(nodes), "nodes_omitted": max(0, len(nodes) - MAX_GRAPH_NODES)}


def tactic_lanes(rows: Sequence[Fact], lo: float, hi: float, kb: AttackKB | None,
                 target: int = 120) -> dict[str, Any]:
    step = bin_seconds(hi - lo, target)
    start = math.floor(lo / step) * step
    n = max(1, math.floor((hi - start) / step) + 1)
    lanes: dict[str, list[int]] = {}
    unmapped = 0
    for f in rows:
        tacs = {t for tid in f.techniques for t in tactics_of(tid, kb)}
        if not f.techniques:
            unmapped += 1
            continue
        i = int((f.ts - start) // step)
        for tac in tacs or {UNKNOWN_TACTIC}:
            lanes.setdefault(tac, [0] * n)[i] += 1
    order = [t for t in (*TACTIC_ORDER, UNKNOWN_TACTIC) if t in lanes]
    return {"start": iso(start), "end": iso(start + n * step), "bin_seconds": step, "bins": n,
            "lanes": [{"tactic": t, "name": TACTIC_NAMES.get(t, "Technique not in the local bundle"),
                       "bins": [[i, c] for i, c in enumerate(lanes[t]) if c]} for t in order],
            "unmapped_alerts": unmapped}


def incident_analysis(inc: Mapping[str, Any], rows: Sequence[Fact], kb: AttackKB | None) -> dict[str, Any]:
    detail = inc.get("detail") or {}
    lo, hi = _epoch(str(inc["first_ts"])), _epoch(str(inc["last_ts"]))
    return {"incident_id": inc["incident_id"],
            "summary": {"severity": inc["severity"], "status": inc.get("status"),
                        "rule": severity_rule(detail.get("severity_row")),
                        "inputs": detail.get("features"), "first_ts": str(inc["first_ts"]),
                        "last_ts": str(inc["last_ts"]), "alerts": len(inc.get("alert_ids") or []),
                        "alerts_found": len(rows), "detectors": detail.get("detectors") or {},
                        "detectors_agreeing": len(detail.get("detectors") or {}),
                        "gap_seconds": detail.get("gap_seconds")},
            "graph": entity_graph(rows),
            "lanes": tactic_lanes(rows, lo, hi, kb),
            "timeseries": bin_facts(rows, lo, hi, 120),
            "kill_chain": kill_chain(rows, kb)}


def placed_graph(graph: Mapping[str, Any], limit: int = GRAPH_SHOWN, width: float = GRAPH_W,
                 height: float = GRAPH_H) -> dict[str, Any]:
    """The first ``limit`` nodes of :func:`entity_graph` with positions from the shared layout."""
    nodes = list(graph["nodes"])[:limit]
    ids = [str(n["id"]) for n in nodes]
    keep = set(ids)
    edges = [e for e in graph["edges"] if e["source"] in keep and e["target"] in keep]
    pos = {pl.id: pl for pl in layout(ids, [(e["source"], e["target"]) for e in edges], width, height)}
    return {"width": width, "height": height, "edges": edges,
            "nodes": [{**n, "x": pos[n["id"]].x, "y": pos[n["id"]].y} for n in nodes],
            "nodes_total": graph["nodes_total"], "nodes_shown": len(nodes)}


def report_charts(inc: Mapping[str, Any], rows: Sequence[Fact]) -> dict[str, Any]:
    """Charts stored in a report body: the alert timeline by detector and the entity graph."""
    lo, hi = _epoch(str(inc["first_ts"])), _epoch(str(inc["last_ts"]))
    return {"timeseries": bin_facts(rows, lo, hi, 60), "graph": placed_graph(entity_graph(rows))}


def first_review(audit: Iterable[Mapping[str, Any]]) -> dict[str, float]:
    """First ``incident.update`` time per incident (the review moment) from audit entries."""
    out: dict[str, float] = {}
    for e in audit:
        if e.get("action") == "incident.update" and e.get("target"):
            t = _epoch(str(e["ts"]))
            key = str(e["target"])
            out[key] = min(out.get(key, t), t)
    return out


def executive_summary(incidents: Sequence[Mapping[str, Any]], approvals: Sequence[Mapping[str, Any]],
                      audit: Sequence[Mapping[str, Any]], chain: list[dict[str, Any]],
                      now: float) -> dict[str, Any]:
    by_day: dict[str, Counter[str]] = defaultdict(Counter)
    for inc in incidents:
        by_day[str(inc["first_ts"])[:10]][str(inc["severity"])] += 1
    reviewed = first_review(audit)
    waits = []
    for inc in incidents:
        t = reviewed.get(str(inc["incident_id"]))
        if t is not None:
            waits.append(max(0.0, t - _epoch(str(inc["created_utc"]))))
    risks = sorted((i for i in incidents if i.get("status") != "closed" and i["severity"] in ("High", "Medium")),
                   key=lambda i: (_sev_rank(str(i["severity"])), -len(i.get("alert_ids") or []),
                                  str(i["first_ts"])))[:5]
    pending = [a for a in approvals if a.get("status") == "pending"]
    return {"severity_trend": [{"day": d, **{s: by_day[d].get(s, 0) for s in SEVERITIES}}
                               for d in sorted(by_day)],
            "top_risks": [{**incident_row(i), "rule": severity_rule((i.get("detail") or {}).get("severity_row"))}
                          for i in risks],
            "coverage": [{"tactic": c["tactic"], "name": c["name"], "alerts": c["alerts"],
                          "techniques": len(c["techniques"])} for c in chain],
            "time_to_review": {"reviewed": len(waits), "unreviewed": len(incidents) - len(waits),
                               "median_seconds": median(waits) if waits else None,
                               "max_seconds": max(waits) if waits else None},
            "open_approvals": {"pending": len(pending),
                               "oldest_utc": min((str(a["created_utc"]) for a in pending), default=None)},
            "queue": queue_summary(incidents, approvals, now)}


def entity_view(index: AlertIndex, incidents: Sequence[Mapping[str, Any]], kind: str,
                value: str) -> dict[str, Any]:
    rows = [f for f in index.facts if (f.host == value if kind == "host" else f.src == value)]
    rules: Counter[tuple[str, str]] = Counter((f.rule_id or "none", f.rule_name or "") for f in rows)
    key = f"{kind}:{value}"
    related = [incident_row(i) for i in incidents if key in ((i.get("detail") or {}).get("entities") or [])]
    related.sort(key=lambda r: (_sev_rank(str(r["severity"])), r["first_ts"]))
    return {"kind": kind, "value": value, "alerts": len(rows),
            "by_detector": dict(Counter(f.detector for f in rows)),
            "first_ts": iso(rows[0].ts) if rows else None, "last_ts": iso(rows[-1].ts) if rows else None,
            "timeseries": bin_facts(rows, rows[0].ts if rows else None, rows[-1].ts if rows else None),
            "top_rules": [{"rule_id": r, "rule_name": n or None, "alerts": c} for (r, n), c in rules.most_common(10)],
            "incidents": related[:200], "incidents_total": len(related)}


def facts_between(index: AlertIndex, ids: Sequence[str]) -> list[Fact]:
    rows = [index.by_id[i] for i in ids if i in index.by_id]
    rows.sort(key=lambda f: (f.ts, f.alert_id))
    return rows


__all__ = ["AlertFilter", "AlertIndex", "EXPORT_COLUMNS", "Fact", "TACTIC_ORDER", "bin_facts",
           "bin_seconds", "entity_graph", "entity_view", "executive_summary", "fact_from_row",
           "facts_between", "incident_analysis", "incident_row", "incident_starts", "kill_chain",
           "placed_graph", "queue_summary", "report_charts", "severity_rule"]
