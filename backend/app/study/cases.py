"""Case-based study units: attack-phase cases and matched benign-window cases.

A *case* is a time window of one scenario that an investigation agent is
given, together with the alerts one alert source raised in that window:

- **attack case**: one per (scenario, attack phase) in labels.csv; the
  window is the phase interval ``[start, end)`` widened by
  ``padding_seconds`` on each side.
- **benign case**: for each attack case, ``benign_per_attack`` windows of
  the same length drawn from time that is (a) inside the scenario's
  observation range (first to last investigation-eligible alert), (b)
  outside every attack interval widened by the padding, and (c) disjoint
  from the benign windows already drawn. Windows start on whole seconds,
  uniformly over all valid starts, with one seeded RNG per scenario,
  processing attack cases in time order. When no valid start is left the
  case is listed under ``unavailable`` in the sampling log, not invented.

For each case and variant the alerts are those with
``window_start <= timestamp < window_end``, time-ordered. A case holds at
most ``max_alerts``; with the ``earliest`` rule the first ``max_alerts`` by
time are kept (the order an analyst's queue shows them). Every truncation
is recorded: alerts dropped, and how many of those were attack-labelled by
event_label and by time_label, so a cap that hides an attack is visible.

Ceilings: scoring a case as if the agent cited *every* alert it was given
gives the best coverage any agent could reach from that alert source.
These are ceilings, not agent results.
"""

from __future__ import annotations

import bisect
import json
import math
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any

from app.evaluation.case_scoring import CaseScore, score_case
from app.ingestion.ground_truth import AttackTimeline
from app.study.config import TRUNCATION_CHOICES, CaseConfig, StudyConfig
from app.study.variants import AlertPool, PoolEntry, Variant, derive_seed, experiment_variants


class CaseKind(StrEnum):
    ATTACK = "attack"
    BENIGN = "benign"


@dataclass(frozen=True)
class Case:
    case_id: str
    scenario: str
    kind: CaseKind
    phase: str  # the attack phase; for a benign case, the phase it is matched to
    start: datetime
    end: datetime
    padding_seconds: int

    @property
    def window_start(self) -> datetime:
        return self.start - timedelta(seconds=self.padding_seconds)

    @property
    def window_end(self) -> datetime:
        return self.end + timedelta(seconds=self.padding_seconds)


@dataclass(frozen=True)
class CaseSet:
    scenario: str
    cases: tuple[Case, ...]
    benign_sampling: dict[str, Any]


def _utc(seconds: float) -> datetime:
    return datetime.fromtimestamp(seconds, tz=timezone.utc)


def _subtract(free: list[tuple[float, float]], lo: float, hi: float) -> list[tuple[float, float]]:
    result = []
    for a, b in free:
        if hi <= a or lo >= b:
            result.append((a, b))
            continue
        if a < lo:
            result.append((a, lo))
        if hi < b:
            result.append((hi, b))
    return result


def _valid_starts(free: list[tuple[float, float]], length: float) -> list[tuple[int, int]]:
    """Inclusive ranges of whole-second starts x with [x, x + length) inside a free segment."""
    ranges = []
    for a, b in free:
        first, last = math.ceil(a), math.floor(b - length)
        if last >= first:
            ranges.append((first, last))
    return ranges


def build_cases(pool: AlertPool, timeline: AttackTimeline, config: CaseConfig) -> CaseSet:
    scenario = pool.scenario
    pad = config.padding_seconds
    attack = [
        Case(f"{scenario}:attack:{i.attack}", scenario, CaseKind.ATTACK, i.attack, i.start, i.end, pad)
        for i in timeline.intervals
    ]
    derived = derive_seed(config.seed, "benign", scenario)
    rng = random.Random(derived)
    log: dict[str, Any] = {
        "rule": ("per attack case, benign_per_attack windows of equal length; whole-second "
                 "start drawn uniformly from all starts whose padded window lies inside the "
                 "observation range, outside every attack interval widened by the padding, "
                 "and disjoint from earlier benign windows; attack cases in time order"),
        "seed": config.seed,
        "derived_seed": derived,
        "benign_per_attack": config.benign_per_attack,
        "observation_range": None,
        "free_seconds": 0,
        "unavailable": [],
    }
    benign: list[Case] = []
    if pool.entries:
        lo, hi = pool.entries[0].timestamp.timestamp(), pool.entries[-1].timestamp.timestamp()
        log["observation_range"] = [_utc(lo).isoformat(), _utc(hi).isoformat()]
        free = [(lo, hi)]
        for interval in timeline.intervals:
            free = _subtract(free, interval.start.timestamp() - pad, interval.end.timestamp() + pad)
        log["free_seconds"] = sum(b - a for a, b in free)
        for case in attack:
            duration = (case.end - case.start).total_seconds()
            for k in range(1, config.benign_per_attack + 1):
                case_id = f"{scenario}:benign:{case.phase}:{k}"
                ranges = _valid_starts(free, duration + 2 * pad)
                total = sum(last - first + 1 for first, last in ranges)
                if total == 0:
                    log["unavailable"].append(case_id)
                    continue
                pick = rng.randrange(total)
                window_start = ranges[-1][1]  # overwritten below; pick < total guarantees a hit
                for first, last in ranges:
                    if pick <= last - first:
                        window_start = first + pick
                        break
                    pick -= last - first + 1
                start = _utc(window_start + pad)
                benign.append(Case(case_id, scenario, CaseKind.BENIGN, case.phase, start,
                                   start + (case.end - case.start), pad))
                free = _subtract(free, window_start, window_start + duration + 2 * pad)
    return CaseSet(scenario, tuple(attack + benign), log)


@dataclass(frozen=True)
class CaseAlerts:
    """One variant's alerts for one case, after the cap."""

    case_id: str
    variant: str
    entries: tuple[PoolEntry, ...]
    in_window: int
    dropped: int
    dropped_event_attack: int
    dropped_time_attack: int
    in_phase_before_cap: int
    in_phase_event_attack_before_cap: int
    truncation_rule: str


def in_phase(case: Case, entry: PoolEntry) -> bool:
    """Inside the case's own interval (not the padding). Benign cases have no phase."""
    return case.kind is CaseKind.ATTACK and case.start <= entry.timestamp < case.end


def case_alerts(case: Case, variant: Variant, *, max_alerts: int, truncation: str) -> CaseAlerts:
    if truncation not in TRUNCATION_CHOICES:
        raise ValueError(f"truncation must be one of {', '.join(TRUNCATION_CHOICES)}")
    times = [e.timestamp for e in variant.entries]  # variants are time-ordered
    lo = bisect.bisect_left(times, case.window_start)
    hi = bisect.bisect_left(times, case.window_end)
    window = variant.entries[lo:hi]
    kept, dropped = window[:max_alerts], window[max_alerts:]
    return CaseAlerts(
        case_id=case.case_id,
        variant=variant.name,
        entries=kept,
        in_window=len(window),
        dropped=len(dropped),
        dropped_event_attack=sum(bool(e.event_attack) for e in dropped),
        dropped_time_attack=sum(e.time_attack for e in dropped),
        in_phase_before_cap=sum(in_phase(case, e) for e in window),
        in_phase_event_attack_before_cap=sum(in_phase(case, e) and bool(e.event_attack) for e in window),
        truncation_rule=(f"earliest {max_alerts} by timestamp (tiebreak source_file, source_line); "
                         "later alerts dropped"),
    )


def _rate(covered: int, cases: int) -> dict[str, Any]:
    return {"covered": covered, "cases": cases, "rate": covered / cases if cases else None}


def _mean(values: list[int]) -> float | None:
    return sum(values) / len(values) if values else None


def _summary(cases: tuple[Case, ...], views: list[CaseAlerts], scores: list[CaseScore]) -> dict[str, Any]:
    kinds = [c.kind for c in cases]
    attack = [i for i, k in enumerate(kinds) if k is CaseKind.ATTACK]
    benign = [i for i, k in enumerate(kinds) if k is CaseKind.BENIGN]
    return {
        "attack_cases": len(attack),
        "benign_cases": len(benign),
        "coverage_ceiling": {
            "time_label": _rate(sum(scores[i].coverage_time == 1.0 for i in attack), len(attack)),
            "event_label": _rate(sum(scores[i].coverage_event == 1.0 for i in attack), len(attack)),
        },
        "coverage_ceiling_before_cap": {
            "time_label": _rate(sum(views[i].in_phase_before_cap > 0 for i in attack), len(attack)),
            "event_label": _rate(sum(views[i].in_phase_event_attack_before_cap > 0 for i in attack),
                                 len(attack)),
        },
        "mean_alerts_per_case": {
            "attack": _mean([scores[i].load for i in attack]),
            "benign": _mean([scores[i].load for i in benign]),
            "all": _mean([s.load for s in scores]),
        },
        "mean_alerts_in_window_before_cap": {
            "attack": _mean([views[i].in_window for i in attack]),
            "benign": _mean([views[i].in_window for i in benign]),
            "all": _mean([v.in_window for v in views]),
        },
        "truncation": {
            "cases_truncated": sum(v.dropped > 0 for v in views),
            "alerts_dropped": sum(v.dropped for v in views),
            "cases_cap_dropped_event_attack": sum(v.dropped_event_attack > 0 for v in views),
            "cases_cap_dropped_time_attack": sum(v.dropped_time_attack > 0 for v in views),
        },
        "benign_cases_with_event_attack_alert": sum(
            any(e.event_attack for e in views[i].entries) for i in benign),
    }


def _dump(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
                    encoding="utf-8")


def dev_case_report(processed_dir: str | Path, labels_path: str | Path, scenario: str,
                    config: StudyConfig, *, output_dir: str | Path | None = None) -> dict[str, Any]:
    """Build the cases of a dev scenario and their per-variant coverage ceilings."""
    config.split.require_dev(scenario)
    cfg = config.cases
    pool = AlertPool.from_processed(processed_dir, scenario)
    timeline = AttackTimeline.from_labels_csv(labels_path, scenario)
    case_set = build_cases(pool, timeline, cfg)
    variants = experiment_variants(pool, config)

    case_records: list[dict[str, Any]] = [
        {"case_id": c.case_id, "kind": c.kind.value, "phase": c.phase,
         "start": c.start.isoformat(), "end": c.end.isoformat(),
         "window_start": c.window_start.isoformat(), "window_end": c.window_end.isoformat(),
         "variants": {}}
        for c in case_set.cases
    ]
    summaries: dict[str, Any] = {}
    for name, variant in variants.items():
        views = [case_alerts(c, variant, max_alerts=cfg.max_alerts, truncation=cfg.truncation)
                 for c in case_set.cases]
        # Ceiling: the agent cites every alert it was given; no claims.
        scores = [score_case(c, v, [e.alert_id for e in v.entries])
                  for c, v in zip(case_set.cases, views)]
        summaries[name] = _summary(case_set.cases, views, scores)
        for record, view, score in zip(case_records, views, scores):
            record["variants"][name] = {
                "alerts_in_window": view.in_window,
                "load": score.load,
                "dropped": view.dropped,
                "dropped_event_attack": view.dropped_event_attack,
                "dropped_time_attack": view.dropped_time_attack,
                "in_phase_before_cap": view.in_phase_before_cap,
                "in_phase_event_attack_before_cap": view.in_phase_event_attack_before_cap,
                "truncation_rule": view.truncation_rule,
                "ceiling_coverage_time": score.coverage_time,
                "ceiling_coverage_event": score.coverage_event,
                "alert_ids": [e.alert_id for e in view.entries],
            }

    case_config = {"seed": cfg.seed, "padding_seconds": cfg.padding_seconds,
                   "max_alerts": cfg.max_alerts, "truncation": cfg.truncation,
                   "benign_per_attack": cfg.benign_per_attack}
    report: dict[str, Any] = {
        "scenario": scenario,
        "scenario_split": "dev",
        "note": ("DEV-SCENARIO CEILINGS: best coverage any agent could reach from each alert "
                 "source (agent cites every alert it is given); not agent results"),
        "study_config": config.source,
        "case_config": case_config,
        "cases": {"attack": sum(c.kind is CaseKind.ATTACK for c in case_set.cases),
                  "benign": sum(c.kind is CaseKind.BENIGN for c in case_set.cases)},
        "benign_sampling": case_set.benign_sampling,
        "variants": summaries,
    }
    if output_dir is not None:
        out = Path(output_dir) / scenario
        out.mkdir(parents=True, exist_ok=True)
        _dump(out / f"{scenario}.cases.json", {
            "scenario": scenario, "study_config": config.source, "case_config": case_config,
            "benign_sampling": case_set.benign_sampling,
            "source": {"alerts_file": pool.alerts_path.name, "alerts_sha256": pool.alerts_sha256,
                       "labels_file": Path(labels_path).name},
            "cases": case_records,
        })
        _dump(out / f"{scenario}.case_ceilings.json", report)
    return report
