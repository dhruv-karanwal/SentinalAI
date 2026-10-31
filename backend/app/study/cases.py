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

Every case records the time of day (UTC) of its start and end; benign
windows are deliberately not matched on time of day.

For each case and variant the alerts are those with
``window_start <= timestamp < window_end``, time-ordered. A case holds at
most ``max_alerts``. The default ``spread`` rule keeps alerts at evenly
spaced time ranks across the window, so long phases are seen from start to
end; ``earliest`` keeps the first ``max_alerts`` (analyst-queue order).
Every truncation is recorded: the rule, alerts dropped, and how many of
those were attack-labelled by event_label and by time_label.

Noise controls (``noise-<det>``) are rebuilt per case: as many alerts as
``<det>`` has in the window (before the cap), drawn from event-benign
alerts of the same window first, then from the scenario pool's other
event-benign alerts (which then lie outside the window), with the split
recorded. The cap then applies as for any variant.

Ceilings: scoring a case as if the agent cited *every* alert it was given
gives the best coverage any agent could reach from that alert source.
Baselines (app.study.baselines) are deterministic non-LLM citers scored on
every variant. Both are reference points, not agent results.
"""

from __future__ import annotations

import bisect
import json
import math
import random
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any

from app.evaluation.case_scoring import CaseScore, alert_claim_index, alert_quote_index, score_case
from app.ingestion.ground_truth import AttackTimeline
from app.study.baselines import BASELINE_NAMES, baseline_citations, baseline_claims
from app.study.config import TRUNCATION_CHOICES, BaselineConfig, CaseConfig, StudyConfig
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
    in_window: int  # before the cap (for a noise control: the alerts drawn)
    dropped: int
    dropped_event_attack: int
    dropped_time_attack: int
    in_phase_before_cap: int
    in_phase_event_attack_before_cap: int
    truncation_rule: str
    noise: dict[str, int] | None = None


def in_phase(case: Case, entry: PoolEntry) -> bool:
    """Inside the case's own interval (not the padding). Benign cases have no phase."""
    return case.kind is CaseKind.ATTACK and case.start <= entry.timestamp < case.end


def _time_key(entry: PoolEntry) -> tuple[datetime, str, int]:
    return (entry.timestamp, entry.source_file, entry.source_line)


def _truncate(window: Sequence[PoolEntry], max_alerts: int,
              truncation: str) -> tuple[tuple[PoolEntry, ...], tuple[PoolEntry, ...], str]:
    if truncation not in TRUNCATION_CHOICES:
        raise ValueError(f"truncation must be one of {', '.join(TRUNCATION_CHOICES)}")
    n = len(window)
    if truncation == "earliest":
        keep = set(range(min(n, max_alerts)))
        rule = (f"earliest {max_alerts} by timestamp (tiebreak source_file, source_line); "
                "later alerts dropped")
    else:
        keep = (set(range(n)) if n <= max_alerts
                else {((2 * i + 1) * n) // (2 * max_alerts) for i in range(max_alerts)})
        rule = (f"spread: {max_alerts} alerts at evenly spaced time ranks "
                f"floor((i + 0.5) * n / {max_alerts}), i = 0..{max_alerts - 1}, of the n alerts "
                "in the window (time order, tiebreak source_file, source_line)")
    kept = tuple(window[i] for i in range(n) if i in keep)
    dropped = tuple(window[i] for i in range(n) if i not in keep)
    return kept, dropped, rule


def _view(case: Case, name: str, window: Sequence[PoolEntry], max_alerts: int, truncation: str,
          noise: dict[str, int] | None = None) -> CaseAlerts:
    kept, dropped, rule = _truncate(window, max_alerts, truncation)
    return CaseAlerts(
        case_id=case.case_id,
        variant=name,
        entries=kept,
        in_window=len(window),
        dropped=len(dropped),
        dropped_event_attack=sum(bool(e.event_attack) for e in dropped),
        dropped_time_attack=sum(e.time_attack for e in dropped),
        in_phase_before_cap=sum(in_phase(case, e) for e in window),
        in_phase_event_attack_before_cap=sum(in_phase(case, e) and bool(e.event_attack) for e in window),
        truncation_rule=rule,
        noise=noise,
    )


def _window(entries: Sequence[PoolEntry], case: Case) -> tuple[int, int]:
    times = [e.timestamp for e in entries]  # time-ordered
    return bisect.bisect_left(times, case.window_start), bisect.bisect_left(times, case.window_end)


def case_alerts(case: Case, variant: Variant, *, max_alerts: int, truncation: str) -> CaseAlerts:
    lo, hi = _window(variant.entries, case)
    return _view(case, variant.name, variant.entries[lo:hi], max_alerts, truncation)


def noise_case_alerts(case: Case, benign: Sequence[PoolEntry], count: int, *, seed: int, name: str,
                      max_alerts: int, truncation: str) -> CaseAlerts:
    """``count`` event-benign alerts for a case: same window first, scenario pool as fallback.

    ``benign`` is the pool's event-benign alerts in time order. The split
    (from_window / from_fallback / shortfall) is recorded on the view.
    """
    lo, hi = _window(benign, case)
    inside, outside = list(benign[lo:hi]), list(benign[:lo]) + list(benign[hi:])
    rng = random.Random(derive_seed(seed, "noise-case", case.case_id, name))
    from_window = min(count, len(inside))
    chosen = [inside[i] for i in rng.sample(range(len(inside)), from_window)]
    from_fallback = min(count - from_window, len(outside))
    chosen += [outside[i] for i in rng.sample(range(len(outside)), from_fallback)]
    chosen.sort(key=_time_key)
    record = {"reference_count": count, "from_window": from_window, "from_fallback": from_fallback,
              "shortfall": count - from_window - from_fallback}
    return _view(case, name, chosen, max_alerts, truncation, noise=record)


def variant_case_views(case_set: CaseSet, variants: dict[str, Variant], pool: AlertPool,
                       config: CaseConfig) -> dict[str, list[CaseAlerts]]:
    """Case views for every variant; noise controls are rebuilt per case."""
    views: dict[str, list[CaseAlerts]] = {}
    benign = pool.event_benign()
    for name, variant in variants.items():
        if variant.family == "noise":
            reference = views[str(variant.reference)]  # detectors come before noise controls
            views[name] = [
                noise_case_alerts(case, benign, ref.in_window, seed=config.seed, name=name,
                                  max_alerts=config.max_alerts, truncation=config.truncation)
                for case, ref in zip(case_set.cases, reference)]
        else:
            views[name] = [case_alerts(case, variant, max_alerts=config.max_alerts,
                                       truncation=config.truncation) for case in case_set.cases]
    return views


def reachable_phases(case_set: CaseSet, pool: AlertPool) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Attack phases with / without an event-labelled pool alert inside the phase interval."""
    times = [e.timestamp for e in pool.entries]
    reachable: list[str] = []
    unreachable: list[str] = []
    for case in case_set.cases:
        if case.kind is not CaseKind.ATTACK:
            continue
        lo, hi = bisect.bisect_left(times, case.start), bisect.bisect_left(times, case.end)
        hit = any(e.event_attack for e in pool.entries[lo:hi])
        (reachable if hit else unreachable).append(case.phase)
    return tuple(reachable), tuple(unreachable)


def _rate(covered: int, cases: int) -> dict[str, Any]:
    return {"covered": covered, "cases": cases, "rate": covered / cases if cases else None}


def _mean(values: list[int]) -> float | None:
    return sum(values) / len(values) if values else None


def _summary(cases: tuple[Case, ...], views: list[CaseAlerts], scores: list[CaseScore]) -> dict[str, Any]:
    kinds = [c.kind for c in cases]
    attack = [i for i, k in enumerate(kinds) if k is CaseKind.ATTACK]
    benign = [i for i, k in enumerate(kinds) if k is CaseKind.BENIGN]
    noise = None
    if views and views[0].noise is not None:
        noise = {key: sum(v.noise[key] for v in views if v.noise is not None)
                 for key in ("reference_count", "from_window", "from_fallback", "shortfall")}
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
        "noise": noise,
    }


def _baseline_summaries(case_set: CaseSet, views: list[CaseAlerts], pool: AlertPool,
                        config: BaselineConfig, reachable: tuple[str, ...]) -> dict[str, Any]:
    cases = case_set.cases
    attack = [i for i, c in enumerate(cases) if c.kind is CaseKind.ATTACK]
    benign = [i for i, c in enumerate(cases) if c.kind is CaseKind.BENIGN]
    reach = [i for i in attack if cases[i].phase in reachable]
    flat: dict[str, dict[str, str]] = {}
    summaries: dict[str, Any] = {}
    for name in BASELINE_NAMES:
        scores = []
        for case, view in zip(cases, views):
            cited = baseline_citations(name, view, config)
            wanted = set(cited)
            alerts = [pool.alert(e) for e in view.entries if e.alert_id in wanted]
            for alert in alerts:
                if alert.alert_id not in flat:
                    flat[alert.alert_id] = alert_claim_index([alert])[alert.alert_id]
            scores.append(score_case(
                case, view, cited, claims=baseline_claims(alerts, quote_chars=config.quote_chars),
                claim_index={a.alert_id: flat[a.alert_id] for a in alerts},
                quote_index=alert_quote_index(alerts)))
        cited_total = sum(s.cited for s in scores)
        claims = sum(s.claims for s in scores)
        summaries[name] = {
            "coverage": {
                "time_label": {
                    "all": _rate(sum(scores[i].coverage_time == 1.0 for i in attack), len(attack)),
                    "reachable": _rate(sum(scores[i].coverage_time == 1.0 for i in reach), len(reach)),
                },
                "event_label": {
                    "all": _rate(sum(scores[i].coverage_event == 1.0 for i in attack), len(attack)),
                    "reachable": _rate(sum(scores[i].coverage_event == 1.0 for i in reach), len(reach)),
                },
            },
            "citation_precision": {
                "event_label": (sum(s.cited_event_attack for s in scores) / cited_total
                                if cited_total else None),
                "time_label": sum(s.cited_in_phase for s in scores) / cited_total if cited_total else None,
                "cited": cited_total,
                "event_attack": sum(s.cited_event_attack for s in scores),
                "in_phase": sum(s.cited_in_phase for s in scores),
            },
            "unsupported_claim_rate": sum(s.unsupported_claims for s in scores) / claims if claims else None,
            "claims": claims,
            "alerts_cited": {
                "total": cited_total,
                "mean_per_case": _mean([s.cited for s in scores]),
                "mean_per_attack_case": _mean([scores[i].cited for i in attack]),
                "mean_per_benign_case": _mean([scores[i].cited for i in benign]),
            },
        }
    return summaries


def _dump(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
                    encoding="utf-8")


def dev_case_report(processed_dir: str | Path, labels_path: str | Path, scenario: str,
                    config: StudyConfig, *, output_dir: str | Path | None = None) -> dict[str, Any]:
    """Cases of a dev scenario: per-variant ceilings and deterministic baselines."""
    config.split.require_dev(scenario)
    cfg = config.cases
    pool = AlertPool.from_processed(processed_dir, scenario)
    timeline = AttackTimeline.from_labels_csv(labels_path, scenario)
    case_set = build_cases(pool, timeline, cfg)
    variants = experiment_variants(pool, config)
    views_by_variant = variant_case_views(case_set, variants, pool, cfg)
    reachable, unreachable = reachable_phases(case_set, pool)

    case_records: list[dict[str, Any]] = [
        {"case_id": c.case_id, "kind": c.kind.value, "phase": c.phase,
         "start": c.start.isoformat(), "end": c.end.isoformat(),
         "start_time_of_day_utc": c.start.strftime("%H:%M:%S"),
         "end_time_of_day_utc": c.end.strftime("%H:%M:%S"),
         "window_start": c.window_start.isoformat(), "window_end": c.window_end.isoformat(),
         "phase_reachable": (c.phase in reachable) if c.kind is CaseKind.ATTACK else None,
         "variants": {}}
        for c in case_set.cases
    ]
    summaries: dict[str, Any] = {}
    baselines: dict[str, Any] = {}
    for name, views in views_by_variant.items():
        # Ceiling: the agent cites every alert it was given; no claims.
        scores = [score_case(c, v, [e.alert_id for e in v.entries])
                  for c, v in zip(case_set.cases, views)]
        summaries[name] = {"family": variants[name].family,
                           **_summary(case_set.cases, views, scores)}
        baselines[name] = _baseline_summaries(case_set, views, pool, config.baselines, reachable)
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
                "noise": view.noise,
                "ceiling_coverage_time": score.coverage_time,
                "ceiling_coverage_event": score.coverage_event,
                "alert_ids": [e.alert_id for e in view.entries],
            }

    case_config = {"seed": cfg.seed, "padding_seconds": cfg.padding_seconds,
                   "max_alerts": cfg.max_alerts, "truncation": cfg.truncation,
                   "benign_per_attack": cfg.benign_per_attack}
    b = config.baselines
    report: dict[str, Any] = {
        "scenario": scenario,
        "scenario_split": "dev",
        "note": ("DEV-SCENARIO CEILINGS AND BASELINES: ceilings = best coverage any agent could "
                 "reach from each alert source (agent cites every alert it is given); baselines "
                 "= deterministic non-LLM citers; not agent results"),
        "study_config": config.source,
        "case_config": case_config,
        "baseline_config": {"top_k": b.top_k, "detector_order": list(b.detector_order),
                            "quote_chars": b.quote_chars},
        "cases": {"attack": sum(c.kind is CaseKind.ATTACK for c in case_set.cases),
                  "benign": sum(c.kind is CaseKind.BENIGN for c in case_set.cases)},
        "phases": {
            "all": [c.phase for c in case_set.cases if c.kind is CaseKind.ATTACK],
            "reachable": list(reachable),
            "unreachable": list(unreachable),
            "rule": ("reachable = at least one investigation-eligible alert (any detector) with "
                     "an attack event_label lies inside the phase interval"),
        },
        "benign_sampling": case_set.benign_sampling,
        "variants": summaries,
        "baselines": baselines,
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
