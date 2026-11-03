"""Alert-source variants and detector-level triage scores.

The study holds the investigation agent fixed and varies where its alerts
come from. Every variant is a subset of one *pool*: a scenario's
investigation-eligible alerts (``INVESTIGATION_SELECTION``: no training-mode
alerts, no fast.log duplicates, no aggregates), time-ordered.

Variants
--------
- ``wazuh`` / ``suricata`` / ``aminer``: one detector's alerts.
- ``fused``: the union of the three. Alert ids are unique within a pool
  (checked on load) and fast.log duplicates are already excluded, so no
  detection is counted twice.
- ``oracle``: the alerts whose ``event_label`` is an attack, i.e. a perfect
  detector restricted to the existing alert pool.
- ``noise-<det>`` (the random control, M4b): alerts whose event_label is
  *benign*, count-matched to detector ``<det>``. At scenario level it is a
  seeded draw of ``len(<det>)`` alerts from the pool's event-benign alerts.
  In cases it is rebuilt per case (app.study.cases.noise_case_alerts): the
  same number of alerts as ``<det>`` has in the case window, taken from
  event-benign alerts in the same window first, then from the scenario
  pool, with the split recorded. It measures what an agent does when the
  alert source is pure noise at a real detector's volume.
- ``shuffled-<ref>`` (the M3 random control, kept as "shuffled-pool" rows):
  a seeded uniform draw from the whole pool with the same count as variant
  ``<ref>``. ``shuffled-fused`` is the whole pool, so it is written only as
  a manifest, flagged ``degenerate`` and ``experiment_variant: false``.

The study unit is the case (app.study.cases); the M3 per-variant 20-alert
study sample was retired in M4.

Scores
------
:func:`triage_by_truth` treats "alert is in the variant" as the verdict
over the pool, with event_label as primary truth and time_label as a
sensitivity analysis. These are detector-level numbers, not agent results.
Scoring is for development only: :func:`dev_triage_report` refuses held-out
scenarios.

Determinism: every random choice uses ``random.Random`` seeded with a
SHA-256 derivation of (base seed, purpose, scenario, variant), over a
population in a fixed order, so results do not depend on run order.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import platform
import random
from collections import Counter
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from app.evaluation.metrics import TriageScores, triage_scores
from app.ingestion.mappings import AIT_ADS_BENIGN_TIME_LABEL
from app.ingestion.records import IngestionError, resolve_input_file
from app.schemas.alert import INVESTIGATION_SELECTION, Alert, AlertSelection, Detector, GroundTruth
from app.study.config import NOISE_REFERENCE_CHOICES, SHUFFLED_REFERENCE_CHOICES, StudyConfig

BASE_VARIANTS = SHUFFLED_REFERENCE_CHOICES  # wazuh, suricata, aminer, fused, oracle


@dataclass(frozen=True)
class PoolEntry:
    """Index entry for one pool alert: what selection and scoring need."""

    alert_id: str
    detector: Detector
    timestamp: datetime
    source_file: str
    source_line: int
    offset: int  # byte offset of the alert's line in alerts.jsonl
    time_label: str
    event_label: str | None
    event_label_available: bool
    severity: int | None = None  # detector-native (Wazuh rule.level, Suricata alert.severity)

    @property
    def event_attack(self) -> bool | None:
        return (self.event_label is not None) if self.event_label_available else None

    @property
    def time_attack(self) -> bool:
        return self.time_label != AIT_ADS_BENIGN_TIME_LABEL


@dataclass(frozen=True)
class Variant:
    name: str
    scenario: str
    rule: str
    entries: tuple[PoolEntry, ...]
    seed: int | None = None
    derived_seed: int | None = None
    reference: str | None = None
    reference_size: int | None = None
    degenerate: bool = False
    family: str = "detector"  # detector | fused | oracle | shuffled | noise

    @property
    def alert_ids(self) -> tuple[str, ...]:
        return tuple(e.alert_id for e in self.entries)


class AlertPool:
    """A scenario's selected alerts, indexed by byte offset into alerts.jsonl.

    Only the small index is kept in memory; :meth:`alerts` re-reads the
    exact ingested records on demand.
    """

    def __init__(self, scenario: str, alerts_path: Path, ground_truth_path: Path,
                 entries: tuple[PoolEntry, ...], excluded: int, alerts_sha256: str,
                 selection: AlertSelection):
        self.scenario = scenario
        self.alerts_path = alerts_path
        self.ground_truth_path = ground_truth_path
        self.entries = entries
        self.excluded = excluded
        self.alerts_sha256 = alerts_sha256
        self.selection = selection
        self._cache: dict[int, Alert] = {}

    @classmethod
    def from_processed(cls, processed_dir: str | Path, scenario: str,
                       selection: AlertSelection = INVESTIGATION_SELECTION) -> AlertPool:
        root = Path(processed_dir)
        return cls.load(root / f"{scenario}.alerts.jsonl", root / f"{scenario}.ground_truth.jsonl",
                        scenario, selection)

    @classmethod
    def load(cls, alerts_path: Path, ground_truth_path: Path, scenario: str,
             selection: AlertSelection = INVESTIGATION_SELECTION) -> AlertPool:
        resolve_input_file(alerts_path)
        resolve_input_file(ground_truth_path)
        truth: dict[str, GroundTruth] = {}
        with ground_truth_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    item = GroundTruth.model_validate_json(line)
                    truth[item.alert_id] = item

        entries: list[PoolEntry] = []
        seen: set[str] = set()
        excluded = 0
        digest = hashlib.sha256()
        with alerts_path.open("rb") as handle:
            offset = 0
            for raw in iter(handle.readline, b""):
                digest.update(raw)
                start, offset = offset, offset + len(raw)
                if not raw.strip():
                    continue
                alert = Alert.model_validate_json(raw)
                if alert.scenario != scenario:
                    raise IngestionError(
                        f"{alerts_path.name}: alert {alert.alert_id} belongs to {alert.scenario!r}")
                if alert.alert_id in seen:
                    raise IngestionError(f"{alerts_path.name}: duplicate alert_id {alert.alert_id}")
                seen.add(alert.alert_id)
                if not selection.accepts(alert):
                    excluded += 1
                    continue
                gt = truth.get(alert.alert_id)
                if gt is None:
                    raise IngestionError(
                        f"{ground_truth_path.name}: no ground truth for alert {alert.alert_id}")
                entries.append(PoolEntry(
                    alert_id=alert.alert_id, detector=alert.detector, timestamp=alert.timestamp,
                    source_file=alert.source_file, source_line=alert.source_line, offset=start,
                    time_label=gt.time_label, event_label=gt.event_label,
                    event_label_available=gt.event_label_available, severity=alert.severity,
                ))
        entries.sort(key=lambda e: (e.timestamp, e.source_file, e.source_line))
        return cls(scenario, alerts_path, ground_truth_path, tuple(entries), excluded,
                   digest.hexdigest(), selection)

    def _lines(self, variant: Variant) -> Iterator[bytes]:
        with self.alerts_path.open("rb") as handle:
            for entry in variant.entries:
                handle.seek(entry.offset)
                yield handle.readline()

    def alerts(self, variant: Variant) -> Iterator[Alert]:
        """The variant's alerts, exactly as ingested, in variant (time) order."""
        for line in self._lines(variant):
            yield Alert.model_validate_json(line)

    def alert(self, entry: PoolEntry) -> Alert:
        """One alert record by its index entry (cached: cases reuse alerts)."""
        cached = self._cache.get(entry.offset)
        if cached is None:
            with self.alerts_path.open("rb") as handle:
                handle.seek(entry.offset)
                cached = Alert.model_validate_json(handle.readline())
            self._cache[entry.offset] = cached
        return cached

    def event_benign(self) -> tuple[PoolEntry, ...]:
        """Pool alerts whose event_label is benign (available and ``-``), time-ordered."""
        return tuple(e for e in self.entries if e.event_attack is False)


def derive_seed(seed: int, *parts: str) -> int:
    text = "|".join((str(seed), *parts))
    return int.from_bytes(hashlib.sha256(text.encode("utf-8")).digest()[:8], "big")


def _shuffled_variant(pool: AlertPool, reference: Variant, seed: int) -> Variant:
    derived = derive_seed(seed, "random", pool.scenario, reference.name)
    size = len(reference.entries)
    picked = sorted(random.Random(derived).sample(range(len(pool.entries)), size))
    return Variant(
        name=f"shuffled-{reference.name}",
        scenario=pool.scenario,
        rule=(f"uniform draw without replacement from the pool, same count as "
              f"'{reference.name}' ({size})"),
        entries=tuple(pool.entries[i] for i in picked),
        seed=seed,
        derived_seed=derived,
        reference=reference.name,
        reference_size=size,
        degenerate=size == len(pool.entries),
        family="shuffled",
    )


def _noise_variant(pool: AlertPool, reference: Variant, seed: int) -> Variant:
    benign = pool.event_benign()
    derived = derive_seed(seed, "noise", pool.scenario, reference.name)
    size = min(len(reference.entries), len(benign))
    picked = sorted(random.Random(derived).sample(range(len(benign)), size))
    return Variant(
        name=f"noise-{reference.name}",
        scenario=pool.scenario,
        rule=(f"uniform draw without replacement from the pool's event-benign alerts, same "
              f"count as '{reference.name}' ({len(reference.entries)}); in cases rebuilt per "
              "window (same window first, scenario pool as fallback)"),
        entries=tuple(benign[i] for i in picked),
        seed=seed,
        derived_seed=derived,
        reference=reference.name,
        reference_size=len(reference.entries),
        family="noise",
    )


def build_variants(pool: AlertPool, *, seed: int,
                   shuffled_references: Sequence[str] = ("fused",),
                   noise_references: Sequence[str] = ()) -> dict[str, Variant]:
    unknown = [r for r in shuffled_references if r not in BASE_VARIANTS]
    if unknown:
        raise ValueError(f"unknown shuffled reference variant(s): {', '.join(unknown)}")
    unknown = [r for r in noise_references if r not in NOISE_REFERENCE_CHOICES]
    if unknown:
        raise ValueError(f"unknown noise reference detector(s): {', '.join(unknown)}")
    variants: dict[str, Variant] = {}
    for detector in Detector:
        variants[detector.value] = Variant(
            detector.value, pool.scenario, f"pool alerts with detector == {detector.value}",
            tuple(e for e in pool.entries if e.detector is detector))
    variants["fused"] = Variant(
        "fused", pool.scenario, "union of the wazuh, suricata and aminer variants (the whole pool)",
        pool.entries, family="fused")
    variants["oracle"] = Variant(
        "oracle", pool.scenario,
        "pool alerts whose event_label is an attack; alerts without an available event label "
        "are left out", tuple(e for e in pool.entries if e.event_attack), family="oracle")
    for reference in shuffled_references:
        variants[f"shuffled-{reference}"] = _shuffled_variant(pool, variants[reference], seed)
    for reference in noise_references:
        variants[f"noise-{reference}"] = _noise_variant(pool, variants[reference], seed)
    return variants


def _stratum(entry: PoolEntry) -> str:
    attack = entry.event_attack
    return "unavailable" if attack is None else ("attack" if attack else "benign")


def _share(attack: int, other: int) -> float | None:
    return attack / (attack + other) if attack + other else None


def variant_manifest(variant: Variant, pool: AlertPool, *,
                     experiment_variant: bool = True) -> dict[str, Any]:
    ev = Counter(_stratum(e) for e in variant.entries)
    time_attack = sum(e.time_attack for e in variant.entries)
    time_benign = len(variant.entries) - time_attack
    return {
        "variant": variant.name,
        "family": variant.family,
        "scenario": variant.scenario,
        "rule": variant.rule,
        "selection": dataclasses.asdict(pool.selection),
        "pool_size": len(pool.entries),
        "alerts": len(variant.entries),
        "by_detector": dict(sorted(Counter(e.detector.value for e in variant.entries).items())),
        "seed": variant.seed,
        "derived_seed": variant.derived_seed,
        "reference_variant": variant.reference,
        "reference_size": variant.reference_size,
        "degenerate": variant.degenerate,
        "experiment_variant": experiment_variant,
        "attack_share": {
            "event_label": {"attack": ev["attack"], "benign": ev["benign"],
                            "unavailable": ev["unavailable"],
                            "share": _share(ev["attack"], ev["benign"])},
            "time_label": {"attack": time_attack, "benign": time_benign,
                           "share": _share(time_attack, time_benign)},
        },
        "source": {
            "alerts_file": pool.alerts_path.name,
            "ground_truth_file": pool.ground_truth_path.name,
            "alerts_sha256": pool.alerts_sha256,
        },
        "python": platform.python_version(),
    }


def triage_by_truth(variant: Variant, pool: AlertPool) -> dict[str, TriageScores]:
    """Verdict "in the variant" over the pool, against event_label and time_label."""
    chosen = set(variant.alert_ids)
    scored = [e for e in pool.entries if e.event_attack is not None]
    return {
        "event_label": triage_scores({e.alert_id: e.alert_id in chosen for e in scored},
                                     {e.alert_id: bool(e.event_attack) for e in scored}),
        "time_label": triage_scores({e.alert_id: e.alert_id in chosen for e in pool.entries},
                                    {e.alert_id: e.time_attack for e in pool.entries}),
    }


def scores_dict(scores: TriageScores) -> dict[str, Any]:
    return {"tp": scores.tp, "fp": scores.fp, "fn": scores.fn, "tn": scores.tn,
            "precision": scores.precision, "recall": scores.recall, "f1": scores.f1,
            "fnr": scores.false_negative_rate}


def _dump(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
                    encoding="utf-8")


def write_variant(variant: Variant, pool: AlertPool, out_dir: str | Path) -> tuple[Path, Path]:
    """Write the variant's alerts (byte-identical ingested lines) and its manifest."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stem = f"{variant.scenario}.variant.{variant.name}"
    alerts_path, manifest_path = out / f"{stem}.alerts.jsonl", out / f"{stem}.manifest.json"
    with alerts_path.open("wb") as handle:
        for line in pool._lines(variant):
            handle.write(line if line.endswith(b"\n") else line + b"\n")
    _dump(manifest_path, variant_manifest(variant, pool))
    return alerts_path, manifest_path


def experiment_variants(pool: AlertPool, config: StudyConfig,
                        shuffled_references: Sequence[str] | None = None) -> dict[str, Variant]:
    """The variants experiments use: base variants plus the configured shuffled and noise controls."""
    return build_variants(pool, seed=config.variant_seed,
                          shuffled_references=(config.shuffled_reference if shuffled_references is None
                                               else shuffled_references),
                          noise_references=config.noise_reference)


def dev_triage_report(processed_dir: str | Path, scenario: str, config: StudyConfig, *,
                      output_dir: str | Path | None = None,
                      shuffled_references: Sequence[str] | None = None) -> dict[str, Any]:
    """Build all variants and score them. Dev scenarios only."""
    config.split.require_dev(scenario)
    pool = AlertPool.from_processed(processed_dir, scenario)
    variants = experiment_variants(pool, config, shuffled_references)
    manifest_only = {
        name: variant
        for name, variant in build_variants(
            pool, seed=config.variant_seed,
            shuffled_references=config.manifest_only_shuffled_reference).items()
        if name.startswith("shuffled-") and name not in variants
    }
    report: dict[str, Any] = {
        "scenario": scenario,
        "scenario_split": "dev",
        "note": "DEV-SCENARIO NUMBERS: detector-level triage over the alert pool, not held-out results",
        "study_config": config.source,
        "truth": {"primary": "event_label", "sensitivity": "time_label"},
        "pool": {"alerts": len(pool.entries), "excluded_by_selection": pool.excluded,
                 "event_label_available": sum(e.event_attack is not None for e in pool.entries)},
        "variants": {},
        "manifest_only": {name: variant_manifest(v, pool, experiment_variant=False)
                          for name, v in manifest_only.items()},
    }
    for name, variant in variants.items():
        report["variants"][name] = {
            "manifest": variant_manifest(variant, pool),
            "triage": {truth: scores_dict(s) for truth, s in triage_by_truth(variant, pool).items()},
        }
    if output_dir is not None:
        out = Path(output_dir) / scenario
        for variant in variants.values():
            write_variant(variant, pool, out)
        for name, manifest in report["manifest_only"].items():
            _dump(out / f"{scenario}.variant.{name}.manifest.json", manifest)
        _dump(out / f"{scenario}.dev_triage.json", report)
    return report
