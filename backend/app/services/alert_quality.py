"""Streaming quality report for one ingested AIT-ADS scenario.

Besides the usual counts (input, normalized, rejected by reason) the report
answers the questions the study depends on:

- how many alerts each detector contributes, and how many survive the
  default exclusions (training mode, Suricata duplicates, aggregates);
- how many fast.log records have an eve.json twin (excluded duplicates)
  and how many do not (kept as Suricata alerts), per run;
- whether the label clock agrees with the alert clock (attack intervals
  that fall inside the alert time range);
- label coverage: which attack phases have at least one eligible alert per
  detector, and how many alerts have a verified event label.

Memory is bounded by the number of distinct keys, stored as 16-byte digests,
not by the size of the input.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

from app.ingestion.alert_normalizer import digest16
from app.ingestion.ground_truth import AttackTimeline, EventLabelLinker, LinkStatus
from app.ingestion.mappings import (
    AIT_ADS_BENIGN_TIME_LABEL,
    SURICATA_EVE_LOCATION,
    suricata_twin_key,
)
from app.ingestion.normalizer import Rejection
from app.schemas.alert import (
    DEFAULT_EVALUATION_SELECTION,
    INVESTIGATION_SELECTION,
    Alert,
    AlertKind,
    Detector,
    GroundTruth,
)


class AlertQualityAccumulator:
    def __init__(self, timeline: AttackTimeline):
        self.timeline = timeline
        self.total = 0
        self.rejected_by_reason: Counter[str] = Counter()
        self.rejected_by_file: Counter[str] = Counter()
        self.detectors: dict[str, Counter[str]] = {d.value: Counter() for d in Detector}
        self.eve_keys: Counter[bytes] = Counter()
        self.fast_keys: Counter[bytes] = Counter()
        self.alert_ids: set[bytes] = set()
        self.duplicate_alert_ids = 0
        self.derived_ids = 0
        self.ts_min: datetime | None = None
        self.ts_max: datetime | None = None
        self.time_labels: Counter[str] = Counter()
        self.investigation_labels: dict[str, Counter[str]] = defaultdict(Counter)
        self.event_labels: Counter[str] = Counter()
        self.event_available = 0
        self.no_event_label = 0
        self.csv_time_agree = 0
        self.csv_time_disagree = 0

    def add_rejection(self, rejection: Rejection) -> None:
        self.total += 1
        self.rejected_by_reason[rejection.category] += 1
        self.rejected_by_file[rejection.source] += 1

    def add_alert(self, alert: Alert, truth: GroundTruth, csv_time_label: str | None) -> None:
        self.total += 1
        counts = self.detectors[alert.detector.value]
        counts["alerts"] += 1
        counts["training_mode"] += alert.training_mode
        counts["aggregate"] += alert.kind is AlertKind.AGGREGATE
        counts["duplicate_of_suricata"] += alert.duplicate_of_suricata
        counts["fast_log_unmatched"] += alert.fast_log_unmatched
        counts["evaluation_eligible"] += DEFAULT_EVALUATION_SELECTION.accepts(alert)
        investigation = INVESTIGATION_SELECTION.accepts(alert)
        counts["investigation_eligible"] += investigation

        twin = suricata_twin_key(alert.raw_alert)
        if twin is not None:
            target = self.eve_keys if alert.raw_alert.get("location") == SURICATA_EVE_LOCATION else self.fast_keys
            target[digest16(*twin)] += 1

        key = digest16(alert.detector.value, alert.alert_id)
        if key in self.alert_ids:
            self.duplicate_alert_ids += 1
        self.alert_ids.add(key)
        self.derived_ids += alert.alert_id_derived

        if self.ts_min is None or alert.timestamp < self.ts_min:
            self.ts_min = alert.timestamp
        if self.ts_max is None or alert.timestamp > self.ts_max:
            self.ts_max = alert.timestamp

        self.time_labels[truth.time_label] += 1
        if investigation:
            self.investigation_labels[alert.detector.value][truth.time_label] += 1
        if truth.event_label_available:
            self.event_available += 1
            if truth.event_label is None:
                self.no_event_label += 1
            else:
                self.event_labels[truth.event_label] += 1
        if csv_time_label is not None:
            if csv_time_label == truth.time_label:
                self.csv_time_agree += 1
            else:
                self.csv_time_disagree += 1

    def report(self, linker: EventLabelLinker | None, event_label_file: str | None) -> dict[str, Any]:
        normalized = sum(c["alerts"] for c in self.detectors.values())
        fields = ("alerts", "training_mode", "aggregate", "duplicate_of_suricata",
                  "fast_log_unmatched", "evaluation_eligible", "investigation_eligible")
        fast_total = sum(self.fast_keys.values())
        fast_matched = sum(c["duplicate_of_suricata"] for c in self.detectors.values())
        fast_unmatched = sum(c["fast_log_unmatched"] for c in self.detectors.values())
        eve_total = sum(self.eve_keys.values())
        eve_unmatched = sum(max(n - self.fast_keys[k], 0) for k, n in self.eve_keys.items())
        intervals = self.timeline.intervals
        inside = 0
        if self.ts_min is not None and self.ts_max is not None:
            inside = sum(1 for i in intervals if self.ts_min <= i.start and i.end <= self.ts_max)
        phases = {
            detector: sorted(label for label in labels if label != AIT_ADS_BENIGN_TIME_LABEL)
            for detector, labels in sorted(self.investigation_labels.items())
        }
        return {
            "record_counts": {
                "total_input": self.total,
                "normalized": normalized,
                "rejected": sum(self.rejected_by_reason.values()),
            },
            "rejections": {
                "by_reason": dict(sorted(self.rejected_by_reason.items())),
                "by_file": dict(sorted(self.rejected_by_file.items())),
            },
            "detectors": {d: {f: self.detectors[d][f] for f in fields} for d in self.detectors},
            "suricata_duplicates": {
                "fast_log_records": fast_total,
                "fast_log_matched_to_eve": fast_matched,
                "fast_log_unmatched": fast_unmatched,
                "eve_records": eve_total,
                "eve_without_fast_log_twin": eve_unmatched,
            },
            "alert_ids": {"derived": self.derived_ids, "duplicate_alert_ids": self.duplicate_alert_ids},
            "timestamps": {
                "min": self.ts_min.isoformat() if self.ts_min else None,
                "max": self.ts_max.isoformat() if self.ts_max else None,
            },
            "ground_truth": {
                "attack_intervals": [
                    {"attack": i.attack, "start": i.start.isoformat(), "end": i.end.isoformat()}
                    for i in intervals
                ],
                "attack_intervals_within_alert_range": inside,
                "time_label_distribution": dict(sorted(self.time_labels.items())),
                "investigation_time_labels_by_detector": {
                    d: dict(sorted(c.items())) for d, c in sorted(self.investigation_labels.items())
                },
                "attack_phases_with_investigation_alert": phases,
                "event_labels": {
                    "source_file": event_label_file,
                    "link_status": (linker.status if linker else LinkStatus.NOT_PROVIDED).value,
                    "rows_consumed": linker.rows_consumed if linker else 0,
                    "csv_rows_left_over": linker.left_over if linker else 0,
                    "mismatch_position": linker.mismatch_position if linker else None,
                    "available": self.event_available,
                    "unavailable": normalized - self.event_available,
                    "no_event_label": self.no_event_label,
                    "distribution": dict(sorted(self.event_labels.items())),
                    "csv_time_label_agreement": {
                        "agree": self.csv_time_agree, "disagree": self.csv_time_disagree},
                },
                "coverage": {
                    "alerts": normalized,
                    "with_time_label": sum(self.time_labels.values()),
                    "with_event_label_available": self.event_available,
                },
            },
        }
