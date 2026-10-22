"""Streaming data-quality summary for a normalization run.

Statistics are accumulated one record at a time so large inputs do not have
to be held in memory. Duplicate detection keeps a 16-byte hash per
normalized record, which is the main memory cost for very large files.

Notes on definitions:

- ``duplicate_raw_records``: normalized records whose ``raw_event`` is
  identical to an earlier one (extra copies only).
- ``duplicate_feature_vectors``: records whose ``features`` *and* ``label``
  equal an earlier record's; relevant for train/test leakage later.
- ``duplicate_event_ids``: repeated source-provided ids. Derived ids
  (``<file>:<position>``) are unique by construction and not tracked.
- numeric statistics use finite values only; infinities are counted
  separately. ``std`` is the sample standard deviation (n - 1).
- class imbalance is reported, never corrected, in Phase 1.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.ingestion.normalizer import INVALID_TIMESTAMP, Rejection
from app.schemas.event import SecurityEvent

CANONICAL_OPTIONAL_FIELDS = (
    "event_id",
    "timestamp",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "event_type",
    "severity",
    "label",
    "dataset_name",
)

_MAX_DISTINCT = 50


@dataclass
class _NumericStats:
    count: int = 0
    non_finite: int = 0
    mean: float = 0.0
    m2: float = 0.0
    minimum: float = math.inf
    maximum: float = -math.inf

    def add(self, value: float) -> None:
        if not math.isfinite(value):
            self.non_finite += 1
            return
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        self.m2 += delta * (value - self.mean)
        self.minimum = min(self.minimum, value)
        self.maximum = max(self.maximum, value)

    def to_dict(self) -> dict[str, Any]:
        has_values = self.count > 0
        return {
            "finite_count": self.count,
            "non_finite_count": self.non_finite,
            "min": self.minimum if has_values else None,
            "max": self.maximum if has_values else None,
            "mean": round(self.mean, 6) if has_values else None,
            "std": round(math.sqrt(self.m2 / (self.count - 1)), 6) if self.count > 1 else None,
        }


@dataclass
class _FeatureTracker:
    present: int = 0
    numeric: _NumericStats = field(default_factory=_NumericStats)
    categorical: Counter[str] = field(default_factory=Counter)
    distinct_capped: bool = False

    def add(self, value: Any) -> None:
        self.present += 1
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            self.numeric.add(float(value))
            return
        key = str(value)
        if key in self.categorical or len(self.categorical) < _MAX_DISTINCT:
            self.categorical[key] += 1
        else:
            self.distinct_capped = True


def _digest(payload: Any) -> bytes:
    text = json.dumps(payload, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.blake2b(text.encode("utf-8"), digest_size=16).digest()


class DataQualityAccumulator:
    def __init__(self, max_examples: int = 20) -> None:
        self.max_examples = max_examples
        self.normalized = 0
        self.rejected = 0
        self.rejection_reasons: Counter[str] = Counter()
        self.rejection_examples: list[dict[str, Any]] = []
        self.timestamp_failures = 0
        self.missing: Counter[str] = Counter()
        self.labels: Counter[str] = Counter()
        self.source_types: Counter[str] = Counter()
        self.timestamps_assumed_tz = 0
        self.ts_min: datetime | None = None
        self.ts_max: datetime | None = None
        self.event_ids_derived = 0
        self._seen_ids: set[str] = set()
        self.duplicate_ids = 0
        self.duplicate_id_examples: list[str] = []
        self._seen_raw: set[bytes] = set()
        self.duplicate_raw = 0
        self._seen_vectors: set[bytes] = set()
        self.duplicate_vectors = 0
        self.features: dict[str, _FeatureTracker] = {}

    def add(self, outcome: SecurityEvent | Rejection) -> None:
        if isinstance(outcome, Rejection):
            self.add_rejection(outcome)
        else:
            self.add_event(outcome)

    def add_rejection(self, rejection: Rejection) -> None:
        self.rejected += 1
        self.rejection_reasons[rejection.category] += 1
        if any(e.category == INVALID_TIMESTAMP for e in rejection.errors):
            self.timestamp_failures += 1
        if len(self.rejection_examples) < self.max_examples:
            self.rejection_examples.append({
                "source_file": rejection.source,
                "source_position": rejection.position,
                "category": rejection.category,
                "messages": [e.message for e in rejection.errors],
            })

    def add_event(self, event: SecurityEvent) -> None:
        self.normalized += 1
        for name in CANONICAL_OPTIONAL_FIELDS:
            if getattr(event, name) is None:
                self.missing[name] += 1
        self.source_types[event.source_type.value] += 1
        if event.label is not None:
            self.labels[event.label] += 1

        if event.timestamp is not None:
            if event.metadata.get("timestamp_timezone_assumed"):
                self.timestamps_assumed_tz += 1
            if self.ts_min is None or event.timestamp < self.ts_min:
                self.ts_min = event.timestamp
            if self.ts_max is None or event.timestamp > self.ts_max:
                self.ts_max = event.timestamp

        if event.metadata.get("event_id_derived"):
            self.event_ids_derived += 1
        elif event.event_id is not None:
            if event.event_id in self._seen_ids:
                self.duplicate_ids += 1
                if len(self.duplicate_id_examples) < self.max_examples:
                    self.duplicate_id_examples.append(event.event_id)
            else:
                self._seen_ids.add(event.event_id)

        raw_digest = _digest(event.raw_event)
        if raw_digest in self._seen_raw:
            self.duplicate_raw += 1
        else:
            self._seen_raw.add(raw_digest)
        if event.features:
            vector_digest = _digest([event.features, event.label])
            if vector_digest in self._seen_vectors:
                self.duplicate_vectors += 1
            else:
                self._seen_vectors.add(vector_digest)

        for name, value in event.features.items():
            tracker = self.features.setdefault(name, _FeatureTracker())
            if value is not None:
                tracker.add(value)

    def report(self) -> dict[str, Any]:
        labelled = sum(self.labels.values())
        numeric: dict[str, Any] = {}
        categorical: dict[str, Any] = {}
        for name in sorted(self.features):
            tracker = self.features[name]
            base = {"present": tracker.present, "missing": self.normalized - tracker.present}
            if tracker.numeric.count or tracker.numeric.non_finite:
                numeric[name] = {**base, **tracker.numeric.to_dict()}
            if tracker.categorical:
                categorical[name] = {
                    **base,
                    "value_counts": dict(tracker.categorical.most_common()),
                    "distinct_values_capped": tracker.distinct_capped,
                }
            if not tracker.present:
                numeric[name] = {**base, **tracker.numeric.to_dict()}

        return {
            "record_counts": {
                "total_input": self.normalized + self.rejected,
                "normalized": self.normalized,
                "rejected": self.rejected,
            },
            "rejections": {
                "by_reason": dict(sorted(self.rejection_reasons.items())),
                "examples": self.rejection_examples,
            },
            "missing_values_by_field": {
                name: self.missing[name] for name in CANONICAL_OPTIONAL_FIELDS
            },
            "duplicates": {
                "duplicate_event_ids": self.duplicate_ids,
                "duplicate_event_id_examples": self.duplicate_id_examples,
                "event_ids_derived": self.event_ids_derived,
                "duplicate_raw_records": self.duplicate_raw,
                "duplicate_feature_vectors": self.duplicate_vectors,
            },
            "timestamps": {
                "parsed": self.normalized - self.missing["timestamp"],
                "missing": self.missing["timestamp"],
                "parse_failures": self.timestamp_failures,
                "timezone_assumed": self.timestamps_assumed_tz,
                "min": self.ts_min.isoformat() if self.ts_min else None,
                "max": self.ts_max.isoformat() if self.ts_max else None,
            },
            "labels": {
                "labelled": labelled,
                "unlabelled": self.normalized - labelled,
                "distribution": {
                    label: {"count": count, "proportion": round(count / labelled, 6)}
                    for label, count in self.labels.most_common()
                },
            },
            "source_type_distribution": dict(self.source_types.most_common()),
            "features": {
                "feature_count": len(self.features),
                "numeric": numeric,
                "categorical": categorical,
            },
        }


def build_quality_report(outcomes: list[SecurityEvent | Rejection]) -> dict[str, Any]:
    accumulator = DataQualityAccumulator()
    for outcome in outcomes:
        accumulator.add(outcome)
    return accumulator.report()
