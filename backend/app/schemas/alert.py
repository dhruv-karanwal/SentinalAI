"""Canonical security-alert schema for the detector-conditioned study.

The study holds the investigation agent fixed and varies the alert source,
so alerts from every detector are normalized into one :class:`Alert` shape.
Detector-native values are kept as they are: ``severity`` is the detector's
own number (Wazuh ``rule.level``, Suricata ``alert.severity``; AMiner has
none) and is never mapped onto a common scale, because any such mapping
would be an invented equivalence.

Layers
------
- ``raw_alert``: the original record, for traceability.
- canonical fields: identity, detector, time, rule, host and ``evidence``.
- ``event_ids``: IDs of the log events an alert refers to. The AIT-ADS
  alerts carry no such IDs, so this stays empty until a log dataset with
  real event IDs is added. IDs are never invented.
- :class:`GroundTruth`: scenario labels, written to a separate file and
  joined by ``alert_id``. An alert has no label or feature fields at all,
  so ground truth cannot leak into what an agent or model sees.

Default exclusions (:class:`AlertSelection`)
--------------------------------------------
Every record is kept in the output; exclusion happens only when alerts are
selected for an experiment, so nothing is dropped silently:

- ``training_mode``: AMiner alerts raised while the detector was still
  learning its baseline. Excluded from all evaluation variants by default.
- ``duplicate_of_suricata``: Wazuh records decoded from Suricata's
  ``fast.log``; they repeat Suricata ``eve.json`` alerts and would count the
  same detection twice. Excluded by default.
- ``kind == "aggregate"``: AMiner count/frequency anomalies about a time
  window rather than one log line. Kept for detector-level scoring,
  excluded from the investigation variants by default.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    field_validator,
    model_validator,
)


class Detector(StrEnum):
    WAZUH = "wazuh"
    SURICATA = "suricata"
    AMINER = "aminer"


class DetectorType(StrEnum):
    RULE_BASED = "rule_based"
    SIGNATURE_BASED = "signature_based"
    ANOMALY_BASED = "anomaly_based"


# A property of the detector, not of a dataset. AMiner is anomaly-based: the
# AIT-ADS README describes running it "for anomaly detection", and its
# components (NewMatchPathDetector, EventFrequencyDetector, ...) learn a
# baseline (TrainingMode) and report deviations.
DETECTOR_TYPES: dict[Detector, DetectorType] = {
    Detector.WAZUH: DetectorType.RULE_BASED,
    Detector.SURICATA: DetectorType.SIGNATURE_BASED,
    Detector.AMINER: DetectorType.ANOMALY_BASED,
}


class AlertKind(StrEnum):
    EVENT = "event"          # raised by (a) specific log line(s)
    AGGREGATE = "aggregate"  # raised by a count/frequency over a time window


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(timezone.utc)


class AlertEvidence(BaseModel):
    """What the alert itself carries about the events that triggered it."""

    model_config = ConfigDict(extra="forbid")

    source_alert_id: str | None = Field(default=None, min_length=1)
    log_lines: list[str] = Field(default_factory=list)
    log_paths: list[str] = Field(default_factory=list)
    log_timestamps: list[datetime] = Field(default_factory=list)

    @field_validator("log_timestamps")
    @classmethod
    def _require_aware_utc(cls, value: list[datetime]) -> list[datetime]:
        return [_aware_utc(item) for item in value]


class Alert(BaseModel):
    """A single normalized alert from one detector."""

    model_config = ConfigDict(extra="forbid")

    alert_id: str = Field(min_length=1)
    alert_id_derived: bool = False
    scenario: str = Field(min_length=1)
    detector: Detector
    detector_type: DetectorType
    kind: AlertKind = AlertKind.EVENT
    timestamp: datetime
    rule_id: str | None = Field(default=None, min_length=1)
    rule_name: str | None = Field(default=None, min_length=1)
    severity: int | None = None
    host_ip: IPvAnyAddress | None = None
    event_ids: list[str] = Field(default_factory=list)
    evidence: AlertEvidence = Field(default_factory=AlertEvidence)
    training_mode: bool = False
    duplicate_of_suricata: bool = False
    raw_alert: dict[str, Any]
    dataset_name: str | None = Field(default=None, min_length=1)
    source_file: str = Field(min_length=1)
    source_line: int = Field(ge=1)

    @field_validator("timestamp")
    @classmethod
    def _require_aware_utc(cls, value: datetime) -> datetime:
        return _aware_utc(value)

    @field_validator("event_ids")
    @classmethod
    def _non_empty_ids(cls, value: list[str]) -> list[str]:
        if any(not item.strip() for item in value):
            raise ValueError("event ids must be non-empty")
        return value

    @model_validator(mode="after")
    def _check_consistency(self) -> Alert:
        expected = DETECTOR_TYPES[self.detector]
        if self.detector_type is not expected:
            raise ValueError(
                f"detector_type {self.detector_type.value!r} does not match "
                f"detector {self.detector.value!r} (expected {expected.value!r})"
            )
        if self.rule_id is None and self.rule_name is None:
            raise ValueError("an alert needs a rule_id or rule_name")
        return self


class GroundTruth(BaseModel):
    """Scenario labels for one alert; never an input to an agent or model.

    ``time_label``: the attack phase whose interval contains the alert time,
    or ``"false_positive"`` outside every interval (the dataset's own term).
    ``event_label``: the dataset's per-event label, ``None`` when the
    dataset says no labelled attack event matched. ``event_label_available``
    is false when no verified event label exists for this alert at all.
    """

    model_config = ConfigDict(extra="forbid")

    alert_id: str = Field(min_length=1)
    scenario: str = Field(min_length=1)
    time_label: str = Field(min_length=1)
    event_label: str | None = Field(default=None, min_length=1)
    event_label_available: bool = False
    event_label_source: str | None = None

    @model_validator(mode="after")
    def _check_event_label(self) -> GroundTruth:
        if self.event_label is not None and not self.event_label_available:
            raise ValueError("event_label given but event_label_available is false")
        return self


@dataclass(frozen=True)
class AlertSelection:
    """Which alerts an experiment variant uses (see module docstring)."""

    include_training_mode: bool = False
    include_duplicates: bool = False
    include_aggregates: bool = False

    def accepts(self, alert: Alert) -> bool:
        if alert.training_mode and not self.include_training_mode:
            return False
        if alert.duplicate_of_suricata and not self.include_duplicates:
            return False
        if alert.kind is AlertKind.AGGREGATE and not self.include_aggregates:
            return False
        return True


# Detector-level scoring: aggregates are real detector output, keep them.
DEFAULT_EVALUATION_SELECTION = AlertSelection(include_aggregates=True)
# Investigation variants: only alerts tied to concrete log lines.
INVESTIGATION_SELECTION = AlertSelection()
