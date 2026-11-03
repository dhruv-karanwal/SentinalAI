from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from app.schemas.alert import (
    DEFAULT_EVALUATION_SELECTION,
    INVESTIGATION_SELECTION,
    Alert,
    AlertEvidence,
    AlertKind,
    AlertSelection,
    Detector,
    DetectorType,
    GroundTruth,
)


def make_alert(**overrides: Any) -> Alert:
    values: dict[str, Any] = {
        "alert_id": "1700000000.1",
        "scenario": "synthetic",
        "detector": Detector.WAZUH,
        "detector_type": DetectorType.RULE_BASED,
        "timestamp": datetime(2023, 11, 14, 22, 0, tzinfo=timezone.utc),
        "rule_id": "52507",
        "rule_name": "ClamAV database update",
        "raw_alert": {"id": "1700000000.1"},
        "source_file": "synthetic_wazuh.json",
        "source_line": 1,
    }
    values.update(overrides)
    return Alert(**values)


def test_minimal_alert_defaults() -> None:
    alert = make_alert()
    assert alert.event_ids == []
    assert alert.kind is AlertKind.EVENT
    assert alert.training_mode is False
    assert alert.duplicate_of_suricata is False
    assert alert.alert_id_derived is False
    assert alert.evidence == AlertEvidence()


def test_timestamp_is_converted_to_utc() -> None:
    local = datetime(2023, 11, 14, 23, 0, tzinfo=timezone(timedelta(hours=1)))
    assert make_alert(timestamp=local).timestamp == datetime(2023, 11, 14, 22, 0, tzinfo=timezone.utc)


def test_naive_timestamp_is_rejected() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        make_alert(timestamp=datetime(2023, 11, 14, 22, 0))


def test_naive_evidence_timestamp_is_rejected() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        AlertEvidence(log_timestamps=[datetime(2023, 11, 14)])


@pytest.mark.parametrize(
    ("detector", "detector_type"),
    [(Detector.WAZUH, DetectorType.SIGNATURE_BASED), (Detector.AMINER, DetectorType.RULE_BASED)],
)
def test_detector_type_must_match_detector(detector: Detector, detector_type: DetectorType) -> None:
    with pytest.raises(ValidationError, match="detector_type"):
        make_alert(detector=detector, detector_type=detector_type)


def test_alert_has_no_ground_truth_or_feature_fields() -> None:
    for name in ("label", "time_label", "event_label", "features"):
        with pytest.raises(ValidationError):
            make_alert(**{name: "x"})


def test_alert_needs_a_rule_id_or_name() -> None:
    with pytest.raises(ValidationError, match="rule_id or rule_name"):
        make_alert(rule_id=None, rule_name=None)


def test_fast_log_unmatched_only_on_suricata() -> None:
    assert make_alert(detector=Detector.SURICATA, detector_type=DetectorType.SIGNATURE_BASED,
                      fast_log_unmatched=True).fast_log_unmatched
    with pytest.raises(ValidationError, match="fast_log_unmatched"):
        make_alert(fast_log_unmatched=True)
    with pytest.raises(ValidationError, match="fast_log_unmatched"):
        make_alert(detector=Detector.SURICATA, detector_type=DetectorType.SIGNATURE_BASED,
                   fast_log_unmatched=True, duplicate_of_suricata=True)


def test_empty_event_id_is_rejected() -> None:
    with pytest.raises(ValidationError):
        make_alert(event_ids=[""])


def test_ground_truth_is_a_separate_record() -> None:
    truth = GroundTruth(
        alert_id="a", scenario="synthetic", time_label="dirb",
        event_label=None, event_label_available=True,
    )
    assert truth.event_label is None and truth.event_label_available
    with pytest.raises(ValidationError):
        GroundTruth(alert_id="a", scenario="s", time_label="dirb",
                    event_label="dirb", event_label_available=False)


def test_selections_exclude_by_default() -> None:
    plain = make_alert()
    training = make_alert(training_mode=True)
    duplicate = make_alert(duplicate_of_suricata=True)
    unmatched = make_alert(detector=Detector.SURICATA, detector_type=DetectorType.SIGNATURE_BASED,
                           fast_log_unmatched=True)
    assert INVESTIGATION_SELECTION.accepts(unmatched) and DEFAULT_EVALUATION_SELECTION.accepts(unmatched)
    aggregate = make_alert(detector=Detector.AMINER, detector_type=DetectorType.ANOMALY_BASED,
                           kind=AlertKind.AGGREGATE)
    assert DEFAULT_EVALUATION_SELECTION.accepts(plain)
    assert not DEFAULT_EVALUATION_SELECTION.accepts(training)
    assert not DEFAULT_EVALUATION_SELECTION.accepts(duplicate)
    assert DEFAULT_EVALUATION_SELECTION.accepts(aggregate)
    assert not INVESTIGATION_SELECTION.accepts(aggregate)
    assert INVESTIGATION_SELECTION.accepts(plain)
    everything = AlertSelection(include_training_mode=True, include_duplicates=True,
                                include_aggregates=True)
    assert all(everything.accepts(a) for a in (plain, training, duplicate, aggregate))
