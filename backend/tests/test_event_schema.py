from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from app.schemas.event import SecurityEvent, Severity, SourceType


def test_minimal_event_only_requires_raw_event() -> None:
    event = SecurityEvent(raw_event={"x": "1"})
    assert event.source_type is SourceType.UNKNOWN
    assert event.timestamp is None
    assert event.source_ip is None
    assert event.label is None
    assert event.severity is None
    assert event.features == {}
    assert event.raw_event == {"x": "1"}


def test_raw_event_is_required() -> None:
    with pytest.raises(ValidationError, match="raw_event"):
        SecurityEvent()  # type: ignore[call-arg]


def test_full_event_is_validated_and_normalized() -> None:
    event = SecurityEvent(
        event_id="e1",
        timestamp=datetime(2026, 1, 1, 12, 0, tzinfo=timezone(timedelta(hours=2))),
        source_type=" Network ",
        source_ip="10.0.0.1",
        destination_ip="2001:db8::1",
        source_port="51515",
        destination_port=443,
        protocol=" TCP ",
        event_type="connection",
        severity="Info",
        label="BENIGN",
        features={"bytes": 10, "ratio": 0.5, "flag": True, "method": "GET", "gap": None},
        raw_event={"original": "record"},
        dataset_name="test",
        metadata={"host": "h1"},
    )
    assert event.timestamp == datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    assert event.timestamp.utcoffset() == timedelta(0)
    assert event.source_type is SourceType.NETWORK
    assert str(event.source_ip) == "10.0.0.1"
    assert str(event.destination_ip) == "2001:db8::1"
    assert event.source_port == 51515
    assert event.protocol == "tcp"
    assert event.severity is Severity.INFORMATIONAL
    assert event.features["flag"] is True


def test_naive_timestamp_is_rejected() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        SecurityEvent(timestamp=datetime(2026, 1, 1), raw_event={})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_ip", "999.1.1.1"),
        ("destination_ip", "not-an-ip"),
        ("source_port", -1),
        ("destination_port", 65536),
        ("severity", "urgent"),
        ("source_type", "firewall"),
        ("event_id", ""),
        ("label", ""),
    ],
)
def test_invalid_values_are_rejected(field: str, value: object) -> None:
    with pytest.raises(ValidationError) as info:
        SecurityEvent(raw_event={}, **{field: value})
    assert info.value.errors()[0]["loc"][0] == field


def test_unknown_fields_are_forbidden() -> None:
    with pytest.raises(ValidationError, match="extra"):
        SecurityEvent(raw_event={}, src="10.0.0.1")  # type: ignore[call-arg]


@pytest.mark.parametrize("name", ["label", " Label "])
def test_label_cannot_be_a_feature(name: str) -> None:
    with pytest.raises(ValidationError, match="ground truth"):
        SecurityEvent(raw_event={}, features={name: "BENIGN"})


def test_non_scalar_feature_is_rejected() -> None:
    with pytest.raises(ValidationError):
        SecurityEvent(raw_event={}, features={"nested": {"a": 1}})  # type: ignore[dict-item]


def test_infinite_feature_round_trips_through_json() -> None:
    event = SecurityEvent(raw_event={}, features={"rate": float("inf")})
    dumped = event.model_dump_json()
    assert "Infinity" in dumped
    assert SecurityEvent.model_validate_json(dumped).features["rate"] == float("inf")
