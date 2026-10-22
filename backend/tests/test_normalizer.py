import dataclasses
import math
from datetime import datetime, timezone
from typing import Any

import pytest

from app.ingestion.mappings import CICIDS2017, GENERIC, feature_name, get_mapping, normalize_column_name
from app.ingestion.normalizer import (
    INVALID_FEATURE,
    INVALID_IP,
    INVALID_PORT,
    INVALID_PROTOCOL,
    INVALID_SEVERITY,
    INVALID_SOURCE_TYPE,
    INVALID_TIMESTAMP,
    Rejection,
    normalize_protocol,
    normalize_record,
    parse_number,
)
from app.ingestion.records import EMPTY_RECORD, MALFORMED_RECORD, RawRecord
from app.schemas.event import SecurityEvent, Severity, SourceType

CICIDS_ROW = {
    "Flow ID": "192.168.10.5-203.0.113.10-52100-443-6",
    "Source IP": "192.168.10.5",
    "Source Port": "52100",
    "Destination IP": "203.0.113.10",
    "Destination Port": "443",
    "Protocol": "6",
    "Timestamp": "3/7/2017 8:55",
    "Flow Duration": "120000",
    "Flow Bytes/s": "Infinity",
    "Flow Packets/s": "NaN",
    "Fwd Header Length": "200",
    "Fwd Header Length.1": "200",
    "Label": "Web Attack – Brute Force",
}


def record(data: dict[str, Any] | None, **kwargs: Any) -> RawRecord:
    return RawRecord(source="test.csv", position=kwargs.pop("position", 2), data=data, **kwargs)


def event(data: dict[str, Any], mapping: Any = CICIDS2017) -> SecurityEvent:
    outcome = normalize_record(record(data), mapping)
    assert isinstance(outcome, SecurityEvent), outcome
    return outcome


def rejection(data: dict[str, Any], mapping: Any = CICIDS2017) -> Rejection:
    outcome = normalize_record(record(data), mapping)
    assert isinstance(outcome, Rejection), outcome
    return outcome


# --- helpers ---------------------------------------------------------------


def test_column_and_feature_names() -> None:
    assert normalize_column_name("  Source_IP ") == "source ip"
    assert normalize_column_name(" Destination  Port") == "destination port"
    assert feature_name("Flow Bytes/s") == "flow_bytes_s"
    assert feature_name("Fwd Header Length.1") == "fwd_header_length_1"


@pytest.mark.parametrize(
    ("text", "expected"),
    [("42", 42), ("-3", -3), ("1.5", 1.5), ("1e3", 1000.0), (".5", 0.5),
     ("Infinity", math.inf), ("-Infinity", -math.inf), (7, 7), (2.5, 2.5)],
)
def test_parse_number(text: Any, expected: float) -> None:
    assert parse_number(text) == expected


@pytest.mark.parametrize("text", ["abc", "1_000", "0x10", "", "1.2.3", True])
def test_parse_number_rejects_look_alikes(text: Any) -> None:
    with pytest.raises(ValueError):
        parse_number(text)


@pytest.mark.parametrize(
    ("value", "expected"),
    [(6, "tcp"), ("17", "udp"), ("1", "icmp"), ("0", "0"), ("99", "99"), ("TCP", "tcp")],
)
def test_normalize_protocol(value: Any, expected: str) -> None:
    assert normalize_protocol(value) == expected


def test_normalize_protocol_out_of_range() -> None:
    with pytest.raises(ValueError, match="0-255"):
        normalize_protocol("300")


def test_get_mapping_unknown() -> None:
    with pytest.raises(ValueError, match="available: cicids2017, generic"):
        get_mapping("nope")


# --- CICIDS2017 mapping ----------------------------------------------------


def test_cicids_row_is_normalized() -> None:
    result = event(CICIDS_ROW)
    assert result.source_type is SourceType.NETWORK
    assert str(result.source_ip) == "192.168.10.5"
    assert str(result.destination_ip) == "203.0.113.10"
    assert result.source_port == 52100
    assert result.destination_port == 443
    assert result.protocol == "tcp"
    assert result.event_type == "network_flow"
    assert result.dataset_name == "CICIDS2017"
    # 3 July 2017 08:55 at the assumed UTC-03:00 -> 11:55 UTC
    assert result.timestamp == datetime(2017, 7, 3, 11, 55, tzinfo=timezone.utc)
    assert result.metadata["timestamp_timezone_assumed"] == "UTC-03:00"
    assert result.metadata["flow_id"] == CICIDS_ROW["Flow ID"]
    assert result.metadata["source_file"] == "test.csv"
    assert result.metadata["source_position"] == 2


def test_cicids_label_and_raw_event_are_preserved() -> None:
    result = event(CICIDS_ROW)
    assert result.label == "Web Attack – Brute Force"
    assert result.raw_event == CICIDS_ROW
    assert "label" not in result.features


def test_cicids_features() -> None:
    features = event(CICIDS_ROW).features
    assert features == {
        "flow_duration": 120000,
        "flow_bytes_s": math.inf,
        "flow_packets_s": None,  # "NaN" is treated as missing
        "fwd_header_length": 200,
        "fwd_header_length_1": 200,
    }


def test_cicids_event_id_is_derived_from_position() -> None:
    result = event(CICIDS_ROW)
    assert result.event_id == "test.csv:2"
    assert result.metadata["event_id_derived"] is True


def test_missing_optional_fields_are_not_invented() -> None:
    row = {**CICIDS_ROW, "Source IP": "", "Timestamp": " ", "Label": "", "Protocol": ""}
    result = event(row)
    assert result.source_ip is None
    assert result.timestamp is None
    assert result.label is None
    assert result.protocol is None
    assert result.severity is None
    assert "timestamp_timezone_assumed" not in result.metadata


def test_machine_learning_cve_layout_without_ids() -> None:
    result = event({" Destination Port": "80", "Flow Duration": "5", " Label": "BENIGN"})
    assert result.destination_port == 80
    assert result.source_ip is None and result.timestamp is None
    assert result.features == {"flow_duration": 5}
    assert result.label == "BENIGN"


@pytest.mark.parametrize(
    ("timestamp", "expected"),
    [
        ("7/7/2017 1:45:10 PM", datetime(2017, 7, 7, 16, 45, 10, tzinfo=timezone.utc)),
        ("3/7/2017 9:01:30", datetime(2017, 7, 3, 12, 1, 30, tzinfo=timezone.utc)),
        ("2017-07-03T08:55:00+00:00", datetime(2017, 7, 3, 8, 55, tzinfo=timezone.utc)),
    ],
)
def test_cicids_timestamp_formats(timestamp: str, expected: datetime) -> None:
    assert event({**CICIDS_ROW, "Timestamp": timestamp}).timestamp == expected


def test_assumed_timezone_can_be_overridden() -> None:
    utc_mapping = dataclasses.replace(CICIDS2017, naive_timezone=timezone.utc)
    result = event(CICIDS_ROW, utc_mapping)
    assert result.timestamp == datetime(2017, 7, 3, 8, 55, tzinfo=timezone.utc)


def test_naive_timestamp_rejected_without_assumption() -> None:
    strict = dataclasses.replace(CICIDS2017, naive_timezone=None)
    result = rejection(CICIDS_ROW, strict)
    assert result.category == INVALID_TIMESTAMP
    assert "--assume-timezone" in result.errors[0].message


@pytest.mark.parametrize("timestamp", ["32/7/2017 8:00", "yesterday", "7/13/2017 10:00"])
def test_invalid_timestamp_is_rejected(timestamp: str) -> None:
    result = rejection({**CICIDS_ROW, "Timestamp": timestamp})
    assert result.category == INVALID_TIMESTAMP
    assert result.fields == {"timestamp"}
    assert result.raw_event is not None and result.raw_event["Timestamp"] == timestamp


@pytest.mark.parametrize(
    ("column", "value", "category"),
    [
        ("Source IP", "192.168.10.300", INVALID_IP),
        ("Destination Port", "70000", INVALID_PORT),
        ("Destination Port", "http", INVALID_PORT),
        ("Protocol", "256", INVALID_PROTOCOL),
        ("Flow Duration", "abc", INVALID_FEATURE),
    ],
)
def test_invalid_values_are_rejected_not_coerced(column: str, value: str, category: str) -> None:
    result = rejection({**CICIDS_ROW, column: value})
    assert result.category == category
    assert value in result.errors[0].message


def test_all_errors_in_a_record_are_reported() -> None:
    result = rejection({**CICIDS_ROW, "Timestamp": "bad", "Flow Duration": "x", "Source IP": "nope"})
    categories = {e.category for e in result.errors}
    assert {INVALID_TIMESTAMP, INVALID_FEATURE} <= categories
    assert result.category == INVALID_TIMESTAMP


def test_empty_and_loader_error_records() -> None:
    empty = rejection({"a": "", "b": " ", "c": "NaN"})
    assert empty.category == EMPTY_RECORD
    loader_error = normalize_record(
        record(None, error="expected 3 fields, found 2", error_category=MALFORMED_RECORD,
               raw_text="1,2"),
        CICIDS2017,
    )
    assert isinstance(loader_error, Rejection)
    assert loader_error.category == MALFORMED_RECORD
    assert loader_error.raw_text == "1,2"
    assert loader_error.to_dict()["errors"][0]["message"] == "expected 3 fields, found 2"


def test_feature_name_collision_is_rejected() -> None:
    result = rejection({"Flow Bytes/s": "1", "flow bytes s": "2", "Label": "BENIGN"})
    assert result.category == INVALID_FEATURE
    assert "collides" in result.errors[0].message


def test_explicit_feature_columns() -> None:
    mapping = dataclasses.replace(CICIDS2017, feature_columns=("Flow Duration",))
    result = event(CICIDS_ROW, mapping)
    assert result.features == {"flow_duration": 120000}
    assert "Flow Bytes/s" in result.metadata["unmapped_fields"]


# --- generic mapping -------------------------------------------------------


def test_generic_aliases_and_nested_features() -> None:
    data = {
        "id": 17,
        "@timestamp": "2026-01-15T09:31:12+01:00",
        "source_type": "Authentication",
        "src_ip": "10.0.0.77",
        "dst_port": "22",
        "proto": 6,
        "severity": "HIGH",
        "event_type": "login_failure",
        "ground_truth": "credential_stuffing",
        "dataset": "synthetic",
        "user": "svc",
        "process": {"name": "sshd"},
        "features": {"attempts": 14, "mfa": False, "method": "password"},
    }
    result = event(data, GENERIC)
    assert result.event_id == "17"
    assert result.timestamp == datetime(2026, 1, 15, 8, 31, 12, tzinfo=timezone.utc)
    assert result.source_type is SourceType.AUTHENTICATION
    assert result.destination_port == 22
    assert result.protocol == "tcp"
    assert result.severity is Severity.HIGH
    assert result.label == "credential_stuffing"
    assert result.dataset_name == "synthetic"
    assert result.metadata["user"] == "svc"
    assert result.metadata["unmapped_fields"] == ["process"]
    assert result.features == {"attempts": 14, "mfa": False, "method": "password"}
    assert result.raw_event == data
    assert "event_id_derived" not in result.metadata


def test_generic_defaults_do_not_invent_values() -> None:
    result = event({"message": "heartbeat"}, GENERIC)
    assert result.source_type is SourceType.UNKNOWN
    assert result.event_id is None
    assert result.timestamp is None
    assert result.event_type is None
    assert result.dataset_name is None
    assert result.features == {}
    assert result.metadata["unmapped_fields"] == ["message"]


def test_generic_epoch_seconds_are_utc() -> None:
    result = event({"timestamp": 1768469400}, GENERIC)
    assert result.timestamp == datetime(2026, 1, 15, 9, 30, tzinfo=timezone.utc)


def test_epoch_not_accepted_for_cicids() -> None:
    assert rejection({**CICIDS_ROW, "Timestamp": 1768469400}).category == INVALID_TIMESTAMP


@pytest.mark.parametrize(
    ("data", "category"),
    [
        ({"timestamp": "2026-01-15 10:05:00"}, INVALID_TIMESTAMP),
        ({"severity": "urgent"}, INVALID_SEVERITY),
        ({"source_type": "firewall"}, INVALID_SOURCE_TYPE),
        ({"dst_port": 70000}, INVALID_PORT),
        ({"src_ip": "10.0.0"}, INVALID_IP),
        ({"features": [1, 2]}, INVALID_FEATURE),
        ({"features": {"x": {"nested": 1}}}, INVALID_FEATURE),
        ({"features": {"label": "BENIGN"}}, INVALID_FEATURE),
    ],
)
def test_generic_invalid_records(data: dict[str, Any], category: str) -> None:
    assert rejection({"event_id": "x", **data}, GENERIC).category == category
