import json
import math
from typing import Any

from app.ingestion.mappings import CICIDS2017, GENERIC
from app.ingestion.normalizer import Rejection, normalize_record
from app.ingestion.records import RawRecord
from app.schemas.event import SecurityEvent
from app.services.data_quality import CANONICAL_OPTIONAL_FIELDS, build_quality_report


def outcomes(rows: list[dict[str, Any] | None], mapping: Any = GENERIC) -> list[SecurityEvent | Rejection]:
    return [
        normalize_record(
            RawRecord("t.json", i, row, error=None if row is not None else "bad",
                      error_category=None if row is not None else "malformed_record"),
            mapping,
        )
        for i, row in enumerate(rows, start=1)
    ]


def test_empty_input_report() -> None:
    report = build_quality_report([])
    assert report["record_counts"] == {"total_input": 0, "normalized": 0, "rejected": 0}
    assert report["labels"]["distribution"] == {}
    assert report["timestamps"]["min"] is None
    assert report["features"]["feature_count"] == 0
    json.dumps(report, allow_nan=False)


def test_counts_and_rejection_reasons() -> None:
    report = build_quality_report(outcomes([
        {"event_id": "a", "label": "BENIGN"},
        {"event_id": "b", "timestamp": "not a time"},
        {"event_id": "c", "src_ip": "999.0.0.1"},
        None,
    ]))
    assert report["record_counts"] == {"total_input": 4, "normalized": 1, "rejected": 3}
    assert report["rejections"]["by_reason"] == {
        "invalid_ip": 1, "invalid_timestamp": 1, "malformed_record": 1,
    }
    examples = report["rejections"]["examples"]
    assert [e["source_position"] for e in examples] == [2, 3, 4]
    assert "not a time" in examples[0]["messages"][0]
    assert report["timestamps"]["parse_failures"] == 1


def test_missing_values_by_field() -> None:
    report = build_quality_report(outcomes([
        {"event_id": "a", "src_ip": "10.0.0.1", "timestamp": "2026-01-01T00:00:00Z"},
        {"event_id": "b"},
    ]))
    missing = report["missing_values_by_field"]
    assert set(missing) == set(CANONICAL_OPTIONAL_FIELDS)
    assert missing["event_id"] == 0
    assert missing["source_ip"] == 1
    assert missing["timestamp"] == 1
    assert missing["label"] == 2
    assert report["timestamps"]["parsed"] == 1
    assert report["timestamps"]["missing"] == 1


def test_duplicate_detection() -> None:
    report = build_quality_report(outcomes([
        {"event_id": "a", "label": "x", "features": {"f": 1}},
        {"event_id": "a", "label": "x", "features": {"f": 1}},  # exact duplicate
        {"event_id": "a", "label": "y", "features": {"f": 1}},  # id reused, new label
        {"event_id": "b", "label": "x", "features": {"f": 1}},  # same vector + label
    ]))
    dup = report["duplicates"]
    assert dup["duplicate_raw_records"] == 1
    assert dup["duplicate_event_ids"] == 2
    assert dup["duplicate_event_id_examples"] == ["a", "a"]
    assert dup["duplicate_feature_vectors"] == 2
    assert dup["event_ids_derived"] == 0


def test_derived_ids_are_not_counted_as_duplicates() -> None:
    row = {"Flow Duration": "1", "Label": "BENIGN"}
    report = build_quality_report(outcomes([row, row], CICIDS2017))
    assert report["duplicates"]["event_ids_derived"] == 2
    assert report["duplicates"]["duplicate_event_ids"] == 0
    assert report["duplicates"]["duplicate_raw_records"] == 1


def test_label_distribution_is_reported_not_rebalanced() -> None:
    rows = [{"label": "BENIGN"}] * 3 + [{"label": "DoS"}, {"message": "no label"}]
    report = build_quality_report(outcomes(rows))
    labels = report["labels"]
    assert labels["labelled"] == 4
    assert labels["unlabelled"] == 1
    assert labels["distribution"] == {
        "BENIGN": {"count": 3, "proportion": 0.75},
        "DoS": {"count": 1, "proportion": 0.25},
    }
    assert report["record_counts"]["normalized"] == 5


def test_numeric_and_categorical_feature_statistics() -> None:
    rows = [
        {"features": {"rate": 1, "method": "GET"}},
        {"features": {"rate": 3.0, "method": "POST"}},
        {"features": {"rate": math.inf, "method": "GET"}},
        {"features": {"rate": None}},
    ]
    report = build_quality_report(outcomes(rows))
    rate = report["features"]["numeric"]["rate"]
    assert rate["present"] == 3
    assert rate["missing"] == 1
    assert rate["finite_count"] == 2
    assert rate["non_finite_count"] == 1
    assert (rate["min"], rate["max"], rate["mean"]) == (1.0, 3.0, 2.0)
    assert rate["std"] == round(math.sqrt(2), 6)
    method = report["features"]["categorical"]["method"]
    assert method["value_counts"] == {"GET": 2, "POST": 1}
    assert method["missing"] == 1
    json.dumps(report, allow_nan=False)


def test_source_type_distribution() -> None:
    rows = [{"source_type": "network"}, {"source_type": "endpoint"}, {"source_type": "network"}]
    assert build_quality_report(outcomes(rows))["source_type_distribution"] == {
        "network": 2, "endpoint": 1,
    }
