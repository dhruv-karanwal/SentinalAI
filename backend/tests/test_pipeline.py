"""End-to-end runs over the committed synthetic samples."""

import dataclasses
import json
from pathlib import Path

import pytest

from app.ingestion.mappings import CICIDS2017, GENERIC
from app.main import main, parse_timezone
from app.pipeline import run_pipeline
from app.schemas.event import SecurityEvent


def test_cicids_csv_sample(samples_dir: Path, tmp_path: Path) -> None:
    mapping = dataclasses.replace(CICIDS2017, dataset_name="synthetic-cicids2017-format")
    result = run_pipeline(samples_dir / "synthetic_cicids2017_format.csv", mapping, output_dir=tmp_path)
    report = result.report

    assert report["record_counts"] == {"total_input": 14, "normalized": 9, "rejected": 5}
    assert report["rejections"]["by_reason"] == {
        "empty_record": 1, "invalid_feature": 1, "invalid_ip": 1,
        "invalid_timestamp": 1, "malformed_record": 1,
    }
    assert report["timestamps"]["parse_failures"] == 1
    assert report["timestamps"]["missing"] == 1
    assert report["timestamps"]["min"] == "2017-07-03T11:55:00+00:00"
    assert report["timestamps"]["max"] == "2017-07-07T16:45:10+00:00"
    assert report["duplicates"]["duplicate_raw_records"] == 1
    assert report["duplicates"]["duplicate_feature_vectors"] == 1
    assert report["labels"]["unlabelled"] == 1
    assert {k: v["count"] for k, v in report["labels"]["distribution"].items()} == {
        "BENIGN": 4, "DoS Hulk": 2, "PortScan": 1, "Web Attack – Brute Force": 1,
    }
    bytes_s = report["features"]["numeric"]["flow_bytes_s"]
    assert (bytes_s["present"], bytes_s["missing"], bytes_s["non_finite_count"]) == (7, 2, 1)
    assert report["dataset_name"] == "synthetic-cicids2017-format"
    assert all(e.dataset_name == "synthetic-cicids2017-format" for e in result.events)

    # Outputs exist, line counts match, and events round-trip through the schema.
    events_lines = result.output_paths["events"].read_text(encoding="utf-8").splitlines()
    rejected_lines = result.output_paths["rejected"].read_text(encoding="utf-8").splitlines()
    assert len(events_lines) == 9
    assert len(rejected_lines) == 5
    restored = SecurityEvent.model_validate_json(events_lines[0])
    assert restored == result.events[0]
    rejected = [json.loads(line) for line in rejected_lines]
    assert [r["source_position"] for r in rejected] == [9, 10, 11, 12, 13]
    assert rejected[1]["raw_event"]["Source IP"] == "192.168.10.300"
    saved_report = json.loads(result.output_paths["quality"].read_text(encoding="utf-8"))
    assert saved_report == report


def test_json_sample(samples_dir: Path) -> None:
    result = run_pipeline(samples_dir / "synthetic_security_events.json", GENERIC)
    report = result.report
    assert report["record_counts"] == {"total_input": 10, "normalized": 5, "rejected": 5}
    assert report["rejections"]["by_reason"] == {
        "invalid_port": 1, "invalid_severity": 1, "invalid_source_type": 1,
        "invalid_timestamp": 1, "malformed_record": 1,
    }
    assert report["duplicates"]["duplicate_event_ids"] == 1
    assert report["source_type_distribution"] == {
        "network": 2, "authentication": 1, "endpoint": 1, "application": 1,
    }
    assert all(e.dataset_name == "synthetic-sample" for e in result.events)
    assert result.events[2].metadata["unmapped_fields"] == ["parent_process", "process_name"]


def test_jsonl_sample(samples_dir: Path) -> None:
    result = run_pipeline(samples_dir / "synthetic_security_events.jsonl", GENERIC)
    assert result.report["record_counts"] == {"total_input": 4, "normalized": 3, "rejected": 1}
    assert result.rejections[0].position == 4
    assert result.rejections[0].category == "malformed_record"


def test_row_limit(samples_dir: Path) -> None:
    result = run_pipeline(samples_dir / "synthetic_cicids2017_format.csv", CICIDS2017, limit=3)
    assert result.report["record_counts"]["total_input"] == 3
    assert result.report["row_limit"] == 3


def test_collect_false_streams_to_disk(samples_dir: Path, tmp_path: Path) -> None:
    result = run_pipeline(samples_dir / "synthetic_security_events.jsonl", GENERIC,
                          output_dir=tmp_path, collect=False)
    assert result.events == [] and result.rejections == []
    assert len(result.output_paths["events"].read_text(encoding="utf-8").splitlines()) == 3


def test_cli_success_and_failure(samples_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main([
        "ingest", str(samples_dir / "synthetic_cicids2017_format.csv"),
        "--mapping", "cicids2017", "--dataset-name", "synthetic-cicids2017-format",
        "--assume-timezone", "UTC", "--output-dir", str(tmp_path),
    ])
    out = capsys.readouterr().out
    assert code == 0
    assert "14 input, 9 normalized, 5 rejected" in out
    report = json.loads((tmp_path / "synthetic_cicids2017_format.quality.json").read_text(encoding="utf-8"))
    assert report["timestamps"]["min"] == "2017-07-03T08:55:00+00:00"

    assert main(["ingest", str(tmp_path / "missing.csv"), "--no-output"]) == 1
    assert "not found" in capsys.readouterr().err


def test_parse_timezone() -> None:
    assert parse_timezone("none") is None
    assert parse_timezone("+05:30").utcoffset(None).total_seconds() == 5.5 * 3600  # type: ignore[union-attr]
    assert parse_timezone("-0300").utcoffset(None).total_seconds() == -3 * 3600  # type: ignore[union-attr]
