"""End-to-end runs over the committed synthetic AIT-ADS-format sample."""

import json
from pathlib import Path

import pytest

from app.alert_pipeline import AitAdsInputs, iter_alert_file, run_alert_ingest
from app.ingestion.records import IngestionError
from app.main import main
from app.schemas.alert import (
    DEFAULT_EVALUATION_SELECTION,
    INVESTIGATION_SELECTION,
    Alert,
    GroundTruth,
)

DATASET = "synthetic-ait-ads-format"


@pytest.fixture
def sample_dir(samples_dir: Path) -> Path:
    return samples_dir / "synthetic_ait_ads"


def inputs(sample_dir: Path, *, event_labels: bool = True) -> AitAdsInputs:
    return AitAdsInputs(
        scenario="synthetic",
        wazuh=sample_dir / "synthetic_wazuh.json",
        aminer=sample_dir / "synthetic_aminer.json",
        labels=sample_dir / "synthetic_labels.csv",
        event_labels=sample_dir / "synthetic_alerts.txt" if event_labels else None,
    )


def test_sample_ingest(sample_dir: Path, tmp_path: Path) -> None:
    result = run_alert_ingest(inputs(sample_dir), dataset_name=DATASET, output_dir=tmp_path)
    report = result.report

    assert report["record_counts"] == {"total_input": 13, "normalized": 9, "rejected": 4}
    assert report["rejections"]["by_reason"] == {
        "invalid_ip": 1, "invalid_timestamp": 1, "invalid_value": 1, "malformed_record": 1}
    assert report["rejections"]["by_file"] == {"synthetic_aminer.json": 1, "synthetic_wazuh.json": 3}
    assert report["detectors"] == {
        "wazuh": {"alerts": 4, "training_mode": 0, "aggregate": 0, "duplicate_of_suricata": 2,
                  "evaluation_eligible": 2, "investigation_eligible": 2},
        "suricata": {"alerts": 1, "training_mode": 0, "aggregate": 0, "duplicate_of_suricata": 0,
                     "evaluation_eligible": 1, "investigation_eligible": 1},
        "aminer": {"alerts": 4, "training_mode": 1, "aggregate": 2, "duplicate_of_suricata": 0,
                   "evaluation_eligible": 3, "investigation_eligible": 1},
    }
    assert report["suricata_duplicates"] == {
        "fast_log_records": 2, "fast_log_matched_to_eve": 1, "fast_log_unmatched": 1,
        "eve_records": 1, "eve_without_fast_log_twin": 0,
    }
    assert report["alert_ids"] == {"derived": 4, "duplicate_alert_ids": 0}
    assert report["timestamps"] == {
        "min": "2023-11-14T19:26:50.500000+00:00", "max": "2023-11-14T22:18:20+00:00"}

    truth = report["ground_truth"]
    assert [i["attack"] for i in truth["attack_intervals"]] == ["dnsteal", "network_scans", "dirb"]
    assert truth["attack_intervals_within_alert_range"] == 2
    assert truth["time_label_distribution"] == {
        "dirb": 4, "dnsteal": 2, "false_positive": 2, "network_scans": 1}
    assert truth["investigation_time_labels_by_detector"] == {
        "aminer": {"dirb": 1}, "suricata": {"dirb": 1},
        "wazuh": {"false_positive": 1, "network_scans": 1},
    }
    assert truth["attack_phases_with_investigation_alert"] == {
        "aminer": ["dirb"], "suricata": ["dirb"], "wazuh": ["network_scans"]}
    events = truth["event_labels"]
    assert events["source_file"] == "synthetic_alerts.txt"
    assert events["link_status"] == "linked"
    assert (events["rows_consumed"], events["csv_rows_left_over"], events["mismatch_position"]) == (13, 0, None)
    assert (events["available"], events["unavailable"], events["no_event_label"]) == (9, 0, 4)
    assert events["distribution"] == {
        "dirb": 2, "dnsteal": 1, "escalated_sudo_command": 1, "service_scan": 1}
    assert events["csv_time_label_agreement"] == {"agree": 9, "disagree": 0}
    assert truth["coverage"] == {"alerts": 9, "with_time_label": 9, "with_event_label_available": 9}

    # Outputs: one line per alert / rejection / ground-truth record, all round-trip.
    paths = result.output_paths
    alerts = [Alert.model_validate_json(line) for line in paths["alerts"].read_text("utf-8").splitlines()]
    truths = [GroundTruth.model_validate_json(line)
              for line in paths["ground_truth"].read_text("utf-8").splitlines()]
    rejected = [json.loads(line) for line in paths["rejected"].read_text("utf-8").splitlines()]
    assert (len(alerts), len(truths), len(rejected)) == (9, 9, 4)
    assert [a.alert_id for a in alerts] == [t.alert_id for t in truths]
    assert all(a.dataset_name == DATASET and a.event_ids == [] for a in alerts)
    assert json.loads(paths["quality"].read_text("utf-8")) == report
    # Ground truth never leaks into the alert layer.
    alerts_text = paths["alerts"].read_text("utf-8")
    assert '"time_label"' not in alerts_text and '"event_label"' not in alerts_text

    eligible = list(iter_alert_file(paths["alerts"], INVESTIGATION_SELECTION))
    assert [a.detector.value for a in eligible] == ["wazuh", "suricata", "wazuh", "aminer"]
    assert len(list(iter_alert_file(paths["alerts"], DEFAULT_EVALUATION_SELECTION))) == 6
    assert len(list(iter_alert_file(paths["alerts"]))) == 9


def test_without_event_labels(sample_dir: Path) -> None:
    result = run_alert_ingest(inputs(sample_dir, event_labels=False), dataset_name=DATASET)
    events = result.report["ground_truth"]["event_labels"]
    assert events["link_status"] == "not_provided" and events["available"] == 0
    assert all(not t.event_label_available and t.event_label is None for t in result.ground_truth)


def test_limit_stops_reading(sample_dir: Path) -> None:
    result = run_alert_ingest(inputs(sample_dir), dataset_name=DATASET, limit=3)
    assert result.report["record_counts"]["total_input"] == 3
    assert result.report["row_limit"] == 3


def test_missing_input_file_raises(sample_dir: Path, tmp_path: Path) -> None:
    bad = inputs(sample_dir)
    bad = AitAdsInputs(bad.scenario, tmp_path / "missing_wazuh.json", bad.aminer, bad.labels, None)
    with pytest.raises(IngestionError, match="not found"):
        run_alert_ingest(bad)


def test_layout_paths(tmp_path: Path) -> None:
    layout = AitAdsInputs.from_layout(tmp_path, "fox")
    assert layout.wazuh == tmp_path / "fox_wazuh.json"
    assert layout.aminer == tmp_path / "fox_aminer.json"
    assert layout.labels == tmp_path / "labels.csv"
    assert layout.event_labels is None  # alerts_csv not present
    csv_dir = tmp_path / "alerts_csv" / "alerts_csv"
    csv_dir.mkdir(parents=True)
    (csv_dir / "fox_alerts.txt").write_text("x", encoding="utf-8")
    assert AitAdsInputs.from_layout(tmp_path, "fox").event_labels == csv_dir / "fox_alerts.txt"
    with pytest.raises(ValueError, match="scenario"):
        AitAdsInputs.from_layout(tmp_path, "../etc")


def test_cli(sample_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main([
        "ingest-alerts", "--data-dir", str(sample_dir), "--scenario", "synthetic",
        "--labels", str(sample_dir / "synthetic_labels.csv"),
        "--event-labels", str(sample_dir / "synthetic_alerts.txt"),
        "--dataset-name", DATASET, "--output-dir", str(tmp_path),
    ])
    assert code == 0
    out = capsys.readouterr().out
    assert "13 input, 9 normalized, 4 rejected" in out
    assert (tmp_path / "synthetic.alerts.jsonl").exists()
    assert (tmp_path / "synthetic.ground_truth.jsonl").exists()

    assert main(["ingest-alerts", "--data-dir", str(tmp_path / "nope"), "--scenario", "synthetic",
                 "--no-output"]) == 1
