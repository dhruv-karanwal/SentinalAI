import copy
from datetime import datetime, timezone
from typing import Any

import pytest

from app.ingestion.alert_normalizer import normalize_ait_ads_record
from app.ingestion.mappings import AitAdsFile
from app.ingestion.normalizer import Rejection
from app.ingestion.records import MALFORMED_RECORD, RawRecord
from app.schemas.alert import Alert, AlertKind, Detector, DetectorType

WAZUH: dict[str, Any] = {
    "agent": {"ip": "10.0.0.5", "name": "wazuh-client", "id": "18"},
    "rule": {"level": 3, "description": "ClamAV database update", "id": "52507"},
    "full_log": "Nov 14 22:00:00 mail freshclam[100]: synthetic line",
    "@timestamp": "2023-11-14T22:00:00.000000Z",
    "location": "/var/log/syslog",
    "id": "1700000000.1",
}
EVE: dict[str, Any] = {
    "agent": {"ip": "10.0.0.9"},
    "data": {"alert": {"severity": "2", "signature_id": "2000001", "rev": "2", "gid": "1",
                       "signature": "ET SCAN synthetic signature"}},
    "rule": {"level": 3, "description": "Suricata: Alert - ET SCAN synthetic signature", "id": "86601"},
    "@timestamp": "2023-11-14T22:15:00.000000Z",
    "location": "/var/log/suricata/eve.json",
    "id": "1700000000.2",
}
FAST: dict[str, Any] = {
    "agent": {"ip": "10.0.0.9"},
    "data": {"id": "1:2000001:2"},
    "rule": {"level": 8, "description": "First time this IDS alert is generated.", "id": "20100"},
    "full_log": "11/14/2023-22:15:00.000000  [**] [1:2000001:2] ET SCAN synthetic signature",
    "@timestamp": "2023-11-14T22:15:00.000000Z",
    "location": "/var/log/suricata/fast.log",
    "id": "1700000000.3",
}
AMINER: dict[str, Any] = {
    "AnalysisComponent": {"AnalysisComponentIdentifier": 19,
                          "AnalysisComponentType": "NewMatchPathValueDetector",
                          "AnalysisComponentName": "AMiner: New value in Audit logs.",
                          "TrainingMode": False},
    "LogData": {"RawLogData": ["type=EXECVE synthetic"], "Timestamps": [1700000120.25],
                "DetectionTimestamp": [1700000120.25], "LogResources": ["/var/log/audit/audit.log"]},
    "AMiner": {"ID": "10.0.0.7"},
}


def run(data: dict[str, Any] | None, kind: AitAdsFile, position: int = 1) -> Alert | Rejection:
    record = RawRecord(f"synthetic_{kind.value}.json", position, data)
    return normalize_ait_ads_record(record, kind, scenario="synthetic", dataset_name="synthetic-ait-ads")


def ok(data: dict[str, Any], kind: AitAdsFile) -> Alert:
    outcome = run(data, kind)
    assert isinstance(outcome, Alert), outcome
    return outcome


def rejected(data: dict[str, Any], kind: AitAdsFile) -> Rejection:
    outcome = run(data, kind)
    assert isinstance(outcome, Rejection), outcome
    return outcome


def test_wazuh_record() -> None:
    alert = ok(WAZUH, AitAdsFile.WAZUH)
    assert alert.detector is Detector.WAZUH and alert.detector_type is DetectorType.RULE_BASED
    assert alert.alert_id == "1700000000.1" and not alert.alert_id_derived
    assert alert.timestamp == datetime(2023, 11, 14, 22, 0, tzinfo=timezone.utc)
    assert (alert.rule_id, alert.rule_name, alert.severity) == ("52507", "ClamAV database update", 3)
    assert str(alert.host_ip) == "10.0.0.5"
    assert alert.evidence.log_lines == [WAZUH["full_log"]]
    assert alert.evidence.log_paths == ["/var/log/syslog"]
    assert alert.evidence.source_alert_id == "1700000000.1"
    assert alert.event_ids == []
    assert alert.raw_alert == WAZUH
    assert (alert.source_file, alert.source_line) == ("synthetic_wazuh.json", 1)
    assert alert.dataset_name == "synthetic-ait-ads"


def test_eve_record_is_suricata() -> None:
    alert = ok(EVE, AitAdsFile.WAZUH)
    assert alert.detector is Detector.SURICATA and alert.detector_type is DetectorType.SIGNATURE_BASED
    assert alert.rule_id == "1:2000001:2"
    assert alert.rule_name == "ET SCAN synthetic signature"
    assert alert.severity == 2
    assert alert.evidence.log_lines == []  # eve records carry no full_log
    assert not alert.duplicate_of_suricata


def test_fast_log_record_is_flagged_duplicate() -> None:
    alert = ok(FAST, AitAdsFile.WAZUH)
    assert alert.detector is Detector.WAZUH
    assert alert.duplicate_of_suricata


def test_aminer_record_gets_derived_deterministic_id() -> None:
    first = ok(AMINER, AitAdsFile.AMINER)
    again = ok(copy.deepcopy(AMINER), AitAdsFile.AMINER)
    assert first.alert_id == again.alert_id and first.alert_id_derived
    assert first.alert_id.startswith("aminer-")
    assert run(AMINER, AitAdsFile.AMINER, position=2).alert_id != first.alert_id  # type: ignore[union-attr]
    changed = copy.deepcopy(AMINER)
    changed["LogData"]["RawLogData"] = ["type=EXECVE other"]
    assert ok(changed, AitAdsFile.AMINER).alert_id != first.alert_id
    assert first.detector is Detector.AMINER and first.detector_type is DetectorType.ANOMALY_BASED
    assert first.timestamp == datetime.fromtimestamp(1700000120.25, tz=timezone.utc)
    assert (first.rule_id, first.rule_name, first.severity) == ("19", "AMiner: New value in Audit logs.", None)
    assert first.evidence.log_lines == ["type=EXECVE synthetic"]
    assert first.evidence.log_timestamps == [datetime.fromtimestamp(1700000120.25, tz=timezone.utc)]
    assert first.evidence.source_alert_id is None
    assert first.kind is AlertKind.EVENT and not first.training_mode


def test_aminer_training_mode_is_kept_and_flagged() -> None:
    data = copy.deepcopy(AMINER)
    data["AnalysisComponent"]["TrainingMode"] = True
    assert ok(data, AitAdsFile.AMINER).training_mode


@pytest.mark.parametrize("key", ["CountData", "FrequencyData"])
def test_aminer_aggregate_has_no_evidence_log_line(key: str) -> None:
    data = copy.deepcopy(AMINER)
    data[key] = {"Confidence": 1}
    alert = ok(data, AitAdsFile.AMINER)
    assert alert.kind is AlertKind.AGGREGATE
    assert alert.evidence.log_lines == []
    assert alert.raw_alert["LogData"]["RawLogData"] == ["type=EXECVE synthetic"]  # kept, not used


@pytest.mark.parametrize(
    ("kind", "mutate", "category"),
    [
        (AitAdsFile.WAZUH, lambda d: d.update({"@timestamp": "not-a-time"}), "invalid_timestamp"),
        (AitAdsFile.WAZUH, lambda d: d.update({"@timestamp": "2023-11-14T22:00:00"}), "invalid_timestamp"),
        (AitAdsFile.WAZUH, lambda d: d.pop("@timestamp"), "missing_field"),
        (AitAdsFile.WAZUH, lambda d: d["agent"].update({"ip": "999.1.1.1"}), "invalid_ip"),
        (AitAdsFile.WAZUH, lambda d: d.pop("id"), "missing_field"),
        (AitAdsFile.WAZUH, lambda d: d["rule"].update({"level": "high"}), "invalid_severity"),
        (AitAdsFile.WAZUH, lambda d: d["rule"].update({"level": True}), "invalid_severity"),
        (AitAdsFile.WAZUH, lambda d: d.update({"full_log": 5}), "invalid_value"),
        (AitAdsFile.AMINER, lambda d: d["AnalysisComponent"].update({"TrainingMode": "yes"}), "invalid_value"),
        (AitAdsFile.AMINER, lambda d: d["AnalysisComponent"].pop("TrainingMode"), "missing_field"),
        (AitAdsFile.AMINER, lambda d: d["LogData"].update({"DetectionTimestamp": ["x"]}), "invalid_timestamp"),
        (AitAdsFile.AMINER, lambda d: d["LogData"].update({"DetectionTimestamp": []}), "missing_field"),
        (AitAdsFile.AMINER, lambda d: d["LogData"].update({"Timestamps": [float("nan")]}), "invalid_timestamp"),
    ],
)
def test_invalid_values_reject(kind: AitAdsFile, mutate: Any, category: str) -> None:
    data = copy.deepcopy(WAZUH if kind is AitAdsFile.WAZUH else AMINER)
    mutate(data)
    rejection = rejected(data, kind)
    assert rejection.category == category
    assert rejection.raw_event == data


def test_partial_suricata_rule_id_rejects() -> None:
    data = copy.deepcopy(EVE)
    del data["data"]["alert"]["rev"]
    assert rejected(data, AitAdsFile.WAZUH).category == "invalid_value"


def test_all_errors_are_collected() -> None:
    data = copy.deepcopy(WAZUH)
    data["@timestamp"] = "bad"
    data["agent"]["ip"] = "bad"
    assert {e.category for e in rejected(data, AitAdsFile.WAZUH).errors} == {
        "invalid_timestamp", "invalid_ip"}


def test_malformed_loader_record_rejects() -> None:
    record = RawRecord("synthetic_wazuh.json", 8, None, error="invalid JSON", error_category=MALFORMED_RECORD)
    outcome = normalize_ait_ads_record(record, AitAdsFile.WAZUH, scenario="synthetic")
    assert isinstance(outcome, Rejection) and outcome.category == MALFORMED_RECORD
