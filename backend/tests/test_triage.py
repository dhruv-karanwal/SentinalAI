"""Wave B3: grouping by entity and time gap, the severity rule table, incidents, API route."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.api.app import Services, create_app
from app.api.auth import Role
from app.detection import triage as tr
from app.intel.ioc import Indicator, IocStore
from app.platform.enrichment import enrich
from app.schemas.alert import DETECTOR_TYPES, Alert, AlertEvidence, AlertKind, Detector
from app.storage.db import SqliteDatabase
from app.storage.repository import Repository
from tests.test_api import client, services, token  # noqa: F401  (fixtures)
from tests.test_variants import processed  # noqa: F401  (fixture)

T0 = datetime(2022, 1, 21, 10, 0, tzinfo=timezone.utc)


def mk(aid: str, seconds: float, *, detector: Detector = Detector.WAZUH, host: str | None = "10.0.0.5",
       raw: dict[str, Any] | None = None, severity: int | None = 3, **kw: Any) -> Alert:
    return Alert(alert_id=aid, scenario="synthetic", detector=detector,
                 detector_type=DETECTOR_TYPES[detector], timestamp=T0 + timedelta(seconds=seconds),
                 rule_id="r1", severity=severity, host_ip=host, raw_alert=raw or {},
                 evidence=AlertEvidence(), source_file="f.json", source_line=1, **kw)


def groups(alerts: list[Alert], gap: int = 300) -> list[list[str]]:
    return sorted(sorted(a.alert_id for a in g) for g in tr.group_alerts(alerts, gap))


def test_single_alert_is_one_incident() -> None:
    (inc,) = tr.build_incidents([mk("a", 0)], "synthetic", tr.TriageConfig())
    assert inc["alert_ids"] == ["a"] and inc["detail"]["features"]["size"] == 1
    assert inc["severity"] == "Low" and inc["detail"]["severity_row"] == "L1"
    assert inc["detail"]["timeline"][0]["alert_id"] == "a"


def test_gap_boundary_exactly_at_joins_just_over_splits() -> None:
    assert groups([mk("a", 0), mk("b", 300)]) == [["a", "b"]]
    assert groups([mk("a", 0), mk("b", 300.001)]) == [["a"], ["b"]]
    # chaining: each step within the gap
    assert groups([mk("a", 0), mk("b", 200), mk("c", 400)]) == [["a", "b", "c"]]


def test_different_entities_do_not_merge() -> None:
    assert groups([mk("a", 0, host="10.0.0.5"), mk("b", 1, host="10.0.0.6")]) == [["a"], ["b"]]
    assert groups([mk("a", 0, host=None), mk("b", 1, host=None)]) == [["a"], ["b"]]


def test_cross_detector_merge_through_a_shared_ip() -> None:
    wazuh = mk("w", 0, host="10.0.0.5", raw={"data": {"srcip": "192.168.1.9"}})
    suri = mk("s", 60, detector=Detector.SURICATA, host="10.0.0.99", severity=2,
              raw={"data": {"src_ip": "192.168.1.9", "dest_ip": "10.0.0.5"}})
    aminer = mk("m", 120, detector=Detector.AMINER, host="10.0.0.99", severity=None)
    assert groups([wazuh, suri, aminer]) == [["m", "s", "w"]]
    assert tr.entities(suri) == ["host:10.0.0.99", "ip:192.168.1.9"]  # dest ip is not an entity


def test_level_classes() -> None:
    assert tr.level_class(mk("a", 0, severity=12)) == "high"
    assert tr.level_class(mk("a", 0, severity=11)) == "medium"
    assert tr.level_class(mk("a", 0, severity=7)) == "medium"
    assert tr.level_class(mk("a", 0, severity=6)) == "low"
    s = Detector.SURICATA
    assert [tr.level_class(mk("a", 0, detector=s, severity=v)) for v in (1, 2, 3)] == \
        ["high", "medium", "low"]
    assert tr.level_class(mk("a", 0, detector=Detector.AMINER, severity=None)) == "none"
    sig = Detector.SIGMA
    assert tr.level_class(mk("a", 0, detector=sig, severity=None,
                             raw={"sigma": {"level": "critical"}})) == "high"
    assert tr.level_class(mk("a", 0, detector=sig, severity=None,
                             raw={"sigma": {"level": "medium"}})) == "medium"
    assert tr.level_class(mk("a", 0, detector=sig, severity=None,
                             raw={"sigma": {"level": "informational"}})) == "low"


F = tr.IncidentFeatures


@pytest.mark.parametrize("features,severity,row", [
    (F(size=1, detectors=1, max_level="low", attack_mapped=False, ioc_match=True), "High", "H1"),
    (F(size=3, detectors=3, max_level="none", attack_mapped=False, ioc_match=False), "High", "H2"),
    (F(size=2, detectors=1, max_level="high", attack_mapped=True, ioc_match=False), "High", "H3"),
    (F(size=2, detectors=2, max_level="high", attack_mapped=False, ioc_match=False), "High", "H3"),
    (F(size=2, detectors=1, max_level="high", attack_mapped=False, ioc_match=False), "Medium", "M1"),
    (F(size=2, detectors=2, max_level="low", attack_mapped=True, ioc_match=False), "Medium", "M2"),
    (F(size=10, detectors=1, max_level="medium", attack_mapped=False, ioc_match=False), "Medium", "M3"),
    (F(size=9, detectors=1, max_level="medium", attack_mapped=False, ioc_match=False), "Low", "L1"),
    (F(size=50, detectors=2, max_level="low", attack_mapped=False, ioc_match=False), "Low", "L1"),
])
def test_every_row_of_the_severity_table(features: tr.IncidentFeatures, severity: str, row: str) -> None:
    assert tr.severity(features) == (severity, row)


def test_severity_table_rows_are_all_tested() -> None:
    assert [r.row_id for r in tr.SEVERITY_TABLE] == ["H1", "H2", "H3", "M1", "M2", "M3", "L1"]


def test_features_from_alerts_attack_and_ioc() -> None:
    wazuh = mk("w", 0, severity=5, raw={"rule": {"mitre": {"id": ["T1110"]}},
                                        "data": {"srcip": "203.0.113.7"}})
    feats = tr.incident_features([wazuh, mk("x", 1)], IocStore([Indicator("ip", "203.0.113.7",
                                                                          "synthetic")]))
    assert feats == F(size=2, detectors=1, max_level="low", attack_mapped=True, ioc_match=True)


def test_incident_ids_are_deterministic_and_selection_applies() -> None:
    alerts = [mk("a", 0), mk("b", 10), mk("dup", 20, duplicate_of_suricata=True),
              mk("t", 30, detector=Detector.AMINER, severity=None, training_mode=True)]
    first = tr.build_incidents(alerts, "synthetic", tr.TriageConfig())
    again = tr.build_incidents(list(reversed(alerts)), "synthetic", tr.TriageConfig())
    assert [i["incident_id"] for i in first] == [i["incident_id"] for i in again]
    assert first[0]["alert_ids"] == ["a", "b"] and first[0]["detail"]["excluded_by_selection"] == 2
    agg = mk("g", 40, detector=Detector.AMINER, severity=None, kind=AlertKind.AGGREGATE)
    assert len(tr.build_incidents(alerts + [agg], "synthetic", tr.TriageConfig())[0]["alert_ids"]) == 3


def test_build_and_store_writes_incidents(tmp_path: Path) -> None:
    db = SqliteDatabase(":memory:")
    db.migrate()
    repo = Repository(db)
    for a in (mk("a", 0), mk("b", 10), mk("c", 9999)):
        repo.upsert_alert(a, enrich(a), "test")
    summary = tr.build_and_store(repo, "synthetic", tr.TriageConfig())
    assert summary["incidents"] == 2 and summary["alerts"] == 3
    assert summary["size_distribution"] == {"1": 1, "2": 1}
    stored = repo.list_incidents("synthetic")
    assert sorted(len(i["alert_ids"]) for i in stored) == [1, 2]
    assert all(i["detail"]["timeline"] for i in stored)


def test_api_build_route_rbac_and_audit(client: TestClient, services: Services) -> None:  # noqa: F811
    denied = client.post("/incidents/build", headers=token(client, Role.EXECUTIVE),
                         json={"scenario": "synthetic"})
    assert denied.status_code == 403
    assert services.repo.audit_entries()[0]["action"] == "denied"
    r = client.post("/incidents/build", headers=token(client, Role.ANALYST),
                    json={"scenario": "synthetic", "gap_seconds": 300})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["incidents"] >= 1 and "event_label" not in r.text and "time_label" not in r.text
    entry = services.repo.audit_entries()[0]
    assert entry["action"] == "incident.build" and entry["target"] == "synthetic"
    listed = client.get("/incidents?scenario=synthetic", headers=token(client, Role.ANALYST)).json()
    assert len(listed["incidents"]) == body["incidents"]
    bad = client.post("/incidents/build", headers=token(client, Role.ANALYST),
                      json={"scenario": "synthetic", "gap_seconds": 0})
    assert bad.status_code == 422


def test_triage_cli_and_descriptive_check(tmp_path: Path, processed: Path,  # noqa: F811
                                          samples_dir: Path, monkeypatch: pytest.MonkeyPatch,
                                          capsys: pytest.CaptureFixture[str]) -> None:
    from app.main import main
    from app.platform.bootstrap import ingest_scenario, open_stores
    from app.study.config import load_study_config
    from tests.test_cases import synthetic_config
    for var in ("SENTINEL_DB_URL", "SENTINEL_SEARCH_URL", "SENTINEL_KAFKA"):
        monkeypatch.delenv(var, raising=False)
    cfg = synthetic_config(tmp_path)
    platform = tmp_path / "platform"
    ingest_scenario(open_stores(platform), processed, "synthetic", load_study_config(cfg))
    labels = samples_dir / "synthetic_ait_ads" / "synthetic_labels.csv"
    args = ["triage", "--scenario", "synthetic", "--labels", str(labels), "--study-config", str(cfg),
            "--data-dir", str(platform), "--output-dir", str(tmp_path / "tri")]
    assert main(args) == 0
    out = capsys.readouterr().out
    assert "descriptive dev check" in out and "not a paper result" in out
    report = (tmp_path / "tri" / "synthetic.triage.json").read_text(encoding="utf-8")
    assert '"phases_overlapped"' in report
    assert main(["triage", "--scenario", "wilson", "--study-config", str(cfg)]) == 2
