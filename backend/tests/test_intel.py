"""Wave B1: ATT&CK knowledge base and deterministic alert mapping; IOC store and matcher."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from app.intel.attack import DEFAULT_STIX, RULE_TABLE, AttackKB, map_alert
from app.intel.ioc import FEEDS, Indicator, IocStore
from app.platform.enrichment import enrich
from app.schemas.alert import Alert, AlertEvidence, Detector, DetectorType

T0 = datetime(2022, 1, 21, tzinfo=timezone.utc)


def alert(detector: Detector, raw: dict[str, Any], lines: list[str] | None = None,
          host_ip: str | None = "10.0.0.5") -> Alert:
    types = {Detector.WAZUH: DetectorType.RULE_BASED, Detector.SIGMA: DetectorType.RULE_BASED,
             Detector.SURICATA: DetectorType.SIGNATURE_BASED,
             Detector.AMINER: DetectorType.ANOMALY_BASED}
    return Alert(alert_id=f"a-{len(str(raw))}", scenario="synthetic", detector=detector,
                 detector_type=types[detector], timestamp=T0, rule_id="1", host_ip=host_ip,
                 evidence=AlertEvidence(log_lines=lines or []), raw_alert=raw,
                 source_file="synthetic.json", source_line=1)


@pytest.fixture()
def kb(samples_dir: Path) -> AttackKB:
    return AttackKB.from_stix(samples_dir / "synthetic_attack_stix.json")


def test_kb_loads_and_skips_revoked_and_deprecated(kb: AttackKB) -> None:
    assert kb.version == "synthetic-1"
    assert set(kb.techniques) == {"T1110", "T1110.001", "T1190"}
    assert kb.tactics == {"credential-access": "Credential Access", "initial-access": "Initial Access"}
    assert kb.get("T1110.001").is_subtechnique  # type: ignore[union-attr]
    assert kb.parent("T1110.001").name == "Brute Force"  # type: ignore[union-attr]
    assert "Monitor authentication" in kb.get("T1110").text()  # type: ignore[union-attr]
    assert "G9999" in kb.groups and kb.sha256 and len(kb.sha256) == 64


def test_mapping_native_then_rule_table_never_guesses(kb: AttackKB) -> None:
    wazuh = alert(Detector.WAZUH, {"rule": {"mitre": {"id": ["T1110.001", "T4242"]}}})
    assert [(m["technique_id"], m["source"], m["known"]) for m in map_alert(wazuh, kb)] == [
        ("T1110.001", "native", True), ("T4242", "native", False)]
    suri = alert(Detector.SURICATA, {"data": {"alert": {"category": "Web Application Attack"}}})
    assert map_alert(suri, kb)[0] == {"technique_id": "T1190", "name": "Exploit Public-Facing Application",
                                      "tactics": ["initial-access"], "source": "rule_table", "known": True}
    other = alert(Detector.SURICATA, {"data": {"alert": {"category": "Generic Protocol Command Decode"}}})
    assert map_alert(other, kb) == []
    aminer = alert(Detector.AMINER, {"AnalysisComponent": {"AnalysisComponentType": "NewMatchPathDetector"}})
    assert map_alert(aminer, kb) == []
    assert map_alert(alert(Detector.WAZUH, {"rule": {"mitre": "bad"}}), kb) == []
    assert map_alert(wazuh)[0]["known"] is None  # no KB loaded: unknown, not False
    assert all(len(ids) == 1 for ids in RULE_TABLE.values())


@pytest.mark.skipif(not DEFAULT_STIX.exists(), reason="real ATT&CK bundle not in data/raw/mitre")
def test_real_attack_bundle_has_the_dev_native_ids() -> None:
    kb = AttackKB.from_stix()
    # ids Wazuh attaches in the dev scenarios (descriptive check of the local bundle)
    for tid in ("T1078", "T1595.002", "T1110.001", "T1110", "T1055", "T1021.004", "T1548.003", "T1190"):
        assert kb.get(tid) is not None, tid
    assert len(kb.techniques) > 500


def test_ioc_store_matches_exact_ip_domain_hash_and_subdomain() -> None:
    store = IocStore([Indicator("ip", "203.0.113.66", "local"), Indicator("domain", "Evil.Example", "local"),
                      Indicator("sha256", "A" * 64, "local")])
    assert len(store) == 3
    a = alert(Detector.SURICATA,
              {"data": {"src_ip": "203.0.113.66", "dest_ip": "10.0.0.5",
                        "http": {"hostname": "cdn.evil.example", "url": "/x"}}},
              lines=["GET from 203.0.113.66 file " + "a" * 64, "nothing.example here"])
    hits = store.match_alert(a, enrich(a))
    assert {(h["type"], h["indicator"]) for h in hits} == {
        ("ip", "203.0.113.66"), ("domain", "evil.example"), ("sha256", "a" * 64)}
    assert {h["where"] for h in hits if h["type"] == "ip"} == {"network.src"}
    clean = alert(Detector.WAZUH, {}, lines=["login from 10.1.1.1 ok"])
    assert store.match_alert(clean, enrich(clean)) == []
    with pytest.raises(ValueError):
        Indicator.normalize("cve", "x")


def test_ioc_store_load_json(tmp_path: Path) -> None:
    path = tmp_path / "iocs.json"
    path.write_text('{"indicators": [{"type": "ip", "value": "198.51.100.7", "source": "s"}]}', encoding="utf-8")
    assert len(IocStore.load(path)) == 1


def test_feed_adapters_are_disabled_with_a_labelled_synthetic_sample() -> None:
    for feed_cls in FEEDS:
        feed = feed_cls()
        assert feed.enabled is False
        with pytest.raises(RuntimeError, match="disabled"):
            feed.fetch()
        sample = feed.offline_sample()
        assert sample and all("SYNTHETIC" in i.description and "offline-sample" in i.source for i in sample)


def test_sigma_tags_are_native_technique_ids(kb: AttackKB) -> None:
    sig = alert(Detector.SIGMA, {"sigma": {"tags": ["attack.initial-access", "attack.t1190",
                                                    "attack.t1110.001", "cve.2021-1234"]}})
    assert [(m["technique_id"], m["source"]) for m in map_alert(sig, kb)] == [
        ("T1190", "native"), ("T1110.001", "native")]
    assert map_alert(alert(Detector.SIGMA, {"sigma": {"tags": "attack.t1190"}}), kb) == []
