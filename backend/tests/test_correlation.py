"""C6 (2026-11-15): every incident says why its alerts are together. Grouping is unchanged;
the rationale describes the links the union-find used. SYNTHETIC alerts only."""

from __future__ import annotations

from app.detection import triage as tr
from app.schemas.alert import Detector
from tests.test_triage import mk


def corr(alerts: list, **cfg: object) -> list[dict]:  # type: ignore[type-arg]
    incs = tr.build_incidents(alerts, "synthetic", tr.TriageConfig(**cfg))  # type: ignore[arg-type]
    return [i["detail"]["correlation"] for i in sorted(incs, key=lambda i: i["first_ts"])]


def test_single_alert_has_no_links() -> None:
    (c,) = corr([mk("a", 0)])
    assert c["strength"] == "single alert" and c["links"] == 0 and c["linked_by"] == {}
    assert "not a calibrated probability" in c["confidence_note"]


def test_shared_source_ip_and_host_is_strong() -> None:
    raw = {"data": {"srcip": "192.168.1.9"}}
    (c,) = corr([mk("a", 0, raw=raw), mk("b", 30, raw=raw), mk("c", 90, raw=raw)])
    assert c["strength"] == "strong"
    assert c["linked_by"] == {"host": 2, "ip": 2}
    assert c["shared_indicators"] == [{"entity": "host:10.0.0.5", "alerts": 3},
                                      {"entity": "ip:192.168.1.9", "alerts": 3}]
    assert c["max_link_gap_seconds"] == 60.0 and c["gap_limit_seconds"] == 300
    assert "share source IP 192.168.1.9" in c["reason"]


def test_host_only_links_with_different_sources_are_weak() -> None:
    # same target host, two different attacker IPs: grouped by the host alone
    (c,) = corr([mk("a", 0, raw={"data": {"srcip": "192.168.1.9"}}),
                 mk("b", 10, raw={"data": {"srcip": "192.168.7.7"}})])
    assert c["strength"] == "weak" and c["linked_by"] == {"host": 1}
    assert c["source_ips"] == ["192.168.1.9", "192.168.7.7"]
    assert "only through host 10.0.0.5" in c["reason"] and "2 different source IPs" in c["reason"]


def test_host_only_without_source_ip_is_moderate_and_says_so() -> None:
    (c,) = corr([mk("a", 0), mk("b", 10)])
    assert c["strength"] == "moderate" and c["source_ips"] == []
    assert "no source IP recorded" in c["reason"]


def test_unrelated_and_missing_fields_stay_apart() -> None:
    cs = corr([mk("a", 0, host="10.0.0.5"), mk("b", 1, host="10.0.0.6"), mk("c", 2, host=None)])
    assert [c["strength"] for c in cs] == ["single alert", "single alert", "single alert"]
    assert cs[2]["reason"].startswith("No host or source IP")


def test_time_boundary_is_reported_with_the_gap() -> None:
    (c,) = corr([mk("a", 0), mk("b", 300)])
    assert c["max_link_gap_seconds"] == 300.0 and c["links"] == 1
    assert len(corr([mk("a", 0), mk("b", 300.5)])) == 2


def test_cross_detector_link_is_named() -> None:
    w = mk("w", 0, host="10.0.0.5", raw={"data": {"srcip": "192.168.1.9"}})
    s = mk("s", 60, detector=Detector.SURICATA, host="10.0.0.99", severity=2,
           raw={"data": {"src_ip": "192.168.1.9", "dest_ip": "10.0.0.5"}})
    (c,) = corr([w, s])
    assert c["linked_by"] == {"ip": 1} and c["cross_detector_links"] == 1
    assert c["strength"] == "strong"


def test_span_cut_segments_say_they_are_segments() -> None:
    raw = {"data": {"srcip": "192.168.1.9"}}
    cs = corr([mk(f"a{i}", i * 200, raw=raw) for i in range(5)], max_span_seconds=500)
    assert len(cs) >= 2 and all("segment" in c["reason"] for c in cs)
