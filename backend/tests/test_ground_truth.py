from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.ingestion.ground_truth import (
    AttackTimeline,
    EventLabelLinker,
    LinkStatus,
    csv_link_key,
    iter_event_label_rows,
)
from app.ingestion.records import IngestionError
from tests.conftest import write
from tests.test_alert_normalizer import AMINER, EVE, WAZUH, ok
from app.ingestion.mappings import AitAdsFile

HEADER = "scenario,attack,start,end\n"


def utc(seconds: float) -> datetime:
    return datetime.fromtimestamp(seconds, tz=timezone.utc)


def timeline(tmp_path: Path, body: str, scenario: str = "s1") -> AttackTimeline:
    return AttackTimeline.from_labels_csv(write(tmp_path / "labels.csv", HEADER + body), scenario)


def test_unordered_rows_are_sorted_and_filtered(tmp_path: Path) -> None:
    tl = timeline(tmp_path, "s1,b,200,300\ns2,x,0,1000\ns1,a,100,200\ns1,c,50,60\n")
    assert [i.attack for i in tl.intervals] == ["c", "a", "b"]
    assert tl.label_at(utc(55)) == "c"
    assert tl.label_at(utc(150)) == "a"
    assert tl.label_at(utc(10)) == "false_positive"
    assert tl.label_at(utc(300)) == "false_positive"


def test_intervals_are_half_open(tmp_path: Path) -> None:
    tl = timeline(tmp_path, "s1,b,200,300\ns1,a,100,200\n")
    assert tl.label_at(utc(100)) == "a"
    assert tl.label_at(utc(200)) == "b"  # the boundary belongs to the later phase
    assert tl.label_at(utc(199.999999)) == "a"


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("s1,a,100,250\ns1,b,200,300\n", "overlap"),
        ("s1,a,300,200\n", "end before start"),
        ("s1,a,abc,200\n", "start"),
        ("s1,a,nan,200\n", "start"),
        ("s2,a,100,200\n", "no attack intervals"),
        ("s1,,100,200\n", "attack"),
    ],
)
def test_bad_labels_raise(tmp_path: Path, body: str, message: str) -> None:
    with pytest.raises(IngestionError, match=message):
        timeline(tmp_path, body)


def test_wrong_label_header_raises(tmp_path: Path) -> None:
    with pytest.raises(IngestionError, match="columns"):
        AttackTimeline.from_labels_csv(write(tmp_path / "l.csv", "scenario,phase,from,to\ns1,a,1,2\n"), "s1")


def test_event_label_rows_split_from_both_ends(tmp_path: Path) -> None:
    path = write(tmp_path / "x_alerts.txt",
                 "time,name,ip,host,short,time_label,event_label\n"
                 "1700000050,Wazuh: Web server 400 error code, synthetic.,10.0.0.1,web,W-Acc,dirb,-\n"
                 "1700000051,AMiner: x,10.0.0.2,web,A-X,false_positive,dirb\n")
    rows = list(iter_event_label_rows(path))
    assert [(r.position, r.time, r.name, r.ip, r.time_label, r.event_label) for r in rows] == [
        (2, 1700000050, "Wazuh: Web server 400 error code, synthetic.", "10.0.0.1", "dirb", None),
        (3, 1700000051, "AMiner: x", "10.0.0.2", "false_positive", "dirb"),
    ]


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("time,name,ip\n1,a,b\n", "header"),
        ("time,name,ip,host,short,time_label,event_label\n1,a,b\n", "fields"),
        ("time,name,ip,host,short,time_label,event_label\nabc,a,b,c,d,e,f\n", "time"),
    ],
)
def test_bad_event_label_files_raise(tmp_path: Path, text: str, message: str) -> None:
    with pytest.raises(IngestionError, match=message):
        list(iter_event_label_rows(write(tmp_path / "x_alerts.txt", text)))


def test_csv_link_keys() -> None:
    assert csv_link_key(ok(WAZUH, AitAdsFile.WAZUH)) == (1699999200, "Wazuh: ClamAV database update", "10.0.0.5")
    assert csv_link_key(ok(EVE, AitAdsFile.WAZUH)) == (
        1700000100, "Suricata: Alert - ET SCAN synthetic signature", "10.0.0.9")
    assert csv_link_key(ok(AMINER, AitAdsFile.AMINER)) == (
        1700000120, "AMiner: New value in Audit logs.", "10.0.0.7")


def label_file(tmp_path: Path, *rows: str) -> Path:
    return write(tmp_path / "s_alerts.txt", "time,name,ip,host,short,time_label,event_label\n"
                 + "".join(r + "\n" for r in rows))


def test_linker_links_positionally_and_stops_at_first_mismatch(tmp_path: Path) -> None:
    path = label_file(tmp_path,
                      "1699999200,Wazuh: ClamAV database update,10.0.0.5,mail,W,false_positive,-",
                      "1,skipped for a rejected record,10.0.0.1,h,W,false_positive,-",
                      "1699999200,Wazuh: something else,10.0.0.5,mail,W,false_positive,dirb",
                      "1699999200,Wazuh: ClamAV database update,10.0.0.5,mail,W,false_positive,dirb")
    linker = EventLabelLinker(iter_event_label_rows(path))
    alert = ok(WAZUH, AitAdsFile.WAZUH)
    first = linker.link(alert)
    assert first is not None and first.event_label is None
    assert linker.link(None) is None  # a rejected record still consumes its row
    assert linker.link(alert) is None
    assert linker.status is LinkStatus.MISMATCH and linker.mismatch_position == 4
    assert linker.link(alert) is None  # never resumes after a mismatch
    assert linker.rows_consumed == 3


def test_linker_reports_exhaustion_and_leftovers(tmp_path: Path) -> None:
    path = label_file(tmp_path, "1699999200,Wazuh: ClamAV database update,10.0.0.5,mail,W,false_positive,-")
    linker = EventLabelLinker(iter_event_label_rows(path))
    alert = ok(WAZUH, AitAdsFile.WAZUH)
    assert linker.link(alert) is not None
    assert linker.link(alert) is None and linker.status is LinkStatus.EXHAUSTED

    path = label_file(tmp_path, "1699999200,Wazuh: ClamAV database update,10.0.0.5,mail,W,false_positive,-",
                      "1,extra,10.0.0.1,h,W,false_positive,-")
    linker = EventLabelLinker(iter_event_label_rows(path))
    assert linker.link(alert) is not None
    assert linker.finish() == 1 and linker.status is LinkStatus.LEFTOVER_ROWS
