"""Per-case tool layer: opaque ids, relative times, masking and the label-leak checks.

Synthetic pool (tests/test_variants.py): w1 @1699999200, w5 @1700000050,
s2 @1700000100, a2 @1700000120.25, s4 @1700000150. Ground truth uses the
phases dnsteal / network_scans / dirb and the event labels service_scan,
dirb, escalated_sudo_command.
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.agent.tools import TIME_MASK, TOOL_NAMES, CaseToolkit, mask_times
from app.ingestion.ground_truth import AttackTimeline
from app.schemas.alert import Alert
from app.study.cases import build_cases, variant_case_views
from app.study.config import load_study_config
from app.study.variants import AlertPool, build_variants, experiment_variants
from tests.test_variants import S2, W1, aminer_id, pool, processed  # noqa: F401  (fixtures)

WINDOW_START = datetime.fromtimestamp(1700000100, tz=timezone.utc)
REPO = Path(__file__).resolve().parents[2]


def alerts(pool: AlertPool) -> list[Alert]:  # noqa: F811
    return list(pool.alerts(build_variants(pool, seed=7, shuffled_references=())["fused"]))


def toolkit(pool: AlertPool, **kwargs: object) -> CaseToolkit:  # noqa: F811
    options: dict[str, object] = {"window_start": WINDOW_START, "window_seconds": 100.0, "id_salt": "s"}
    options.update(kwargs)
    return CaseToolkit(alerts(pool), **options)  # type: ignore[arg-type]


def call(kit: CaseToolkit, name: str, **arguments: object) -> object:
    return json.loads(kit.call(name, arguments))


def every_output(kit: CaseToolkit) -> list[str]:
    """Brief plus every tool on every alert, every list page and a set of searches."""
    outputs = [kit.brief()]
    page = 1
    while True:
        text = kit.call("list_alerts", {"page": page})
        outputs.append(text)
        if not json.loads(text)["has_more"]:
            break
        page += 1
    for opaque in kit.alert_ids:
        outputs.append(kit.call("get_alert", {"alert_id": opaque}))
        outputs.append(kit.call("get_raw_log", {"alert_id": opaque}))
    for text in ("a", "e", "1", "suricata", "sudo", "scan", "2023", "label", "dirb"):
        outputs.append(kit.call("search_alerts", {"text": text}))
    outputs.append(kit.call("list_alerts", {"detector": "wazuh", "min_severity": 1}))
    return outputs


def test_ids_are_opaque_deterministic_and_resolvable(pool: AlertPool) -> None:  # noqa: F811
    kit = toolkit(pool)
    real = {a.alert_id for a in alerts(pool)}
    assert len(kit.alert_ids) == len(real)
    assert not set(kit.alert_ids) & real
    assert all(re.fullmatch(r"al-[0-9a-f]{8,}", i) for i in kit.alert_ids)
    assert {kit.resolve(i) for i in kit.alert_ids} == real
    assert kit.resolve("al-nope") is None
    assert toolkit(pool).alert_ids == kit.alert_ids  # same salt -> same ids
    assert not set(toolkit(pool, id_salt="other").alert_ids) & set(kit.alert_ids)


def test_times_are_offsets_from_the_window_start(pool: AlertPool) -> None:  # noqa: F811
    kit = toolkit(pool)
    by_real = {kit.resolve(i): i for i in kit.alert_ids}
    a2 = call(kit, "get_alert", alert_id=by_real[aminer_id(pool)])
    assert a2["offset_seconds"] == 20.25  # type: ignore[index]
    assert "timestamp" not in a2  # type: ignore[operator]
    raw = a2["raw_alert"]  # type: ignore[index]
    assert raw["LogData"]["Timestamps"] == [20.25] and raw["LogData"]["DetectionTimestamp"] == [20.25]
    w1 = call(kit, "get_alert", alert_id=by_real[W1])
    assert w1["offset_seconds"] == -900.0  # type: ignore[index]  # before the window start
    assert w1["raw_alert"]["@timestamp"] == -900.0  # type: ignore[index]
    assert w1["raw_alert"]["id"] == by_real[W1]  # type: ignore[index]  # the raw id is opaque too


def test_mask_times_keeps_unmasked_text_exact() -> None:
    line = "Nov 14 22:00:00 mail freshclam[100]: Fri Jan 21 00:02:27 2022 -> started"
    assert mask_times(line) == f"{TIME_MASK} mail freshclam[100]: {TIME_MASK} -> started"
    assert mask_times('type=EXECVE msg=audit(1700000120.250:2): argc=2') == (
        f"type=EXECVE msg=audit({TIME_MASK}:2): argc=2")
    assert mask_times('10.0.0.9 - - [14/Nov/2023:22:15:00 +0000] "GET /"') == (
        f'10.0.0.9 - - [{TIME_MASK}] "GET /"')
    assert mask_times("at 2023-11-14T22:15:00.000000+0000 and 11/14/2023-22:15:00.000000") == (
        f"at {TIME_MASK} and {TIME_MASK}")
    # Any substring that avoids the mask is a substring of the original line,
    # so quote claims made from the masked text verify against the real line.
    masked = mask_times(line)
    for part in masked.split(TIME_MASK):
        assert part in line


def test_raw_log_lines_are_masked_quotable(pool: AlertPool) -> None:  # noqa: F811
    kit = toolkit(pool)
    real_lines = {a.alert_id: a.evidence.log_lines for a in alerts(pool)}
    for opaque in kit.alert_ids:
        out = call(kit, "get_raw_log", alert_id=opaque)
        assert set(out) == {"alert_id", "log_lines", "log_paths", "log_offsets_seconds"}  # type: ignore[arg-type]
        for masked, real in zip(out["log_lines"], real_lines[kit.resolve(opaque)]):  # type: ignore[index]
            assert all(part in real for part in masked.split(TIME_MASK))


def test_list_filter_search_and_paging(pool: AlertPool) -> None:  # noqa: F811
    kit = toolkit(pool, page_size=2)
    first = call(kit, "list_alerts")
    assert first["total"] == 5 and len(first["alerts"]) == 2 and first["has_more"]  # type: ignore[index]
    assert [r["offset_seconds"] for r in first["alerts"]] == [-900.0, -50.0]  # type: ignore[index]  # time order
    assert set(first["alerts"][0]) == {"alert_id", "offset_seconds", "detector", "rule_id",  # type: ignore[index]
                                       "rule_name", "severity", "host_ip"}
    assert call(kit, "list_alerts", page=3)["alerts"][0]["detector"] == "suricata"  # type: ignore[index]
    wazuh = call(kit, "list_alerts", detector="wazuh")
    assert wazuh["total"] == 2  # type: ignore[index]
    window = call(kit, "list_alerts", offset_min=0, offset_max=30)
    assert window["total"] == 2  # type: ignore[index]  # s2 @0, a2 @20.25
    hits = call(kit, "search_alerts", text="SUDO")
    assert [kit.resolve(r["alert_id"]) for r in hits["alerts"]] == [aminer_id(pool)]  # type: ignore[index]
    by_field = call(kit, "search_alerts", text="ET SCAN", field="rule_name")
    assert by_field["total"] >= 1  # type: ignore[index]
    assert call(kit, "search_alerts", text="ET SCAN", field="raw_alert.nope")["total"] == 0  # type: ignore[index]


def test_tool_errors_are_reported_not_raised(pool: AlertPool) -> None:  # noqa: F811
    kit = toolkit(pool)
    assert "unknown alert id" in call(kit, "get_alert", alert_id=S2)["error"]  # type: ignore[index]  # real id refused
    assert "unknown tool" in call(kit, "drop_table")["error"]  # type: ignore[index]
    assert "unexpected" in call(kit, "list_alerts", colour="red")["error"]  # type: ignore[index]
    assert "text" in call(kit, "search_alerts")["error"]  # type: ignore[index]
    assert "page" in call(kit, "list_alerts", page=0)["error"]  # type: ignore[index]
    assert set(TOOL_NAMES) == {"list_alerts", "get_alert", "search_alerts", "get_raw_log"}


def test_long_outputs_are_truncated(pool: AlertPool) -> None:  # noqa: F811
    kit = toolkit(pool, max_output_chars=200)
    text = kit.call("get_alert", {"alert_id": kit.alert_ids[0]})
    assert len(text) <= 200 + 60 and text.endswith("[output truncated at 200 characters]")


def forbidden_tokens(pool: AlertPool) -> set[str]:  # noqa: F811
    truth = [json.loads(line) for line in pool.ground_truth_path.read_text("utf-8").splitlines()]
    tokens = {"time_label", "event_label", "ground_truth", "false_positive", "event_label_source",
              "phase", "variant", "oracle", "fused", "noise-", "shuffled", "synthetic:attack",
              "synthetic:benign", "synthetic-ait-ads-format", "training_mode", "source_file"}
    tokens |= {t["time_label"] for t in truth} | {t["event_label"] for t in truth if t["event_label"]}
    tokens |= {"dnsteal", "network_scans", "dirb", "service_scan", "escalated_sudo_command"}
    return tokens


def test_no_tool_output_leaks_labels_truth_phases_variants_ids_or_times(pool: AlertPool) -> None:  # noqa: F811
    kit = toolkit(pool)
    outputs = every_output(kit)
    real_ids = {a.alert_id for a in alerts(pool)}
    for text in outputs:
        lower = text.lower()
        for token in forbidden_tokens(pool):
            assert token.lower() not in lower, f"leaked {token!r} in {text[:120]}"
        for value in re.findall(r'"([^"]*)"', text):  # no string equal to a real alert id
            assert value not in real_ids, f"real alert id {value!r} leaked"
        assert not re.search(r"\b1[0-9]{9}\b", text), f"epoch time leaked in {text[:120]}"
        assert not re.search(r"20[0-9]{2}-[01][0-9]-[0-3][0-9]", text), f"ISO date leaked in {text[:120]}"
        assert "nov 14" not in lower and "14/nov" not in lower


@pytest.mark.skipif(not (REPO / "data" / "processed" / "russellmitchell.alerts.jsonl").exists()
                    or not (REPO / "data" / "raw" / "ait_ads" / "labels.csv").exists(),
                    reason="real russellmitchell files not present")
def test_real_dev_cases_do_not_leak() -> None:
    """Real dev scenario: phase names and event labels may appear only where the raw record has them."""
    config = load_study_config()
    real_pool = AlertPool.from_processed(REPO / "data" / "processed", "russellmitchell")
    timeline = AttackTimeline.from_labels_csv(REPO / "data" / "raw" / "ait_ads" / "labels.csv",
                                              "russellmitchell")
    case_set = build_cases(real_pool, timeline, config.cases)
    views = variant_case_views(case_set, experiment_variants(real_pool, config), real_pool,
                               config.cases)["fused"]
    truth = [json.loads(line) for line in real_pool.ground_truth_path.read_text("utf-8").splitlines()]
    words = ({t["time_label"] for t in truth} | {t["event_label"] for t in truth if t["event_label"]}) - {
        "false_positive"}
    for case, view in list(zip(case_set.cases, views))[:4] + list(zip(case_set.cases, views))[10:12]:
        case_alerts = [real_pool.alert(e) for e in view.entries]
        if not case_alerts:
            continue
        kit = CaseToolkit(case_alerts, window_start=case.window_start,
                          window_seconds=(case.window_end - case.window_start).total_seconds(),
                          id_salt=case.case_id)
        raw_text = " ".join(json.dumps(a.model_dump(mode="json")) for a in case_alerts).lower()
        real_ids = {a.alert_id for a in case_alerts}
        date = case.window_start.strftime("%Y-%m-%d")
        for text in every_output(kit):
            lower = text.lower()
            for key in ("time_label", "event_label", "ground_truth", "false_positive", case.case_id.lower()):
                assert key not in lower
            for word in words:
                if word.lower() in lower:
                    assert word.lower() in raw_text, f"{word!r} not from the record: {text[:160]}"
            assert date not in text
            for value in re.findall(r'"([^"]*)"', text):
                assert value not in real_ids
