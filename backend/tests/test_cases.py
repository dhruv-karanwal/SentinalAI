"""Case builder, truncation and ceiling report on the synthetic sample.

Attack intervals (synthetic_labels.csv): dnsteal [1699990000, 1699990060),
network_scans [1700000000, 1700000100), dirb [1700000100, 1700000200).
Investigation pool (time order): w1 @1699999200 (benign), w5 @1700000050,
s2 @1700000100, a2 @1700000120.25, s4 @1700000150. The pool's time range
[1699999200, 1700000150] leaves [1699999200, 1700000000) for benign windows.
"""

import dataclasses
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.ingestion.ground_truth import AttackTimeline
from app.main import main
from app.study.cases import (
    CaseKind,
    build_cases,
    case_alerts,
    dev_case_report,
    noise_case_alerts,
    reachable_phases,
)
from app.study.config import DEFAULT_STUDY_CONFIG, CaseConfig, load_study_config
from app.study.variants import AlertPool, build_variants
from tests.test_variants import S2, S4, W1, W5, aminer_id, pool, processed  # noqa: F401  (fixtures)

SEED = 7
CONFIG = CaseConfig(seed=SEED, padding_seconds=0, max_alerts=100, truncation="earliest",
                    benign_per_attack=1)


@pytest.fixture
def timeline(samples_dir: Path) -> AttackTimeline:
    return AttackTimeline.from_labels_csv(
        samples_dir / "synthetic_ait_ads" / "synthetic_labels.csv", "synthetic")


def ts(seconds: float) -> datetime:
    return datetime.fromtimestamp(seconds, tz=timezone.utc)


def test_attack_cases_follow_labels(pool: AlertPool, timeline: AttackTimeline) -> None:
    cases = build_cases(pool, timeline, CONFIG)
    attack = [c for c in cases.cases if c.kind is CaseKind.ATTACK]
    assert [c.case_id for c in attack] == [
        "synthetic:attack:dnsteal", "synthetic:attack:network_scans", "synthetic:attack:dirb"]
    assert (attack[1].start, attack[1].end) == (ts(1700000000), ts(1700000100))
    assert (attack[1].window_start, attack[1].window_end) == (attack[1].start, attack[1].end)


def test_benign_windows_are_matched_disjoint_and_seeded(pool: AlertPool, timeline: AttackTimeline) -> None:
    cases = build_cases(pool, timeline, CONFIG)
    benign = [c for c in cases.cases if c.kind is CaseKind.BENIGN]
    assert [c.case_id for c in benign] == [
        "synthetic:benign:dnsteal:1", "synthetic:benign:network_scans:1", "synthetic:benign:dirb:1"]
    durations = {c.phase: c.end - c.start for c in cases.cases if c.kind is CaseKind.ATTACK}
    for case in benign:
        assert case.end - case.start == durations[case.phase]  # equal length
        assert ts(1699999200) <= case.window_start and case.window_end <= ts(1700000000)
        for interval in timeline.intervals:  # outside every attack interval
            assert case.window_end <= interval.start or case.window_start >= interval.end
    spans = sorted((c.window_start, c.window_end) for c in benign)
    assert all(a[1] <= b[0] for a, b in zip(spans, spans[1:]))  # mutually disjoint
    log = cases.benign_sampling
    assert log["seed"] == SEED and isinstance(log["derived_seed"], int)
    assert log["unavailable"] == [] and log["free_seconds"] == 800
    again = build_cases(pool, timeline, CONFIG)
    assert again.cases == cases.cases
    starts = {tuple(c.start for c in build_cases(pool, timeline, dataclasses.replace(CONFIG, seed=s)).cases
                    if c.kind is CaseKind.BENIGN) for s in range(10)}
    assert len(starts) > 1


def test_no_room_for_benign_windows_is_logged(pool: AlertPool, timeline: AttackTimeline) -> None:
    cases = build_cases(pool, timeline, dataclasses.replace(CONFIG, benign_per_attack=9))
    log = cases.benign_sampling
    assert log["unavailable"]  # 27 windows of 60-100 s cannot fit in 800 s
    assert len([c for c in cases.cases if c.kind is CaseKind.BENIGN]) + len(log["unavailable"]) == 27


def by_id(pool: AlertPool, timeline: AttackTimeline, config: CaseConfig = CONFIG) -> dict[str, object]:
    return {c.case_id: c for c in build_cases(pool, timeline, config).cases}


def test_case_alerts_window_and_cap(pool: AlertPool, timeline: AttackTimeline) -> None:
    fused = build_variants(pool, seed=SEED, shuffled_references=())["fused"]
    dirb = by_id(pool, timeline)["synthetic:attack:dirb"]
    full = case_alerts(dirb, fused, max_alerts=100, truncation="earliest")  # type: ignore[arg-type]
    a2 = aminer_id(pool)
    assert [e.alert_id for e in full.entries] == [S2, a2, S4]
    assert (full.in_window, full.dropped, full.in_phase_before_cap,
            full.in_phase_event_attack_before_cap) == (3, 0, 3, 2)
    capped = case_alerts(dirb, fused, max_alerts=1, truncation="earliest")  # type: ignore[arg-type]
    assert [e.alert_id for e in capped.entries] == [S2]
    assert (capped.dropped, capped.dropped_event_attack, capped.dropped_time_attack) == (2, 1, 2)
    assert "earliest" in capped.truncation_rule
    with pytest.raises(ValueError, match="truncation"):
        case_alerts(dirb, fused, max_alerts=1, truncation="random")  # type: ignore[arg-type]


def test_spread_truncation_keeps_evenly_spaced_time_ranks(pool: AlertPool, timeline: AttackTimeline) -> None:
    fused = build_variants(pool, seed=SEED, shuffled_references=())["fused"]
    dirb = by_id(pool, timeline)["synthetic:attack:dirb"]  # fused alerts: s2, a2, s4
    two = case_alerts(dirb, fused, max_alerts=2, truncation="spread")  # type: ignore[arg-type]
    assert [e.alert_id for e in two.entries] == [S2, S4]  # ranks floor((i + 0.5) * 3 / 2) = 0, 2
    one = case_alerts(dirb, fused, max_alerts=1, truncation="spread")  # type: ignore[arg-type]
    assert [e.alert_id for e in one.entries] == [aminer_id(pool)]  # rank 1, the middle
    assert (one.dropped, one.dropped_event_attack, one.dropped_time_attack) == (2, 1, 2)
    assert one.truncation_rule.startswith("spread")
    untouched = case_alerts(dirb, fused, max_alerts=5, truncation="spread")  # type: ignore[arg-type]
    assert untouched.dropped == 0 and len(untouched.entries) == 3


def benign_entries(pool: AlertPool) -> list[object]:
    return [e for e in pool.entries if e.event_attack is False]


def test_noise_case_alerts_same_window_first(pool: AlertPool, timeline: AttackTimeline) -> None:
    dirb = by_id(pool, timeline)["synthetic:attack:dirb"]
    # Suricata has 2 alerts in dirb; the window holds one event-benign alert (s4),
    # the other comes from the scenario pool outside the window (w1).
    view = noise_case_alerts(dirb, benign_entries(pool), 2, seed=SEED,  # type: ignore[arg-type]
                             name="noise-suricata", max_alerts=100, truncation="spread")
    assert [e.alert_id for e in view.entries] == [W1, S4]
    assert view.noise == {"reference_count": 2, "from_window": 1, "from_fallback": 1, "shortfall": 0}
    assert all(e.event_attack is False for e in view.entries)
    short = noise_case_alerts(dirb, benign_entries(pool), 5, seed=SEED,  # type: ignore[arg-type]
                              name="noise-x", max_alerts=100, truncation="spread")
    assert short.noise == {"reference_count": 5, "from_window": 1, "from_fallback": 1, "shortfall": 3}
    empty = noise_case_alerts(dirb, benign_entries(pool), 0, seed=SEED,  # type: ignore[arg-type]
                              name="noise-x", max_alerts=100, truncation="spread")
    assert empty.entries == () and empty.noise["reference_count"] == 0  # type: ignore[index]


def test_reachable_phases(pool: AlertPool, timeline: AttackTimeline) -> None:
    cases = build_cases(pool, timeline, CONFIG)
    reachable, unreachable = reachable_phases(cases, pool)
    assert reachable == ("network_scans", "dirb") and unreachable == ("dnsteal",)


def test_padding_widens_the_window(pool: AlertPool, timeline: AttackTimeline) -> None:
    padded = by_id(pool, timeline, dataclasses.replace(CONFIG, padding_seconds=50))
    case = padded["synthetic:attack:network_scans"]
    assert (case.window_start, case.window_end) == (ts(1699999950), ts(1700000150))  # type: ignore[attr-defined]
    fused = build_variants(pool, seed=SEED, shuffled_references=())["fused"]
    view = case_alerts(case, fused, max_alerts=100, truncation="earliest")  # type: ignore[arg-type]
    assert [e.alert_id for e in view.entries] == [W5, S2, aminer_id(pool)]  # s4 @150 is outside [.., 150)
    assert view.in_phase_before_cap == 1  # only w5 lies inside network_scans itself


def synthetic_config(tmp_path: Path, **cases: object) -> Path:
    data = json.loads(DEFAULT_STUDY_CONFIG.read_text(encoding="utf-8"))
    data["split"]["dev"] = ["synthetic"]
    data["pilot"]["scenarios"] = ["synthetic"]
    data["variants"]["shuffled_reference"] = ["aminer"]
    data["baselines"]["top_k"] = 1
    data["cases"].update(cases)
    path = tmp_path / "study.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_dev_case_report(processed: Path, samples_dir: Path, tmp_path: Path) -> None:  # noqa: F811
    labels = samples_dir / "synthetic_ait_ads" / "synthetic_labels.csv"
    config = load_study_config(synthetic_config(tmp_path))
    report = dev_case_report(processed, labels, "synthetic", config, output_dir=tmp_path / "out")
    assert report["scenario_split"] == "dev" and "CEILING" in report["note"]
    assert report["cases"] == {"attack": 3, "benign": 3}
    assert list(report["variants"]) == [
        "wazuh", "suricata", "aminer", "fused", "oracle", "shuffled-aminer",
        "noise-wazuh", "noise-suricata", "noise-aminer"]
    assert report["phases"] == {"all": ["dnsteal", "network_scans", "dirb"],
                                "reachable": ["network_scans", "dirb"], "unreachable": ["dnsteal"],
                                "rule": report["phases"]["rule"]}
    fused, wazuh = report["variants"]["fused"], report["variants"]["wazuh"]
    assert fused["coverage_ceiling"]["time_label"] == {"covered": 2, "cases": 3, "rate": 2 / 3}
    assert fused["coverage_ceiling"]["event_label"] == {"covered": 2, "cases": 3, "rate": 2 / 3}
    assert fused["mean_alerts_per_case"]["attack"] == pytest.approx(4 / 3)
    assert wazuh["coverage_ceiling"]["time_label"]["covered"] == 1
    assert report["variants"]["oracle"]["coverage_ceiling"]["event_label"]["covered"] == 2
    assert fused["truncation"] == {"cases_truncated": 0, "alerts_dropped": 0,
                                   "cases_cap_dropped_event_attack": 0, "cases_cap_dropped_time_attack": 0}
    out = tmp_path / "out" / "synthetic"
    manifest = json.loads((out / "synthetic.cases.json").read_text("utf-8"))
    dirb = next(c for c in manifest["cases"] if c["case_id"] == "synthetic:attack:dirb")
    assert dirb["variants"]["fused"]["alert_ids"] == [S2, aminer_id(AlertPool.from_processed(processed, "synthetic")), S4]
    assert dirb["variants"]["fused"]["truncation_rule"].startswith("spread")
    assert dirb["variants"]["noise-suricata"]["alert_ids"] == [W1, S4]
    assert dirb["variants"]["noise-suricata"]["noise"]["from_fallback"] == 1
    assert dirb["start_time_of_day_utc"] == "22:15:00" and dirb["end_time_of_day_utc"] == "22:16:40"
    benign = next(c for c in manifest["cases"] if c["kind"] == "benign")
    assert len(benign["start_time_of_day_utc"]) == 8
    noise = report["variants"]["noise-suricata"]["noise"]
    assert noise["from_fallback"] >= 1 and noise["shortfall"] == 0
    assert json.loads((out / "synthetic.case_ceilings.json").read_text("utf-8")) == report

    baselines = report["baselines"]
    assert list(baselines["fused"]) == ["cite-all", "cite-none", "cite-top-k-wazuh-level",
                                        "cite-top-k-detector-order", "cite-aminer-only"]
    cite_all = baselines["fused"]["cite-all"]
    assert cite_all["coverage"]["time_label"]["all"] == {"covered": 2, "cases": 3, "rate": 2 / 3}
    assert cite_all["coverage"]["time_label"]["reachable"] == {"covered": 2, "cases": 2, "rate": 1.0}
    assert cite_all["coverage"]["event_label"]["reachable"]["rate"] == 1.0
    assert cite_all["unsupported_claim_rate"] == 0.0 and cite_all["claims"] > 0
    none = baselines["fused"]["cite-none"]
    assert none["alerts_cited"]["total"] == 0 and none["unsupported_claim_rate"] is None
    assert none["citation_precision"]["event_label"] is None
    assert none["coverage"]["time_label"]["all"]["covered"] == 0
    aminer_only = baselines["fused"]["cite-aminer-only"]
    assert aminer_only["alerts_cited"]["total"] == 1
    assert aminer_only["citation_precision"] == {"event_label": 1.0, "time_label": 1.0,
                                                 "cited": 1, "event_attack": 1, "in_phase": 1}
    assert aminer_only["coverage"]["time_label"]["reachable"] == {"covered": 1, "cases": 2, "rate": 0.5}
    noise_all = baselines["noise-suricata"]["cite-all"]
    assert noise_all["citation_precision"]["event_label"] == 0.0  # noise is benign by construction


def test_dev_case_report_records_truncation(processed: Path, samples_dir: Path, tmp_path: Path) -> None:  # noqa: F811
    labels = samples_dir / "synthetic_ait_ads" / "synthetic_labels.csv"
    config = load_study_config(synthetic_config(tmp_path, max_alerts=1))
    fused = dev_case_report(processed, labels, "synthetic", config)["variants"]["fused"]
    assert fused["truncation"] == {"cases_truncated": 1, "alerts_dropped": 2,
                                   "cases_cap_dropped_event_attack": 1, "cases_cap_dropped_time_attack": 1}
    # The spread cap keeps a2 (an attack), so the ceiling after the cap is unchanged here.
    assert fused["coverage_ceiling"]["time_label"]["covered"] == 2
    assert fused["coverage_ceiling_before_cap"]["time_label"]["covered"] == 2


def test_cli(processed: Path, samples_dir: Path, tmp_path: Path,  # noqa: F811
             capsys: pytest.CaptureFixture[str]) -> None:
    labels = samples_dir / "synthetic_ait_ads" / "synthetic_labels.csv"
    code = main(["cases", "--scenario", "synthetic", "--processed-dir", str(processed),
                 "--labels", str(labels), "--study-config", str(synthetic_config(tmp_path)),
                 "--no-output"])
    assert code == 0
    out = capsys.readouterr().out
    assert "CEILINGS" in out and "not agent results" in out
    assert "BASELINES" in out and "cite-top-k-detector-order" in out
    assert main(["cases", "--scenario", "wilson", "--processed-dir", str(processed),
                 "--labels", str(labels), "--no-output"]) == 2
