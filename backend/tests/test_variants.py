"""Alert-source variants, study sampler and triage scoring on the synthetic sample.

Investigation pool of the synthetic scenario (time order):
  w1 wazuh    benign by both labels
  w5 wazuh    event_label service_scan, time_label network_scans
  s2 suricata event_label dirb,         time_label dirb
  a2 aminer   event_label escalated_sudo_command, time_label dirb
  s4 suricata (fast.log without eve twin) no event label, time_label dirb
"""

import json
from pathlib import Path

import pytest

from app.alert_pipeline import AitAdsInputs, run_alert_ingest
from app.ingestion.records import IngestionError
from app.main import main
from app.study.config import DEFAULT_STUDY_CONFIG, StudyConfig, load_study_config
from app.study.variants import (
    AlertPool,
    build_variants,
    dev_triage_report,
    triage_by_truth,
    variant_manifest,
    write_variant,
)

W1, S2, S4, W5 = "1700000000.1", "1700000000.2", "1700000000.4", "1700000000.5"
SEED = 7


@pytest.fixture
def processed(samples_dir: Path, tmp_path: Path) -> Path:
    d = samples_dir / "synthetic_ait_ads"
    out = tmp_path / "processed"
    run_alert_ingest(
        AitAdsInputs("synthetic", d / "synthetic_wazuh.json", d / "synthetic_aminer.json",
                     d / "synthetic_labels.csv", d / "synthetic_alerts.txt"),
        dataset_name="synthetic-ait-ads-format", output_dir=out, collect=False)
    return out


@pytest.fixture
def pool(processed: Path) -> AlertPool:
    return AlertPool.from_processed(processed, "synthetic")


def aminer_id(pool: AlertPool) -> str:
    return next(e.alert_id for e in pool.entries if e.detector.value == "aminer")


def test_pool_is_investigation_eligible_and_time_sorted(pool: AlertPool) -> None:
    ids = [e.alert_id for e in pool.entries]
    assert ids == [W1, W5, S2, aminer_id(pool), S4]
    assert [e.event_attack for e in pool.entries] == [False, True, True, True, False]
    assert [e.time_attack for e in pool.entries] == [False, True, True, True, True]
    assert pool.excluded == 4  # 1 fast.log duplicate, 1 training, 2 aggregates


def test_variants(pool: AlertPool) -> None:
    v = build_variants(pool, seed=SEED, shuffled_references=("fused", "wazuh"),
                       noise_references=("suricata",))
    assert list(v) == ["wazuh", "suricata", "aminer", "fused", "oracle", "shuffled-fused",
                       "shuffled-wazuh", "noise-suricata"]
    # Scenario-level noise: count-matched to suricata, drawn only from event-benign alerts.
    assert len(v["noise-suricata"].alert_ids) == 2
    assert set(v["noise-suricata"].alert_ids) == {W1, S4}
    assert v["noise-suricata"].family == "noise" and v["shuffled-wazuh"].family == "shuffled"
    assert v["wazuh"].family == "detector" and v["fused"].family == "fused"
    a2 = aminer_id(pool)
    assert v["wazuh"].alert_ids == (W1, W5)
    assert v["suricata"].alert_ids == (S2, S4)
    assert v["aminer"].alert_ids == (a2,)
    assert v["fused"].alert_ids == (W1, W5, S2, a2, S4)
    assert v["oracle"].alert_ids == (W5, S2, a2)
    for variant in v.values():  # no double counting, always time-ordered
        assert len(set(variant.alert_ids)) == len(variant.alert_ids)
        times = [e.timestamp for e in variant.entries]
        assert times == sorted(times)
    # Random at the fused volume draws the whole pool: flagged, not hidden.
    assert set(v["shuffled-fused"].alert_ids) == set(v["fused"].alert_ids)
    assert v["shuffled-fused"].degenerate
    assert len(v["shuffled-wazuh"].alert_ids) == 2 and not v["shuffled-wazuh"].degenerate
    assert v["shuffled-wazuh"].reference == "wazuh"


def test_shuffled_is_seeded(pool: AlertPool) -> None:
    def draw(seed: int) -> tuple[str, ...]:
        return build_variants(pool, seed=seed, shuffled_references=("wazuh",))["shuffled-wazuh"].alert_ids

    assert draw(SEED) == draw(SEED)
    assert len({draw(seed) for seed in range(20)}) > 1


def test_unknown_shuffled_reference_raises(pool: AlertPool) -> None:
    with pytest.raises(ValueError, match="reference"):
        build_variants(pool, seed=SEED, shuffled_references=("oracle-x",))


def test_variant_alerts_are_the_ingested_records(pool: AlertPool, processed: Path) -> None:
    fused = build_variants(pool, seed=SEED)["fused"]
    alerts = list(pool.alerts(fused))
    assert [a.alert_id for a in alerts] == list(fused.alert_ids)
    originals = {}
    for line in (processed / "synthetic.alerts.jsonl").read_text("utf-8").splitlines():
        originals[json.loads(line)["alert_id"]] = line
    assert all(a.model_dump_json() == originals[a.alert_id] for a in alerts)


def scores(s: object) -> tuple[int, int, int, int]:
    return (s.tp, s.fp, s.fn, s.tn)  # type: ignore[attr-defined]


def test_triage_scores(pool: AlertPool) -> None:
    v = build_variants(pool, seed=SEED)
    by_truth = {name: triage_by_truth(variant, pool) for name, variant in v.items()}
    assert scores(by_truth["fused"]["event_label"]) == (3, 2, 0, 0)
    assert by_truth["fused"]["event_label"].precision == pytest.approx(0.6)
    assert by_truth["fused"]["event_label"].recall == 1.0
    assert scores(by_truth["oracle"]["event_label"]) == (3, 0, 0, 2)
    assert scores(by_truth["wazuh"]["event_label"]) == (1, 1, 2, 1)
    assert scores(by_truth["aminer"]["event_label"]) == (1, 0, 2, 2)
    # time_label sensitivity: s4 counts as an attack by time only.
    assert scores(by_truth["fused"]["time_label"]) == (4, 1, 0, 0)
    assert scores(by_truth["oracle"]["time_label"]) == (3, 0, 1, 1)


def test_manifest(pool: AlertPool) -> None:
    v = build_variants(pool, seed=SEED, shuffled_references=("wazuh",))
    m = variant_manifest(v["fused"], pool)
    assert m["variant"] == "fused" and m["scenario"] == "synthetic"
    assert m["alerts"] == 5 and m["pool_size"] == 5
    assert m["by_detector"] == {"aminer": 1, "suricata": 2, "wazuh": 2}
    assert m["attack_share"]["event_label"] == {"attack": 3, "benign": 2, "unavailable": 0, "share": 0.6}
    assert m["attack_share"]["time_label"] == {"attack": 4, "benign": 1, "share": 0.8}
    assert m["selection"] == {"include_training_mode": False, "include_duplicates": False,
                              "include_aggregates": False}
    assert m["source"]["alerts_file"] == "synthetic.alerts.jsonl"
    assert len(m["source"]["alerts_sha256"]) == 64
    r = variant_manifest(v["shuffled-wazuh"], pool)
    assert (r["seed"], r["reference_variant"], r["reference_size"]) == (SEED, "wazuh", 2)
    assert isinstance(r["derived_seed"], int) and r["degenerate"] is False


def test_write_variant(pool: AlertPool, processed: Path, tmp_path: Path) -> None:
    oracle = build_variants(pool, seed=SEED)["oracle"]
    alerts_path, manifest_path = write_variant(oracle, pool, tmp_path / "v")
    assert alerts_path.name == "synthetic.variant.oracle.alerts.jsonl"
    assert manifest_path.name == "synthetic.variant.oracle.manifest.json"
    lines = alerts_path.read_text("utf-8").splitlines()
    assert [json.loads(line)["alert_id"] for line in lines] == list(oracle.alert_ids)
    assert json.loads(manifest_path.read_text("utf-8")) == variant_manifest(oracle, pool)


def test_pool_requires_ground_truth_for_every_alert(processed: Path) -> None:
    truth = processed / "synthetic.ground_truth.jsonl"
    truth.write_text("\n".join(truth.read_text("utf-8").splitlines()[1:]) + "\n", encoding="utf-8")
    with pytest.raises(IngestionError, match="ground truth"):
        AlertPool.from_processed(processed, "synthetic")


def synthetic_config(tmp_path: Path) -> Path:
    data = json.loads(DEFAULT_STUDY_CONFIG.read_text(encoding="utf-8"))
    data["split"]["dev"] = ["synthetic"]
    data["pilot"]["scenarios"] = ["synthetic"]
    data["variants"]["shuffled_reference"] = ["aminer"]
    path = tmp_path / "study.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_dev_triage_report(processed: Path, tmp_path: Path) -> None:
    config: StudyConfig = load_study_config(synthetic_config(tmp_path))
    report = dev_triage_report(processed, "synthetic", config, output_dir=tmp_path / "out")
    assert report["scenario_split"] == "dev"
    assert report["truth"] == {"primary": "event_label", "sensitivity": "time_label"}
    assert list(report["variants"]) == [
        "wazuh", "suricata", "aminer", "fused", "oracle", "shuffled-aminer",
        "noise-wazuh", "noise-suricata", "noise-aminer"]
    assert report["variants"]["noise-aminer"]["triage"]["event_label"]["tp"] == 0
    assert report["variants"]["oracle"]["triage"]["event_label"]["f1"] == 1.0
    # shuffled-fused survives only as a manifest, marked degenerate, never as a variant.
    only = report["manifest_only"]["shuffled-fused"]
    assert only["degenerate"] is True and only["experiment_variant"] is False
    assert "sample" not in report
    out = tmp_path / "out" / "synthetic"
    assert (out / "synthetic.variant.fused.manifest.json").exists()
    assert (out / "synthetic.variant.shuffled-fused.manifest.json").exists()
    assert not (out / "synthetic.variant.shuffled-fused.alerts.jsonl").exists()
    assert json.loads((out / "synthetic.dev_triage.json").read_text("utf-8")) == report


def test_cli(processed: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["variants", "--scenario", "synthetic", "--processed-dir", str(processed),
                 "--study-config", str(synthetic_config(tmp_path)),
                 "--output-dir", str(tmp_path / "out")])
    assert code == 0
    out = capsys.readouterr().out
    assert "DEV-SCENARIO NUMBERS" in out and "oracle" in out
    assert main(["variants", "--scenario", "fox", "--processed-dir", str(processed),
                 "--no-output"]) == 2
