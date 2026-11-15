"""Wave B4: ML detection baselines. Features are label-free; labels come only via dev_labels."""

from __future__ import annotations

import inspect
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from app.detection import features as fx
from app.detection import ml_baselines as ml
from app.detection.labels import TruthLabels
from app.schemas.alert import DETECTOR_TYPES, Alert, AlertEvidence, Detector

T0 = datetime(2022, 1, 21, 10, 0, tzinfo=timezone.utc)

EXPECTED_FEATURES = (
    "detector", "severity", "has_severity", "rule_id", "category", "aminer_component",
    "attack_mapped", "ioc_match", "host_count_60s", "host_count_600s", "evidence_lines",
    "evidence_chars",
)
FORBIDDEN = ("event_label", "time_label", "phase", "attack_phase", "scenario", "alert_id", "timestamp",
             "ts", "label", "source_file", "source_line", "hour")


def mk(aid: str, seconds: float, *, detector: Detector = Detector.WAZUH, host: str | None = "10.0.0.5",
       rule: str = "5501", severity: int | None = 3, raw: dict[str, Any] | None = None,
       lines: list[str] | None = None) -> Alert:
    return Alert(alert_id=aid, scenario="synthetic", detector=detector,
                 detector_type=DETECTOR_TYPES[detector], timestamp=T0 + timedelta(seconds=seconds),
                 rule_id=rule, severity=severity, host_ip=host, raw_alert=raw or {},
                 evidence=AlertEvidence(log_lines=lines or []), source_file="f.json",
                 source_line=int(seconds) + 1)


def test_exact_feature_list_and_no_forbidden_feature() -> None:
    assert fx.FEATURE_NAMES == EXPECTED_FEATURES
    for name in fx.FEATURE_NAMES:
        for bad in FORBIDDEN:
            assert name != bad and not name.startswith(bad + "_") and not name.endswith("_" + bad)
    assert set(fx.CATEGORICAL) == {"detector", "rule_id", "category", "aminer_component"}


def test_feature_builder_takes_no_labels() -> None:
    params = inspect.signature(fx.raw_features).parameters
    assert list(params) == ["alerts", "iocs"]
    source = inspect.getsource(fx)
    for word in ("ground_truth", "GroundTruth", "TruthStore", "event_label", "time_label",
                 "dev_labels", "TruthLabels"):
        assert word not in source


def test_row_values() -> None:
    aminer = mk("m", 5, detector=Detector.AMINER, severity=None,
                raw={"AnalysisComponent": {"AnalysisComponentType": "NewMatchPathDetector"}},
                lines=["abc", "de"])
    wazuh = mk("w", 0, raw={"rule": {"groups": ["sshd"], "mitre": {"id": ["T1110"]}}})
    rows = fx.raw_features([aminer, wazuh])
    assert [r["detector"] for r in rows] == ["aminer", "wazuh"]  # input order kept
    assert rows[0]["severity"] == -1 and rows[0]["has_severity"] == 0
    assert rows[0]["aminer_component"] == "NewMatchPathDetector"
    assert rows[0]["category"] == "NewMatchPathDetector"
    assert rows[0]["evidence_lines"] == 2 and rows[0]["evidence_chars"] == 5
    assert rows[1]["attack_mapped"] == 1 and rows[1]["category"] == "sshd"
    assert rows[1]["aminer_component"] == "n/a" and rows[1]["severity"] == 3


def test_host_counts_use_strictly_past_alerts_only() -> None:
    alerts = [mk("a", 0), mk("b", 0), mk("c", 30), mk("d", 61), mk("e", 700), mk("x", 30, host="10.9.9.9")]
    rows = {a.alert_id: r for a, r in zip(alerts, fx.raw_features(alerts))}
    assert rows["a"]["host_count_60s"] == 0 and rows["b"]["host_count_60s"] == 0  # same instant: not past
    assert rows["c"]["host_count_60s"] == 2
    assert rows["d"]["host_count_60s"] == 1  # a, b are 61 s back: outside the 60 s window
    assert rows["d"]["host_count_600s"] == 3
    assert rows["e"]["host_count_600s"] == 0
    assert rows["x"]["host_count_60s"] == 0  # other host
    # a future alert never changes a past row (no lookahead)
    more = fx.raw_features(alerts + [mk("f", 5000)])  # later than every alert above
    assert more[:len(alerts)] == [rows[a.alert_id] for a in alerts]


def test_encoder_fits_on_train_and_maps_unseen_to_unknown() -> None:
    train = fx.raw_features([mk("a", 0, rule="1"), mk("b", 1, rule="2")])
    test = fx.raw_features([mk("c", 2, rule="3"), mk("d", 3, rule="1")])
    enc = fx.FeatureEncoder.fit(train)
    x = enc.transform(test)
    col = fx.FEATURE_NAMES.index("rule_id")
    assert x[0, col] == fx.UNKNOWN_CODE and x[1, col] == enc.vocab["rule_id"]["1"]
    assert x.shape == (2, len(fx.FEATURE_NAMES))


def test_time_split_is_gone() -> None:
    # replaced by leave-one-phase-out (the 60/40 timeline split had no attacks in training)
    assert not hasattr(ml, "time_split") and not hasattr(ml, "TRAIN_FRACTION")


def test_lopo_folds_hold_out_one_phase_each() -> None:
    alerts = [mk(str(i), i) for i in range(9)]
    phases = {"0": "scan", "1": "scan", "3": "dirb", "4": "dirb", "5": "dirb", "8": "exfil"}
    labels = {a.alert_id: TruthLabels(a.alert_id in phases, a.alert_id in phases,
                                      phases.get(a.alert_id)) for a in alerts}
    folds = ml.lopo_folds(alerts, labels)
    assert [f[0] for f in folds] == ["scan", "dirb", "exfil"]  # first-seen time order
    for phase, train, test in folds:
        assert {a.alert_id for a in test} == {k for k, v in phases.items() if v == phase}
        assert not {a.alert_id for a in train} & {a.alert_id for a in test}
        assert len(train) + len(test) == len(alerts)
    # alerts outside every phase are never a test alert
    tested = {a.alert_id for _, _, t in folds for a in t}
    assert tested == set(phases)


def phased_alerts() -> tuple[list[Alert], dict[str, TruthLabels]]:
    alerts, labels = [], {}
    for i in range(160):
        phase = ("p1", "p2", "p3", "p4")[i // 40]
        hot = i % 4 == 0
        a = mk(f"a{i}", i * 7, rule="31101" if hot else "5501", severity=10 if hot else 3,
               host="10.0.0.5" if hot else "10.0.0.6", lines=["x" * (200 if hot else 20)])
        alerts.append(a)
        labels[a.alert_id] = TruthLabels(hot, hot, phase if i % 2 == 0 else None)
    return alerts, labels


def test_lopo_scores_pool_predictions_and_report_per_phase() -> None:
    alerts, labels = phased_alerts()
    res = ml.lopo_scores(alerts, labels, seed=7)
    assert [p["phase"] for p in res["per_phase"]] == ["p1", "p2", "p3", "p4"]
    hgb = res["pooled"]["hist_gradient_boosting"]["event_label"]
    tested = sum(1 for a in alerts if labels[a.alert_id].phase is not None)
    assert hgb["tp"] + hgb["fp"] + hgb["fn"] + hgb["tn"] == tested
    assert res["pooled"] == ml.lopo_scores(alerts, labels, seed=7)["pooled"]  # deterministic
    for ph in res["per_phase"]:
        assert {"n_test", "event_attack", "models"} <= set(ph)


def test_ablation_drops_detector_and_rule_id() -> None:
    assert ml.ABLATION_DROPPED == ("detector", "rule_id")
    assert ml.FEATURE_SETS["all"] == EXPECTED_FEATURES
    assert ml.FEATURE_SETS["no_detector_rule_id"] == tuple(
        f for f in EXPECTED_FEATURES if f not in ("detector", "rule_id"))
    alerts, attack = synthetic_alerts()
    labels = labels_for(alerts, attack)
    res = ml.fit_and_score(alerts[:72], alerts[72:], labels, seed=7,
                           features=ml.FEATURE_SETS["no_detector_rule_id"])
    assert res["features"] == list(ml.FEATURE_SETS["no_detector_rule_id"])
    assert "detector" not in res["test_rows_with_unseen_category"]


def test_permutation_importances_cover_every_used_feature() -> None:
    alerts, attack = synthetic_alerts()
    labels = labels_for(alerts, attack)
    res = ml.fit_and_score(alerts[:72], alerts[72:], labels, seed=7, importances=True)
    imp = res["models"]["hist_gradient_boosting"]["permutation_importance"]
    assert {r["feature"] for r in imp} == set(EXPECTED_FEATURES)
    assert imp == sorted(imp, key=lambda r: (-r["mean"], r["feature"]))
    assert res == ml.fit_and_score(alerts[:72], alerts[72:], labels, seed=7, importances=True)


def labels_for(alerts: list[Alert], attack: set[str]) -> dict[str, TruthLabels]:
    return {a.alert_id: TruthLabels(a.alert_id in attack, a.alert_id in attack) for a in alerts}


def synthetic_alerts() -> tuple[list[Alert], set[str]]:
    alerts, attack = [], set()
    for i in range(120):
        hot = i % 4 == 0
        a = mk(f"a{i}", i * 7, rule="31101" if hot else "5501", severity=10 if hot else 3,
               host="10.0.0.5" if hot else "10.0.0.6", lines=["x" * (200 if hot else 20)])
        alerts.append(a)
        if hot:
            attack.add(a.alert_id)
    return alerts, attack


def test_models_are_seeded_and_scored_by_both_labels() -> None:
    alerts, attack = synthetic_alerts()
    labels = labels_for(alerts, attack)
    train, test = alerts[:72], alerts[72:]
    first = ml.fit_and_score(train, test, labels, seed=7)
    again = ml.fit_and_score(train, test, labels, seed=7)
    assert first == again
    assert set(first["models"]) == {"isolation_forest", "hist_gradient_boosting"}
    for model in first["models"].values():
        assert set(model) == {"event_label", "time_label"}
        assert {"precision", "recall", "f1", "fnr", "tp", "fp", "fn", "tn"} <= set(model["event_label"])
    assert first["class_balance"]["train"]["event_label"]["attack"] == sum(a.alert_id in attack for a in train)
    assert first["models"]["hist_gradient_boosting"]["event_label"]["recall"] == 1.0
    assert first["features"] == list(EXPECTED_FEATURES)


def test_unavailable_event_labels_are_left_out_of_training_and_event_scoring() -> None:
    alerts, attack = synthetic_alerts()
    labels = labels_for(alerts, attack)
    gone = alerts[1].alert_id
    labels[gone] = TruthLabels(None, False)
    train, test = alerts[:72], alerts[72:]
    res = ml.fit_and_score(train, test, labels, seed=7)
    assert res["class_balance"]["train"]["event_label"]["unavailable"] == 1
    assert res["class_balance"]["train"]["n"] == len(train)


def test_single_class_training_is_reported_not_raised() -> None:
    alerts, _ = synthetic_alerts()
    labels = labels_for(alerts, set())
    train, test = alerts[:72], alerts[72:]
    res = ml.fit_and_score(train, test, labels, seed=7)
    assert res["models"]["hist_gradient_boosting"] == {
        "skipped": "training split has a single event_label class"}


def test_ml_cli_refuses_held_out(tmp_path: Path) -> None:
    from app.main import main
    assert main(["ml-baselines", "--scenarios", "fox", "shaw"]) == 2


def test_matrix_is_float(tmp_path: Path) -> None:
    rows = fx.raw_features([mk("a", 0)])
    assert fx.FeatureEncoder.fit(rows).transform(rows).dtype == np.float64


# ---------------------------------------------------------------- comparison (C4, 2026-11-15)

def test_comparison_models_report_threshold_free_metrics_and_timing() -> None:
    alerts, attack = synthetic_alerts()
    labels = labels_for(alerts, attack)
    res = ml.fit_and_score(alerts[:72], alerts[72:], labels, seed=7, models=ml.COMPARISON_MODELS)
    assert set(res["models"]) == set(ml.COMPARISON_MODELS)
    for name, m in res["models"].items():
        ev = m["event_label"]
        assert {"accuracy", "fpr", "pr_auc", "roc_auc", "tp", "fp", "fn", "tn"} <= set(ev), name
        assert 0.0 <= ev["roc_auc"] <= 1.0
        assert set(res["timing"][name]) == {"fit_seconds", "predict_seconds"}
    # determinism of everything except wall-clock timing
    again = ml.fit_and_score(alerts[:72], alerts[72:], labels, seed=7, models=ml.COMPARISON_MODELS)
    assert again["models"] == res["models"]


def test_default_output_is_unchanged_by_the_comparison() -> None:
    alerts, attack = synthetic_alerts()
    labels = labels_for(alerts, attack)
    res = ml.fit_and_score(alerts[:72], alerts[72:], labels, seed=7)
    assert "timing" not in res and set(res["models"]) == {"isolation_forest", "hist_gradient_boosting"}


def test_no_host_counts_set_drops_only_the_rate_features() -> None:
    assert ml.COMPARISON_FEATURE_SETS["no_host_counts"] == tuple(
        f for f in EXPECTED_FEATURES if f not in ("host_count_60s", "host_count_600s"))
    assert ml.COMPARISON_FEATURE_SETS["all"] == EXPECTED_FEATURES
