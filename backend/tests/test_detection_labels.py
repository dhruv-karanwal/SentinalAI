"""The single label door (app.detection.labels) and the Sigma CLI end to end (synthetic)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from app.detection.labels import MissingTruthError, TruthLabels, dev_labels
from app.main import main
from app.platform.bootstrap import ingest_scenario, open_stores
from app.schemas.alert import GroundTruth
from app.storage.db import SqliteDatabase
from app.storage.repository import TruthStore
from app.study.config import HeldOutScenarioError, load_study_config
from tests.test_cases import synthetic_config
from tests.test_variants import processed  # noqa: F401  (fixture)

APP = Path(__file__).resolve().parents[1] / "app"

# Modules allowed to import the label door. Everything else in app/detection
# (Sigma engine, triage code path, ML feature builder) must not.
LABEL_READERS = {"main.py", "detection/labels.py", "detection/sigma_report.py",
                 "detection/ml_baselines.py", "detection/triage_report.py"}
# Detection-layer modules that must never see labels in any form.
LABEL_FREE = ("detection/sigma_engine.py", "detection/triage.py", "detection/features.py",
              "outputs/analytics.py", "outputs/graph_layout.py", "api/explain.py")
LABEL_WORDS = ("ground_truth", "GroundTruth", "TruthStore", "event_label", "time_label",
               "dev_labels", "TruthLabels", "labels.csv", "AttackTimeline")


def truth_store(tmp_path: Path) -> TruthStore:
    db = SqliteDatabase(tmp_path / "truth.db", area="truth")
    db.migrate()
    return TruthStore(db)


def test_dev_labels_maps_rows(tmp_path: Path) -> None:
    store = truth_store(tmp_path)
    store.put_many([
        GroundTruth(alert_id="a", scenario="shaw", time_label="dirb", event_label="dirb",
                    event_label_available=True),
        GroundTruth(alert_id="b", scenario="shaw", time_label="false_positive",
                    event_label_available=True),
        GroundTruth(alert_id="c", scenario="shaw", time_label="dirb"),
    ])
    labels = dev_labels(store, "shaw", load_study_config())
    assert labels == {"a": TruthLabels(True, True, "dirb"), "b": TruthLabels(False, False),
                      "c": TruthLabels(None, True, "dirb")}
    assert labels["b"].phase is None  # outside every interval: no phase


def test_dev_labels_refuses_held_out_and_missing(tmp_path: Path) -> None:
    store = truth_store(tmp_path)
    with pytest.raises(HeldOutScenarioError):
        dev_labels(store, "fox", load_study_config())
    with pytest.raises(MissingTruthError):
        dev_labels(store, "russellmitchell", load_study_config())


def test_only_listed_modules_import_the_label_door() -> None:
    importers = set()
    for path in APP.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if re.search(r"app\.detection\.labels|from app\.detection import labels", text):
            importers.add(path.relative_to(APP).as_posix())
    assert importers <= LABEL_READERS, importers - LABEL_READERS


def test_label_free_detection_modules() -> None:
    for rel in LABEL_FREE:
        path = APP / rel
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        for word in LABEL_WORDS:
            assert word not in text, (rel, word)


def test_sigma_cli_on_synthetic(tmp_path: Path, processed: Path,  # noqa: F811
                                monkeypatch: pytest.MonkeyPatch,
                                capsys: pytest.CaptureFixture[str]) -> None:
    for var in ("SENTINEL_DB_URL", "SENTINEL_SEARCH_URL", "SENTINEL_KAFKA"):
        monkeypatch.delenv(var, raising=False)
    cfg = synthetic_config(tmp_path)
    rules = tmp_path / "sigma"
    rule = rules / "rules" / "linux" / "any.yml"
    rule.parent.mkdir(parents=True)
    rule.write_text("title: synthetic any syslog line\nid: 11111111-1111-1111-1111-111111111111\n"
                    "level: low\nlogsource:\n  product: linux\ndetection:\n  keywords:\n"
                    "    - ' '\n  condition: keywords\n", encoding="utf-8")
    platform = tmp_path / "platform"
    out = tmp_path / "out"
    args = ["sigma", "--scenario", "synthetic", "--rules-dir", str(rules), "--processed-dir",
            str(processed), "--output-dir", str(out), "--study-config", str(cfg),
            "--data-dir", str(platform)]
    open_stores(platform)  # empty truth area -> the dev baseline refuses
    assert main(args) == 1
    assert "platform-ingest" in capsys.readouterr().err
    ingest_scenario(open_stores(platform), processed, "synthetic", load_study_config(cfg))
    assert main(args) == 0
    text = capsys.readouterr().out
    assert "dev detection baseline" in text and "not a paper result" in text
    report = json.loads((out / "synthetic.sigma.report.json").read_text(encoding="utf-8"))
    assert report["rules"] == {"total": 1, "compiled": 1, "skipped": 0, "skipped_by_reason": {},
                               "compiled_by_log_type": {"syslog": 1}}
    assert "_pool_ids" not in json.dumps(report)
    base = json.loads((out / "synthetic.sigma.dev_baseline.json").read_text(encoding="utf-8"))
    assert base["pool_alerts"] == report["stats"]["source_alerts"]
    assert main(["sigma", "--scenario", "fox", "--study-config", str(cfg)]) == 2
