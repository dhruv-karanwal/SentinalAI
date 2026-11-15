"""C4 (2026-11-15): operational ML bundle: train (labels via the door), save, verify, score, store, API.

SYNTHETIC sample only (scenario "synthetic", 9 alerts, made dev by the test config). Numbers here are
plumbing checks, never detection results.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.app import Services, create_app
from app.api.auth import Role, hash_password
from app.detection import ml_model as mm
from app.main import main
from app.platform.bootstrap import ingest_scenario, open_stores
from app.storage.objects import LocalObjectStore
from app.study.config import load_study_config
from tests.test_api import PASSWORD, SECRET, token
from tests.test_cases import synthetic_config
from tests.test_variants import processed  # noqa: F401  (fixture)


@pytest.fixture()
def trained(tmp_path: Path, processed: Path, monkeypatch: pytest.MonkeyPatch  # noqa: F811
            ) -> tuple[Path, Path, Path]:
    for var in ("SENTINEL_DB_URL", "SENTINEL_SEARCH_URL", "SENTINEL_KAFKA"):
        monkeypatch.delenv(var, raising=False)
    cfg = synthetic_config(tmp_path)
    platform, models = tmp_path / "platform", tmp_path / "models"
    ingest_scenario(open_stores(platform), processed, "synthetic", load_study_config(cfg))
    assert main(["ml-train", "--scenarios", "synthetic", "--processed-dir", str(processed),
                 "--study-config", str(cfg), "--data-dir", str(platform), "--model-dir", str(models)]) == 0
    return cfg, platform, models


def test_train_saves_a_versioned_verified_bundle(trained: tuple[Path, Path, Path]) -> None:
    _, _, models = trained
    path = mm.latest_bundle(models)
    assert path is not None and path.name.startswith("ml-")
    meta = json.loads((path / mm.METADATA_FILE).read_text(encoding="utf-8"))
    assert meta["trained_on"] == ["synthetic"] and meta["influences_severity"] is False
    assert set(meta["importance_order"]) == set(meta["features"])
    assert "not paper results" in meta["label"]
    bundle = mm.load_bundle(path)
    assert set(bundle.models) == {"hist_gradient_boosting", "isolation_forest"}
    (path / mm.MODEL_FILE).write_bytes((path / mm.MODEL_FILE).read_bytes() + b"x")  # tampered
    with pytest.raises(mm.BundleError, match="sha256"):
        mm.load_bundle(path)


def test_score_store_and_api(trained: tuple[Path, Path, Path], tmp_path: Path) -> None:
    cfg, platform, models = trained
    assert main(["ml-score", "--scenario", "synthetic", "--study-config", str(cfg),
                 "--data-dir", str(platform), "--model-dir", str(models)]) == 0
    stores = open_stores(platform)
    repo = stores.repo
    alerts = list(repo.iter_alert_models("synthetic"))
    rows = repo.ml_scores([a.alert_id for a in alerts])
    assert len(rows) == 2 * len(alerts)
    assert {r["model"] for r in rows} == {"hist_gradient_boosting", "isolation_forest"}
    assert all(r["in_sample"] for r in rows) and all(len(r["explanation"]) == mm.EXPLAIN_TOP for r in rows)
    assert all(0.0 <= r["score"] <= 1.0 for r in rows if r["model"] == "hist_gradient_boosting")
    # re-scoring the same version replaces, never duplicates
    assert main(["ml-score", "--scenario", "synthetic", "--study-config", str(cfg),
                 "--data-dir", str(platform), "--model-dir", str(models)]) == 0
    assert len(repo.ml_scores([a.alert_id for a in alerts])) == len(rows)
    ids = [a.alert_id for a in alerts][:3]
    repo.put_incident({"incident_id": "inc-ml", "scenario": "synthetic", "first_ts": alerts[0].timestamp.isoformat(),
                       "last_ts": alerts[2].timestamp.isoformat(), "severity": "Low", "alert_ids": ids,
                       "detail": {}})
    for role in Role:
        repo.put_user(role.value, hash_password(PASSWORD, rounds=4), role.value)
    c = TestClient(create_app(Services(repo, stores.index, LocalObjectStore(tmp_path / "obj"), SECRET)))
    body = c.get("/incidents/inc-ml/ml", headers=token(c, Role.EXECUTIVE)).json()
    assert body["influences_severity"] is False and len(body["models"]) == 2
    hgb = next(m for m in body["models"] if m["model"] == "hist_gradient_boosting")
    assert hgb["scored"] == 3 and hgb["in_sample"] is True and "uncalibrated" in hgb["kind"]
    assert "event_label" not in json.dumps(body) and "time_label" not in json.dumps(body)
    assert c.get("/incidents/nope/ml", headers=token(c, Role.ANALYST)).status_code == 404


def test_ml_commands_refuse_held_out(tmp_path: Path) -> None:
    cfg = synthetic_config(tmp_path)
    assert main(["ml-train", "--scenarios", "fox", "--study-config", str(cfg),
                 "--data-dir", str(tmp_path / "p"), "--model-dir", str(tmp_path / "m")]) == 2
    assert main(["ml-score", "--scenario", "fox", "--study-config", str(cfg),
                 "--data-dir", str(tmp_path / "p"), "--model-dir", str(tmp_path / "m")]) == 2


def test_inference_module_never_sees_labels() -> None:
    text = Path(mm.__file__).read_text(encoding="utf-8")
    for word in ("ground_truth", "TruthStore", "dev_labels", "event_label", "time_label"):
        assert word not in text
