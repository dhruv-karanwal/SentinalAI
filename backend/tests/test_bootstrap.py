"""Wave A: dev replay end to end into the SQLite fallback stores."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.platform.bootstrap import ingest_scenario, open_stores
from app.study.config import load_study_config
from tests.test_cases import synthetic_config
from tests.test_variants import processed  # noqa: F401  (fixture)


def test_ingest_scenario_into_fallback_stores(tmp_path: Path, processed: Path,  # noqa: F811
                                             monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("SENTINEL_DB_URL", "SENTINEL_SEARCH_URL", "SENTINEL_KAFKA"):
        monkeypatch.delenv(var, raising=False)
    stores = open_stores(tmp_path / "platform")
    config = load_study_config(synthetic_config(tmp_path))
    report = ingest_scenario(stores, processed, "synthetic", config)
    assert report["stored"] == report["published"] == report["alerts_in_store"] > 0
    assert report["ground_truth_rows"] == report["alerts_in_store"]
    assert (tmp_path / "platform" / "truth.db").exists()
    again = ingest_scenario(open_stores(tmp_path / "platform"), processed, "synthetic", config)
    assert again["stored"] == 0 and again["duplicates"] == report["published"]
