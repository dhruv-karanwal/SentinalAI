"""Integration test on the real AIT-ADS files, when the user has downloaded them.

The real data is git-ignored and never downloaded by tests; without it these
tests are skipped. Assertions are invariants verified on the real files
(clean positional link to alerts_csv, every attack interval inside the alert
time range), not hard-coded dataset statistics.
"""

import csv
from pathlib import Path

import pytest

from app.alert_pipeline import AitAdsInputs, run_alert_ingest
from app.ingestion.ground_truth import AttackTimeline
from app.ingestion.mappings import AIT_ADS_SCENARIOS

RAW_DIR = Path(__file__).resolve().parents[2] / "data" / "raw" / "ait_ads"
SCENARIO = "russellmitchell"  # the smallest scenario

pytestmark = pytest.mark.skipif(
    not (RAW_DIR / f"{SCENARIO}_wazuh.json").is_file()
    or not (RAW_DIR / "labels.csv").is_file(),
    reason="real AIT-ADS files not present in data/raw/ait_ads",
)


def test_labels_load_for_every_scenario() -> None:
    with (RAW_DIR / "labels.csv").open(encoding="utf-8") as handle:
        scenarios = {row["scenario"] for row in csv.DictReader(handle)}
    assert scenarios == set(AIT_ADS_SCENARIOS)
    for scenario in AIT_ADS_SCENARIOS:
        assert AttackTimeline.from_labels_csv(RAW_DIR / "labels.csv", scenario).intervals


def test_real_scenario_ingest() -> None:
    layout = AitAdsInputs.from_layout(RAW_DIR, SCENARIO)
    result = run_alert_ingest(layout, collect=False)
    report = result.report
    counts = report["record_counts"]
    assert counts["total_input"] == counts["normalized"] + counts["rejected"]
    assert counts["normalized"] > 0
    assert sum(d["alerts"] for d in report["detectors"].values()) == counts["normalized"]
    truth = report["ground_truth"]
    assert truth["attack_intervals_within_alert_range"] == len(truth["attack_intervals"])
    if layout.event_labels is not None:
        events = truth["event_labels"]
        assert events["link_status"] == "linked", events
        assert events["rows_consumed"] == counts["total_input"]
