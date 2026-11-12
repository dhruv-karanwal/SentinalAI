"""Statistics for the final study: paired bootstrap, Holm, effect sizes, paired export."""

from __future__ import annotations

import csv
import math
from pathlib import Path

import pytest

from app.study.stats import (
    PairedComparison,
    StatisticsConfig,
    compare_family,
    effect_sizes,
    holm,
    paired_bootstrap,
    write_paired_csv,
)


def test_identical_arms_give_zero_difference() -> None:
    a = [1.0, 0.0, 1.0, 1.0, 0.0, 0.5]
    res = paired_bootstrap(a, list(a), seed=7, resamples=2000)
    assert res.difference == 0.0
    assert res.ci_low == 0.0 and res.ci_high == 0.0
    assert res.p_value == 1.0
    assert res.n == 6


def test_constant_shift_gives_that_shift() -> None:
    a = [0.1, 0.4, 0.2, 0.9, 0.3]
    b = [x + 0.25 for x in a]
    res = paired_bootstrap(a, b, seed=7, resamples=2000)
    assert res.difference == pytest.approx(0.25)
    assert res.ci_low == pytest.approx(0.25) and res.ci_high == pytest.approx(0.25)
    assert res.p_value < 0.01  # every resample is on the same side of zero


def test_bootstrap_is_seeded_and_deterministic() -> None:
    a = [0.0, 1.0, 0.0, 1.0, 1.0, 0.0, 0.0, 1.0]
    b = [1.0, 1.0, 0.0, 1.0, 0.0, 1.0, 1.0, 1.0]
    r1 = paired_bootstrap(a, b, seed=11, resamples=3000)
    r2 = paired_bootstrap(a, b, seed=11, resamples=3000)
    assert r1 == r2
    assert r1.ci_low <= r1.difference <= r1.ci_high


def test_none_pairs_are_dropped_and_counted() -> None:
    res = paired_bootstrap([1.0, None, 0.0], [1.0, 1.0, None], seed=1, resamples=100)
    assert res.n == 1 and res.dropped_pairs == 2


def test_stratified_resampling_keeps_strata_sizes() -> None:
    a = [0.0, 0.0, 1.0, 1.0]
    b = [1.0, 1.0, 1.0, 1.0]
    res = paired_bootstrap(a, b, seed=3, resamples=500, strata=["x", "x", "y", "y"])
    # stratum x always shifts by 1, stratum y by 0: the mean difference is always 0.5
    assert res.ci_low == pytest.approx(0.5) and res.ci_high == pytest.approx(0.5)


def test_length_mismatch_is_an_error() -> None:
    with pytest.raises(ValueError):
        paired_bootstrap([1.0], [1.0, 0.0], seed=1)


def test_holm_hand_computed_example() -> None:
    # p sorted: 0.01 (x4 = 0.04), 0.02 (x3 = 0.06), 0.03 (x2 = 0.06 by monotonicity), 0.5 (x1)
    adjusted = holm({"a": 0.03, "b": 0.01, "c": 0.5, "d": 0.02})
    assert adjusted["b"] == pytest.approx(0.04)
    assert adjusted["d"] == pytest.approx(0.06)
    assert adjusted["a"] == pytest.approx(0.06)
    assert adjusted["c"] == pytest.approx(0.5)


def test_holm_caps_at_one_and_handles_empty() -> None:
    assert holm({}) == {}
    assert holm({"a": 0.6, "b": 0.7}) == {"a": 1.0, "b": 1.0}


def test_effect_sizes() -> None:
    e = effect_sizes([0.0, 0.0, 1.0, 1.0], [1.0, 0.0, 1.0, 1.0])
    assert e["mean_difference"] == pytest.approx(0.25)
    # differences 1, 0, 0, 0: sd (n-1) = 0.5 -> d_z = 0.5
    assert e["cohens_dz"] == pytest.approx(0.5)
    assert e["discordant_b_better"] == 1 and e["discordant_a_better"] == 0
    flat = effect_sizes([1.0, 1.0], [1.0, 1.0])
    assert flat["cohens_dz"] is None


def test_compare_family_applies_holm(tmp_path: Path) -> None:
    config = StatisticsConfig(seed=5, resamples=1000, confidence=0.95, family=(
        PairedComparison("arm", "coverage_event", ("v", "single+verifier"), ("v", "graph+verifier")),
        PairedComparison("same", "coverage_event", ("v", "single+verifier"), ("v", "single+verifier")),
    ))
    rows = [
        {"variant": "v", "arm": arm, "case_key": f"c{i}", "scenario": "s", "coverage_event": val}
        for i in range(8)
        for arm, val in (("single+verifier", float(i % 2)), ("graph+verifier", 1.0))
    ]
    out = compare_family(rows, config)
    by_name = {r["name"]: r for r in out}
    assert by_name["same"]["difference"] == 0.0
    assert by_name["arm"]["difference"] == pytest.approx(0.5)
    assert by_name["arm"]["p_holm"] >= by_name["arm"]["p_value"]
    assert all(not math.isnan(r["p_holm"]) for r in out)


def test_paired_csv_export(tmp_path: Path) -> None:
    rows = [{"scenario": "s", "variant": "v", "arm": "single", "case_key": "c1", "coverage_event": 1.0}]
    path = write_paired_csv(rows, tmp_path / "paired.csv")
    with path.open(encoding="utf-8") as fh:
        got = list(csv.DictReader(fh))
    assert got == [{"scenario": "s", "variant": "v", "arm": "single", "case_key": "c1",
                    "coverage_event": "1.0"}]
