"""Deterministic baseline citers on the synthetic sample.

Fused case alerts: network_scans -> [w5 (wazuh, level 5)];
dirb -> [s2 (suricata), a2 (aminer), s4 (suricata, fast.log unmatched)].
"""

from pathlib import Path

import pytest

from app.evaluation.metrics import unsupported_claim_rate
from app.evaluation.case_scoring import alert_claim_index, alert_quote_index
from app.ingestion.ground_truth import AttackTimeline
from app.study.baselines import BASELINE_NAMES, baseline_citations, baseline_claims
from app.study.cases import build_cases, case_alerts
from app.study.config import BaselineConfig, CaseConfig
from app.study.variants import AlertPool, build_variants
from tests.test_variants import S2, S4, W5, aminer_id, pool, processed  # noqa: F401  (fixtures)

CASES = CaseConfig(seed=7, padding_seconds=0, max_alerts=100, truncation="spread", benign_per_attack=1)
TOP1 = BaselineConfig(top_k=1, detector_order=("aminer", "wazuh", "suricata"), quote_chars=60)


def views(pool: AlertPool, samples_dir: Path) -> dict[str, object]:  # noqa: F811
    timeline = AttackTimeline.from_labels_csv(
        samples_dir / "synthetic_ait_ads" / "synthetic_labels.csv", "synthetic")
    fused = build_variants(pool, seed=7, shuffled_references=())["fused"]
    return {c.case_id: case_alerts(c, fused, max_alerts=100, truncation="spread")
            for c in build_cases(pool, timeline, CASES).cases}


def test_baseline_rules(pool: AlertPool, samples_dir: Path) -> None:  # noqa: F811
    v = views(pool, samples_dir)
    dirb, scans = v["synthetic:attack:dirb"], v["synthetic:attack:network_scans"]
    a2 = aminer_id(pool)
    cite = lambda name, view: baseline_citations(name, view, TOP1)  # noqa: E731
    assert BASELINE_NAMES == ("cite-all", "cite-none", "cite-top-k-wazuh-level",
                              "cite-top-k-detector-order", "cite-aminer-only")
    assert cite("cite-all", dirb) == [S2, a2, S4]
    assert cite("cite-none", dirb) == []
    # No Wazuh alert in dirb: the level ranking falls back to the rest in time order.
    assert cite("cite-top-k-wazuh-level", dirb) == [S2]
    assert cite("cite-top-k-wazuh-level", scans) == [W5]
    assert cite("cite-top-k-detector-order", dirb) == [a2]   # aminer before suricata
    assert cite("cite-top-k-detector-order", scans) == [W5]
    assert cite("cite-aminer-only", dirb) == [a2]
    assert cite("cite-aminer-only", scans) == []
    wide = BaselineConfig(top_k=10, detector_order=("suricata", "wazuh", "aminer"), quote_chars=60)
    assert baseline_citations("cite-top-k-detector-order", dirb, wide) == [S2, S4, a2]  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="baseline"):
        cite("cite-everything", dirb)


def test_wazuh_level_ranking_orders_by_level_then_time(pool: AlertPool, samples_dir: Path) -> None:  # noqa: F811
    from app.study.baselines import _wazuh_level_key

    entries = [e for e in pool.entries if e.detector.value == "wazuh"]  # w1 (level 3), w5 (level 5)
    assert sorted(entries, key=_wazuh_level_key)[0].alert_id == W5


def test_baseline_claims_are_supported_by_the_records(pool: AlertPool, samples_dir: Path) -> None:  # noqa: F811
    alerts = list(pool.alerts(build_variants(pool, seed=7, shuffled_references=())["fused"]))
    claims = baseline_claims(alerts, quote_chars=60)
    kinds = {c.kind for c in claims}
    assert kinds == {"field_value", "quote"}
    # Every alert gets a field claim; only alerts with a raw log line of >= 8 chars get a quote.
    assert sum(c.kind == "field_value" for c in claims) == len(alerts)
    assert sum(c.kind == "quote" for c in claims) == sum(
        bool(a.evidence.log_lines) and len(a.evidence.log_lines[0]) >= 8 for a in alerts)
    rate = unsupported_claim_rate(claims, alert_claim_index(alerts), quote_index=alert_quote_index(alerts))
    assert rate == 0.0
