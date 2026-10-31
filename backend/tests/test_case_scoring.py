from pathlib import Path

import pytest

from app.evaluation.case_scoring import (
    alert_claim_index,
    alert_quote_index,
    flatten_record,
    score_case,
)
from app.evaluation.metrics import Claim
from app.ingestion.ground_truth import AttackTimeline
from app.study.cases import CaseKind, build_cases, case_alerts
from app.study.config import CaseConfig
from app.study.variants import AlertPool, build_variants
from tests.test_variants import S2, S4, W5, pool, processed  # noqa: F401  (fixtures)

CONFIG = CaseConfig(seed=7, padding_seconds=0, max_alerts=100, truncation="earliest",
                    benign_per_attack=1)


def views(pool: AlertPool, samples_dir: Path) -> dict[str, object]:  # noqa: F811
    timeline = AttackTimeline.from_labels_csv(
        samples_dir / "synthetic_ait_ads" / "synthetic_labels.csv", "synthetic")
    fused = build_variants(pool, seed=7, shuffled_references=())["fused"]
    return {c.case_id: (c, case_alerts(c, fused, max_alerts=100, truncation="earliest"))
            for c in build_cases(pool, timeline, CONFIG).cases}


def test_coverage_by_time_and_event_label(pool: AlertPool, samples_dir: Path) -> None:  # noqa: F811
    case, view = views(pool, samples_dir)["synthetic:attack:dirb"]  # type: ignore[misc]
    nothing = score_case(case, view, [])
    assert (nothing.coverage_time, nothing.coverage_event, nothing.load) == (0.0, 0.0, 3)
    s4_only = score_case(case, view, [S4])  # inside dirb by time, but no attack event label
    assert (s4_only.coverage_time, s4_only.coverage_event) == (1.0, 0.0)
    s2 = score_case(case, view, [S2])
    assert (s2.coverage_time, s2.coverage_event) == (1.0, 1.0)
    outside = score_case(case, view, [W5, "made-up"])  # not alerts of this case
    assert (outside.coverage_time, outside.cited, outside.cited_not_in_case) == (0.0, 2, 2)
    assert outside.unsupported_claim_rate is None  # no claims made


def test_benign_case_has_no_steps(pool: AlertPool, samples_dir: Path) -> None:  # noqa: F811
    for case, view in views(pool, samples_dir).values():  # type: ignore[misc]
        if case.kind is CaseKind.BENIGN:
            score = score_case(case, view, [e.alert_id for e in view.entries])
            assert score.coverage_time is None and score.coverage_event is None


def test_flatten_record() -> None:
    flat = flatten_record({"a": {"b": [1, "x", None, True]}, "c": 1.5, "d": None})
    assert flat == {"a.b.0": "1", "a.b.1": "x", "a.b.3": "true", "c": "1.5"}


def test_unsupported_claims_against_alert_record(pool: AlertPool, samples_dir: Path) -> None:  # noqa: F811
    case, view = views(pool, samples_dir)["synthetic:attack:network_scans"]  # type: ignore[misc]
    alerts = list(pool.alerts(build_variants(pool, seed=7, shuffled_references=())["fused"]))
    index = alert_claim_index(a for a in alerts if a.alert_id in {e.alert_id for e in view.entries})
    assert set(index) == {W5}
    record = index[W5]
    assert record["rule_id"] == "31101"
    assert record["raw_alert.agent.ip"] == "192.168.10.20"
    assert record["evidence.log_lines.0"].startswith("10.0.0.9 - - [14/Nov/2023:22:14:10")
    claims = [
        Claim.about_alert(W5, "rule_id", "31101"),                       # supported
        Claim.about_alert(W5, "raw_alert.agent.ip", " 192.168.10.20 "),  # supported (stripped)
        Claim.about_alert(W5, "evidence.log_lines.0", record["evidence.log_lines.0"]),  # raw line
        Claim.about_alert(W5, "host_ip", "10.0.0.1"),                    # wrong value
        Claim.about_alert(S2, "rule_id", "1:2000001:2"),                 # alert not in this case
    ]
    score = score_case(case, view, [W5], claims=claims, claim_index=index)
    assert score.unsupported_claim_rate == pytest.approx(2 / 5)
    assert score.claims == 5


def test_citation_precision(pool: AlertPool, samples_dir: Path) -> None:  # noqa: F811
    case, view = views(pool, samples_dir)["synthetic:attack:dirb"]  # type: ignore[misc]
    every = score_case(case, view, [e.alert_id for e in view.entries])  # s2, a2, s4
    assert (every.citation_precision_event, every.citation_precision_time) == (2 / 3, 1.0)
    assert (every.cited_event_attack, every.cited_in_phase) == (2, 3)
    # Ids outside the case count against precision: the agent cited something it never saw.
    half = score_case(case, view, [S2, "made-up", S2])  # duplicates are cited once
    assert (half.cited, half.citation_precision_event, half.citation_precision_time) == (2, 0.5, 0.5)
    none = score_case(case, view, [])
    assert none.citation_precision_event is None and none.citation_precision_time is None


def test_quote_claims_in_case_scoring(pool: AlertPool, samples_dir: Path) -> None:  # noqa: F811
    case, view = views(pool, samples_dir)["synthetic:attack:network_scans"]  # type: ignore[misc]
    alerts = [a for a in pool.alerts(build_variants(pool, seed=7, shuffled_references=())["fused"])
              if a.alert_id == W5]
    quotes = alert_quote_index(alerts)
    assert quotes[W5][0].startswith("10.0.0.9 - - [14/Nov")
    claims = [Claim.quote(W5, '"GET /synthetic-probe HTTP/1.1"'), Claim.quote(W5, "get /synthetic")]
    score = score_case(case, view, [W5], claims=claims, claim_index=alert_claim_index(alerts),
                       quote_index=quotes)
    assert (score.claims, score.unsupported_claims, score.unsupported_claim_rate) == (2, 1, 0.5)
