import pytest

from app.evaluation.metrics import (
    Claim,
    attack_step_coverage,
    triage_scores,
    unsupported_claim_rate,
)


def test_triage_counts_and_scores() -> None:
    truth = {"a": True, "b": True, "c": False, "d": False}
    pred = {"a": True, "b": False, "c": True, "d": False}
    s = triage_scores(pred, truth)
    assert (s.tp, s.fp, s.fn, s.tn) == (1, 1, 1, 1)
    assert s.precision == 0.5 and s.recall == 0.5 and s.f1 == 0.5
    assert s.false_negative_rate == 0.5


def test_triage_undefined_when_no_positives() -> None:
    s = triage_scores({"a": False}, {"a": False})
    assert s.precision is None and s.recall is None and s.f1 is None


def test_triage_rejects_mismatched_ids() -> None:
    with pytest.raises(ValueError):
        triage_scores({"a": True}, {"b": True})


def test_step_coverage() -> None:
    steps = {"recon": {"e1", "e2"}, "exploit": {"e3"}, "exfil": {"e4"}}
    assert attack_step_coverage(steps, ["e2", "e3", "zzz"]) == pytest.approx(2 / 3)
    assert attack_step_coverage({}, ["e1"]) is None


def test_unsupported_claims() -> None:
    logs = {"e1": {"src_ip": "10.0.0.1"}, "e2": {"src_ip": "10.0.0.2"}}
    claims = [
        Claim("e1", "src_ip", "10.0.0.1"),   # supported
        Claim("e2", "src_ip", "10.0.0.9"),   # wrong value
        Claim("e9", "src_ip", "10.0.0.1"),   # unknown event
        Claim("e1", "dst_ip", "10.0.0.5"),   # unknown field
    ]
    assert unsupported_claim_rate(claims, logs) == 0.75
    assert unsupported_claim_rate([], logs) is None


def test_claim_record_id_is_generic_and_backward_compatible() -> None:
    claim = Claim("alert-1", "rule.id", "52507")
    assert claim.record_id == "alert-1" and claim.event_id == "alert-1"
    assert Claim.about_alert("alert-1", "rule.id", "52507") == claim
    assert unsupported_claim_rate([claim], {"alert-1": {"rule.id": "52507"}}) == 0.0
