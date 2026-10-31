import pytest

from app.evaluation.metrics import (
    Claim,
    attack_step_coverage,
    triage_scores,
    unsupported_claim_rate,
    unsupported_claims,
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


def test_claim_kinds() -> None:
    assert Claim("a1", "f", "v").kind == "field_value"
    assert Claim.quote("a1", "Failed password").kind == "quote"
    with pytest.raises(ValueError, match="kind"):
        Claim("a1", "f", "v", kind="fuzzy")


def test_quote_claims_are_exact_case_sensitive_substrings() -> None:
    lines = {"a1": ["Jan 1 sshd[1]: Failed password for root from 10.0.0.1"]}
    claims = [
        Claim.quote("a1", "Failed password for root"),   # supported
        Claim.quote("a1", " Failed password"),           # supported: the space is in the line
        Claim.quote("a1", "failed password for root"),   # case differs
        Claim.quote("a1", "Failed  password"),           # no whitespace normalization
        Claim.quote("a1", "root fr"),                    # shorter than 8 characters
        Claim.quote("a9", "Failed password for root"),   # unknown record
    ]
    assert unsupported_claims(claims, {}, quote_index=lines) == (4, 6)
    assert unsupported_claim_rate(claims, {}, quote_index=lines) == pytest.approx(4 / 6)
    # Without a quote index every quote is unsupported; field claims are unaffected.
    assert unsupported_claim_rate([Claim.quote("a1", "Failed password")], {}) == 1.0
    mixed = [Claim("a1", "rule.id", "5"), Claim.quote("a1", "Failed password")]
    assert unsupported_claim_rate(mixed, {"a1": {"rule.id": "5"}}, quote_index=lines) == 0.0
