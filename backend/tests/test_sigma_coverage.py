"""C5 (2026-11-15): per-rule Sigma coverage funnel. SYNTHETIC rules and log lines only.

compiled -> applicable (the evidence holds events of the rule's log type) -> evaluated (events
were checked) -> matched (hits) -> useful (hits whose source alert carries an attack event_label;
dev scenarios only, via the label door). Skipped rules keep their counted reason.
"""

from __future__ import annotations

from pathlib import Path

from app.detection import sigma_engine as se
from app.detection.sigma_coverage import AVAILABLE_FIELDS, rule_coverage
from app.detection.sigma_report import rule_usefulness
from app.detection.labels import TruthLabels
from tests.test_sigma_engine import ACCESS, APACHE, SYSLOG, WEB, make_alert, write_rule


def setup(tmp_path: Path) -> tuple[se.RuleSet, se.SigmaRun]:
    write_rule(tmp_path, "get", WEB + "detection:\n  sel:\n    cs-method: GET\n  condition: sel\n")
    write_rule(tmp_path, "post", WEB + "detection:\n  sel:\n    cs-method: POST\n  condition: sel\n")
    write_rule(tmp_path, "audit", "logsource:\n  product: linux\n  service: auditd\n"
               "detection:\n  sel:\n    type: EXECVE\n  condition: sel\n")
    write_rule(tmp_path, "proc", "logsource:\n  product: linux\n  category: process_creation\n"
               "detection:\n  sel:\n    Image|endswith: /bash\n  condition: sel\n")
    rules = se.load_rules(tmp_path)
    run = se.SigmaEngine(rules.compiled).run([make_alert([APACHE], [ACCESS], "a"),
                                              make_alert([SYSLOG], ["/var/log/auth.log"], "b")])
    return rules, run


def test_funnel_and_rows(tmp_path: Path) -> None:
    rules, run = setup(tmp_path)
    cov = rule_coverage(rules, run)
    assert cov["funnel"] == {"rules": 4, "compiled": 3, "applicable": 2, "evaluated": 2,
                             "matched": 1, "skipped": 1}
    rows = {r["file"].rsplit("/", 1)[-1]: r for r in cov["rules"]}
    assert rows["get.yml"]["status"] == "matched" and rows["get.yml"]["matches"] == 1
    assert rows["get.yml"]["required_fields"] == ["cs-method"]
    assert rows["get.yml"]["available_fields"] == sorted(AVAILABLE_FIELDS["apache_access"])
    assert rows["post.yml"]["status"] == "evaluated_no_match" and rows["post.yml"]["events_evaluated"] == 1
    assert rows["audit.yml"]["status"] == "no_events_of_log_type"
    assert rows["audit.yml"]["reason"] == "the evidence holds no auditd lines"
    assert rows["proc.yml"]["status"] == "skipped"
    assert rows["proc.yml"]["reason"] == "logsource_not_derivable:process_creation"
    assert "re-detection" in cov["note"]


def test_usefulness_uses_event_labels_of_the_source_alerts(tmp_path: Path) -> None:
    rules, run = setup(tmp_path)
    labels = {"a": TruthLabels(time_attack=True, event_attack=True),
              "b": TruthLabels(time_attack=False, event_attack=False)}
    use = rule_usefulness(run, labels)
    (row,) = use.values()
    assert row == {"hits": 1, "event_labelled": 1, "attack_event_label": 1, "precision_event": 1.0}
    labels["a"] = TruthLabels(time_attack=True, event_attack=None)
    (row,) = rule_usefulness(run, labels).values()
    assert row["event_labelled"] == 0 and row["precision_event"] is None
