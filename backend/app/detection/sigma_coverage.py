"""Per-rule Sigma coverage funnel (C5, 2026-11-15). Label-free.

Why: "2 of 90 rules fired" mixes several causes. This report separates them per rule:

- **compiled**: the rule's log source and fields map onto a log type these logs carry
  (otherwise ``skipped`` with the counted reason from :func:`sigma_engine.load_rules`);
- **applicable**: the evidence actually holds events of that log type (and program, for
  service rules); a compiled auditd rule is not applicable when no alert carries an audit line;
- **evaluated**: events were checked against the rule (``events_evaluated`` > 0);
- **matched**: at least one hit;
- usefulness (hits on attack-labelled source alerts) needs labels and lives in
  :func:`app.detection.sigma_report.rule_usefulness` (dev scenarios only).

Scope caveat, printed in every report: Sigma sees only log lines that Wazuh or AMiner already
alerted on (AIT-LDSv2, the full logs, is not used: user decision 2026-10-31). A rule that cannot
match is often a rule whose behaviour no other detector alerted on, not a broken rule.
"""

from __future__ import annotations

from typing import Any

from app.detection.sigma_engine import WEBSERVER_FIELDS, RuleSet, SigmaRun

AVAILABLE_FIELDS: dict[str, frozenset[str]] = {
    "apache_access": WEBSERVER_FIELDS,
    "auditd": frozenset({"<any key=value pair of the audit record>"}),
    "syslog": frozenset({"<whole line: keywords only>"}),
    "apache_error": frozenset({"<whole line: keywords only>"}),
}
NOTE = ("Sigma evaluated over the evidence log lines of alerts only (re-detection over lines another "
        "detector already alerted on; AIT-LDSv2 is not used). 'skipped' rules need fields or log "
        "sources these logs do not carry; 'no_events_of_log_type' rules compiled but the evidence "
        "holds no line of their type.")


def rule_coverage(rules: RuleSet, run: SigmaRun) -> dict[str, Any]:
    present = set(run.stats.get("events_by_log_type", {}))
    rows: list[dict[str, Any]] = []
    for r in rules.compiled:
        stats = run.per_rule.get(r.rule_id, {"events_evaluated": 0, "hits": 0})
        evaluated, hits = int(stats["events_evaluated"]), int(stats["hits"])
        if hits:
            status, reason = "matched", None
        elif evaluated:
            status, reason = "evaluated_no_match", "no evaluated event satisfied the condition"
        elif r.log_type not in present:
            status, reason = "no_events_of_log_type", f"the evidence holds no {r.log_type} lines"
        else:
            status, reason = "no_events_of_log_type", f"no {r.log_type} line from program {r.program}"
        rows.append({"file": r.path, "rule_id": r.rule_id, "title": r.title, "level": r.level,
                     "log_type": r.log_type, "program": r.program,
                     "required_fields": list(r.fields),
                     "available_fields": sorted(AVAILABLE_FIELDS.get(r.log_type, frozenset())),
                     "compatibility": "compatible", "status": status, "reason": reason,
                     "events_evaluated": evaluated, "matches": hits})
    for s in rules.skipped_rules:
        rows.append({"file": s["path"], "rule_id": None, "title": None, "level": None,
                     "log_type": None, "program": None, "required_fields": [], "available_fields": [],
                     "compatibility": "incompatible", "status": "skipped", "reason": s["reason"],
                     "events_evaluated": 0, "matches": 0})
    compiled = [x for x in rows if x["compatibility"] == "compatible"]
    funnel = {"rules": rules.total, "compiled": len(compiled),
              "applicable": sum(1 for x in compiled if x["status"] != "no_events_of_log_type"),
              "evaluated": sum(1 for x in compiled if x["events_evaluated"] > 0),
              "matched": sum(1 for x in compiled if x["matches"] > 0),
              "skipped": len(rules.skipped_rules)}
    by_status: dict[str, int] = {}
    for x in rows:
        by_status[x["status"]] = by_status.get(x["status"], 0) + 1
    rows.sort(key=lambda x: (-x["matches"], -x["events_evaluated"], x["status"], x["file"]))
    return {"note": NOTE, "funnel": funnel, "by_status": dict(sorted(by_status.items())),
            "log_types_in_evidence": sorted(present), "rules": rows}
