"""Run the Sigma engine on a dev scenario and score it as a dev detection baseline.

Two separate steps, so labels never touch the engine:

1. :func:`run_sigma_scenario` (no labels): the investigation-eligible alerts
   of ``<scenario>.alerts.jsonl`` (the same pool the study uses) are fed to
   :class:`~app.detection.sigma_engine.SigmaEngine`; it writes
   ``<scenario>.sigma.alerts.jsonl`` and ``<scenario>.sigma.report.json``
   (rule counts, skip reasons, per-rule hits, runtime).
2. :func:`sigma_dev_baseline` (labels via :func:`app.detection.labels.dev_labels`):
   verdict per pool alert = "some Sigma rule fired on its evidence";
   precision / recall / F1 / FNR by ``event_label`` (primary) and
   ``time_label`` (sensitivity). Labelled **dev detection baseline**: Sigma
   only sees lines another detector already alerted on, so this is a
   re-detection rate over the pool, not a detector comparison and not a
   paper result.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from app.alert_pipeline import iter_alert_file
from app.detection.labels import TruthLabels
from app.detection.sigma_coverage import rule_coverage
from app.detection.sigma_engine import RuleSet, SigmaEngine, SigmaRun, load_rules
from app.evaluation.metrics import triage_scores
from app.schemas.alert import INVESTIGATION_SELECTION, Alert
from app.study.config import StudyConfig
from app.study.variants import scores_dict

DEV_BASELINE_LABEL = "dev detection baseline (dev scenario, not a paper result)"


def run_sigma_scenario(processed_dir: str | Path, scenario: str, config: StudyConfig,
                       rules_root: str | Path, output_dir: str | Path | None) -> dict[str, Any]:
    config.split.require_dev(scenario)
    t0 = time.perf_counter()
    rules: RuleSet = load_rules(rules_root)
    t_rules = time.perf_counter() - t0
    engine = SigmaEngine(rules.compiled)
    alerts_path = Path(processed_dir) / f"{scenario}.alerts.jsonl"
    t1 = time.perf_counter()
    pool_ids: list[str] = []

    def pool() -> Iterator[Alert]:
        for a in iter_alert_file(alerts_path, INVESTIGATION_SELECTION):
            pool_ids.append(a.alert_id)
            yield a

    run = engine.run(pool())
    t_eval = time.perf_counter() - t1
    report: dict[str, Any] = {
        "scenario": scenario, "scenario_split": "dev",
        "note": ("Sigma rules evaluated over the evidence log lines of the investigation-eligible "
                 "alerts only (AIT-LDSv2 is not used); an additional platform detector, not a "
                 "study variable"),
        "rules": {"total": rules.total, "compiled": len(rules.compiled),
                  "skipped": sum(rules.skipped.values()),
                  "skipped_by_reason": dict(sorted(rules.skipped.items())),
                  "compiled_by_log_type": _count(r.log_type for r in rules.compiled)},
        "stats": run.stats,
        "rules_with_hits": sum(1 for v in run.per_rule.values() if v["hits"]),
        "per_rule": dict(sorted(run.per_rule.items(), key=lambda kv: (-kv[1]["hits"], kv[0]))),
        "skipped_rules": rules.skipped_rules,
        "coverage": rule_coverage(rules, run),
        "runtime_seconds": {"load_rules": round(t_rules, 2), "evaluate": round(t_eval, 2)},
    }
    if output_dir is not None:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        with (out / f"{scenario}.sigma.alerts.jsonl").open("w", encoding="utf-8") as handle:
            for a in run.alerts:
                handle.write(a.model_dump_json() + "\n")
        (out / f"{scenario}.sigma.report.json").write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    report["_pool_ids"] = pool_ids
    report["_run"] = run  # in memory only (not written): the CLI scores per-rule usefulness with labels
    report["_flagged_source_ids"] = sorted({str(a.evidence.source_alert_id) for a in run.alerts})
    return report


def _count(items: Any) -> dict[str, int]:
    out: dict[str, int] = {}
    for i in items:
        out[i] = out.get(i, 0) + 1
    return dict(sorted(out.items()))


def rule_usefulness(run: SigmaRun, labels: dict[str, TruthLabels]) -> dict[str, dict[str, Any]]:
    """Per matched rule: how many hits sit on source alerts with an attack event_label (dev only).

    Precision is over hits whose source alert has a verified event label; None when none has.
    A dev-scenario detection baseline number, never a detector comparison (Sigma re-detects).
    """
    out: dict[str, dict[str, Any]] = {}
    for hit in run.alerts:
        row = out.setdefault(str(hit.rule_id), {"hits": 0, "event_labelled": 0, "attack_event_label": 0})
        row["hits"] += 1
        lab = labels.get(str(hit.evidence.source_alert_id))
        if lab is not None and lab.event_attack is not None:
            row["event_labelled"] += 1
            row["attack_event_label"] += int(bool(lab.event_attack))
    for row in out.values():
        row["precision_event"] = (round(row["attack_event_label"] / row["event_labelled"], 4)
                                  if row["event_labelled"] else None)
    return out


def sigma_dev_baseline(pool_ids: list[str], flagged: set[str],
                       labels: dict[str, TruthLabels]) -> dict[str, Any]:
    """Verdict = pool alert flagged by some Sigma rule; scored by both labels."""
    missing = [a for a in pool_ids if a not in labels]
    if missing:
        raise ValueError(f"{len(missing)} pool alerts have no truth row (first: {missing[0]})")
    scored = [a for a in pool_ids if labels[a].event_attack is not None]
    event = triage_scores({a: a in flagged for a in scored},
                          {a: bool(labels[a].event_attack) for a in scored})
    time_ = triage_scores({a: a in flagged for a in pool_ids},
                          {a: labels[a].time_attack for a in pool_ids})
    return {"label": DEV_BASELINE_LABEL, "pool_alerts": len(pool_ids), "flagged": len(flagged),
            "event_label_unavailable": len(pool_ids) - len(scored),
            "event_label": scores_dict(event), "time_label": scores_dict(time_)}
