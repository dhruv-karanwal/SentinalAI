"""Descriptive dev check for B3 incidents: which attack phases does an incident overlap in time?

This is the ONLY B3 code that reads labels (``labels.csv`` attack-phase
intervals, via ``AttackTimeline``); the triage code path
(:mod:`app.detection.triage`) never does. It runs after incidents are built
and only reports, it changes nothing.

Overlap is by time alone: incident ``[first_ts, last_ts]`` (closed)
overlaps phase ``[start, end)`` when ``first_ts < end`` and
``last_ts >= start``. A long incident on a busy host can overlap a phase
without containing any attack alert, so this is a **descriptive dev check**
(dev scenario, not a paper result), not a detection score.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from app.ingestion.ground_truth import AttackTimeline
from app.study.config import StudyConfig

CHECK_LABEL = "descriptive dev check (dev scenario, not a paper result)"


def phase_overlap(incidents: list[dict[str, Any]], labels_path: str | Path, scenario: str,
                  config: StudyConfig) -> dict[str, Any]:
    config.split.require_dev(scenario)
    timeline = AttackTimeline.from_labels_csv(labels_path, scenario)
    spans = [(datetime.fromisoformat(str(i["first_ts"])), datetime.fromisoformat(str(i["last_ts"])),
              i) for i in incidents]
    phases = []
    for iv in timeline.intervals:
        hits = [i for first, last, i in spans if first < iv.end and last >= iv.start]
        phases.append({"phase": iv.attack, "start": iv.start.isoformat(), "end": iv.end.isoformat(),
                       "overlapping_incidents": len(hits),
                       "overlapping_by_severity": _by_severity(hits)})
    return {"label": CHECK_LABEL, "scenario": scenario, "phases": len(phases),
            "phases_overlapped": sum(1 for p in phases if p["overlapping_incidents"]),
            "per_phase": phases}


def _by_severity(incidents: list[dict[str, Any]]) -> dict[str, int]:
    out: dict[str, int] = {}
    for i in incidents:
        out[i["severity"]] = out.get(i["severity"], 0) + 1
    return dict(sorted(out.items()))
