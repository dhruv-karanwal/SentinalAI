"""The one door from the detection layer to ground truth (Waves B2-B4).

Why one function: labels must never reach detection code, features, agent
tools or prompts. Every detection-layer use of labels (Sigma dev baseline,
ML training targets and evaluation) goes through :func:`dev_labels`, which

- refuses a held-out scenario (``require_dev``) before reading anything, and
- reads only the separate truth area (``TruthStore``), filled by
  ``platform-ingest``.

The leak tests list the modules that may import this one
(``LABEL_READERS`` in tests/test_detection_labels.py); the Sigma engine, the
triage code path and the ML feature builder are not among them.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.storage.repository import TruthStore
from app.study.config import StudyConfig


@dataclass(frozen=True)
class TruthLabels:
    """``event_attack``: None when no verified event label exists for the alert.

    ``phase``: the labels.csv attack phase whose interval holds the alert
    (``time_label``), None outside every interval. Used only to build
    leave-one-phase-out folds and per-phase scores (B4), never as a feature.
    """

    event_attack: bool | None
    time_attack: bool
    phase: str | None = None


class MissingTruthError(Exception):
    """The truth area holds no rows for the scenario (run platform-ingest first)."""


def dev_labels(truth: TruthStore, scenario: str, config: StudyConfig) -> dict[str, TruthLabels]:
    """alert_id -> labels for one dev scenario, from the truth area only."""
    config.split.require_dev(scenario)
    rows = truth.for_scenario(scenario)
    if not rows:
        raise MissingTruthError(f"no ground truth for {scenario!r} in the truth area; "
                                f"run platform-ingest --scenario {scenario} first")
    out: dict[str, TruthLabels] = {}
    for r in rows:
        available = bool(r["event_label_available"])
        event = (r["event_label"] is not None) if available else None
        inside = r["time_label"] != "false_positive"
        out[str(r["alert_id"])] = TruthLabels(event, inside, str(r["time_label"]) if inside else None)
    return out
