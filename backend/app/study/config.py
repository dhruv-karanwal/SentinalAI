"""Study configuration: the frozen dev/held-out split, variants and cases.

The configuration lives in ``experiments/config/study.json`` so it is
versioned with the code and cannot drift between scripts. Held-out
scenarios are frozen: any function meant for development (looking at
scores or ceilings, tuning, debugging) must call
:meth:`ScenarioSplit.require_dev` first, which raises
:class:`HeldOutScenarioError` for a held-out scenario.

History: the M3 per-variant 20-alert study sample was retired in M4 in
favour of case-based units (``cases``); see docs/research-methodology.md.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_STUDY_CONFIG = Path(__file__).resolve().parents[3] / "experiments" / "config" / "study.json"

# Variants a random control can be matched to (see app.study.variants).
RANDOM_REFERENCE_CHOICES = ("wazuh", "suricata", "aminer", "fused", "oracle")
TRUNCATION_CHOICES = ("earliest",)


class HeldOutScenarioError(Exception):
    """A held-out (frozen) scenario was passed to dev-only code."""


@dataclass(frozen=True)
class ScenarioSplit:
    dev: tuple[str, ...]
    held_out: tuple[str, ...]
    frozen: bool
    frozen_on: str | None

    def require_dev(self, scenario: str) -> str:
        if scenario in self.held_out:
            raise HeldOutScenarioError(
                f"scenario {scenario!r} is held out and frozen; dev-only code may use only "
                f"{', '.join(self.dev)}")
        if scenario not in self.dev:
            raise ValueError(f"scenario {scenario!r} is not in the study split")
        return scenario


@dataclass(frozen=True)
class CaseConfig:
    """How cases are built (see app.study.cases)."""

    seed: int
    padding_seconds: int
    max_alerts: int
    truncation: str
    benign_per_attack: int


@dataclass(frozen=True)
class StudyConfig:
    split: ScenarioSplit
    variant_seed: int
    random_reference: tuple[str, ...]
    manifest_only_random_reference: tuple[str, ...]
    cases: CaseConfig
    source: str


def _names(value: Any, field: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise ValueError(f"{field} must be a list of names")
    if not value and not allow_empty:
        raise ValueError(f"{field} must not be empty")
    if len(set(value)) != len(value):
        raise ValueError(f"{field} has repeated names")
    return tuple(value)


def _int(value: Any, field: str, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{field} must be an integer >= {minimum}, got {value!r}")
    return value


def _references(value: Any, field: str) -> tuple[str, ...]:
    references = _names(value, field, allow_empty=True)
    unknown = [r for r in references if r not in RANDOM_REFERENCE_CHOICES]
    if unknown:
        raise ValueError(f"{field}: unknown variant(s) {', '.join(unknown)}")
    return references


def load_study_config(path: str | Path = DEFAULT_STUDY_CONFIG) -> StudyConfig:
    config_path = Path(path)
    data = json.loads(config_path.read_text(encoding="utf-8"))
    split_data, variants_data, cases_data = data["split"], data["variants"], data["cases"]

    dev = _names(split_data["dev"], "split.dev")
    held_out = _names(split_data["held_out"], "split.held_out", allow_empty=True)
    both = set(dev) & set(held_out)
    if both:
        raise ValueError(f"scenarios in both dev and held_out: {', '.join(sorted(both))}")
    frozen = split_data["frozen"]
    if not isinstance(frozen, bool):
        raise ValueError("split.frozen must be true or false")

    if variants_data.get("selection") != "investigation":
        raise ValueError("variants.selection must be 'investigation'")
    references = _references(variants_data["random_reference"], "variants.random_reference")
    manifest_only = _references(variants_data.get("manifest_only_random_reference", []),
                                "variants.manifest_only_random_reference")
    overlap = set(references) & set(manifest_only)
    if overlap:
        raise ValueError(f"random references in both lists: {', '.join(sorted(overlap))}")

    truncation = cases_data["truncation"]
    if truncation not in TRUNCATION_CHOICES:
        raise ValueError(f"cases.truncation must be one of {', '.join(TRUNCATION_CHOICES)}")

    return StudyConfig(
        split=ScenarioSplit(dev, held_out, frozen, split_data.get("frozen_on")),
        variant_seed=_int(variants_data["seed"], "variants.seed", 0),
        random_reference=references,
        manifest_only_random_reference=manifest_only,
        cases=CaseConfig(
            seed=_int(cases_data["seed"], "cases.seed", 0),
            padding_seconds=_int(cases_data["padding_seconds"], "cases.padding_seconds", 0),
            max_alerts=_int(cases_data["max_alerts"], "cases.max_alerts", 1),
            truncation=truncation,
            benign_per_attack=_int(cases_data["benign_per_attack"], "cases.benign_per_attack", 1),
        ),
        source=config_path.name,
    )
