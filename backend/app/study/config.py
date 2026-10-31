"""Study configuration: the frozen dev/held-out split and sampling defaults.

The split lives in ``experiments/config/study.json`` so it is versioned with
the code and cannot drift between scripts. Held-out scenarios are frozen:
any function meant for development (looking at scores, tuning, debugging
the sampler) must call :meth:`ScenarioSplit.require_dev` first, which
raises :class:`HeldOutScenarioError` for a held-out scenario. Building
alert variants is not itself dev-only; looking at their scores is.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_STUDY_CONFIG = Path(__file__).resolve().parents[3] / "experiments" / "config" / "study.json"

STRATIFY_CHOICES = ("proportional", "none")
# Variants a random control can be matched to (see app.study.variants).
RANDOM_REFERENCE_CHOICES = ("wazuh", "suricata", "aminer", "fused", "oracle")


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
class SamplingConfig:
    seed: int
    sample_size: int
    variant: str
    stratify: str


@dataclass(frozen=True)
class StudyConfig:
    split: ScenarioSplit
    sampling: SamplingConfig
    random_reference: tuple[str, ...]
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


def load_study_config(path: str | Path = DEFAULT_STUDY_CONFIG) -> StudyConfig:
    config_path = Path(path)
    data = json.loads(config_path.read_text(encoding="utf-8"))
    split_data, sampling_data, variants_data = data["split"], data["sampling"], data["variants"]

    dev = _names(split_data["dev"], "split.dev")
    held_out = _names(split_data["held_out"], "split.held_out", allow_empty=True)
    both = set(dev) & set(held_out)
    if both:
        raise ValueError(f"scenarios in both dev and held_out: {', '.join(sorted(both))}")
    frozen = split_data["frozen"]
    if not isinstance(frozen, bool):
        raise ValueError("split.frozen must be true or false")

    stratify = sampling_data["stratify"]
    if stratify not in STRATIFY_CHOICES:
        raise ValueError(f"sampling.stratify must be one of {', '.join(STRATIFY_CHOICES)}")
    references = _names(variants_data["random_reference"], "variants.random_reference")
    unknown = [r for r in references if r not in RANDOM_REFERENCE_CHOICES]
    if unknown:
        raise ValueError(f"variants.random_reference: unknown variant(s) {', '.join(unknown)}")
    if variants_data.get("selection") != "investigation":
        raise ValueError("variants.selection must be 'investigation'")
    variant = sampling_data["variant"]
    if variant not in RANDOM_REFERENCE_CHOICES:
        raise ValueError(f"sampling.variant: unknown variant {variant!r}")

    return StudyConfig(
        split=ScenarioSplit(dev, held_out, frozen, split_data.get("frozen_on")),
        sampling=SamplingConfig(
            seed=_int(sampling_data["seed"], "sampling.seed", 0),
            sample_size=_int(sampling_data["sample_size"], "sampling.sample_size", 1),
            variant=variant,
            stratify=stratify,
        ),
        random_reference=references,
        source=config_path.name,
    )
