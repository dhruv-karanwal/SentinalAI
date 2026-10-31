import json
from pathlib import Path

import pytest

from app.ingestion.mappings import AIT_ADS_SCENARIOS
from app.study.config import (
    DEFAULT_STUDY_CONFIG,
    HeldOutScenarioError,
    StudyConfig,
    load_study_config,
)
from app.study.variants import dev_triage_report

HELD_OUT = ("fox", "harrison", "santos", "wardbeck", "wheeler", "wilson")


def test_committed_split_is_the_frozen_decision() -> None:
    config = load_study_config()
    assert DEFAULT_STUDY_CONFIG.name == "study.json"
    assert config.split.dev == ("russellmitchell", "shaw")
    assert config.split.held_out == HELD_OUT
    assert config.split.frozen
    assert set(config.split.dev) | set(config.split.held_out) == set(AIT_ADS_SCENARIOS)
    assert config.sampling.sample_size == 20
    assert config.sampling.stratify == "proportional"
    assert config.random_reference == ("fused",)


@pytest.mark.parametrize("scenario", HELD_OUT)
def test_held_out_scenario_is_refused_by_dev_only_code(scenario: str, tmp_path: Path) -> None:
    config = load_study_config()
    with pytest.raises(HeldOutScenarioError, match=scenario):
        config.split.require_dev(scenario)
    # The guard runs before any file is touched, so missing inputs cannot mask it.
    with pytest.raises(HeldOutScenarioError):
        dev_triage_report(tmp_path, scenario, config)


def test_unknown_scenario_is_refused() -> None:
    with pytest.raises(ValueError, match="not in the study split"):
        load_study_config().split.require_dev("nope")


def write_config(tmp_path: Path, **changes: object) -> Path:
    data = json.loads(DEFAULT_STUDY_CONFIG.read_text(encoding="utf-8"))
    for dotted, value in changes.items():
        section, key = dotted.split("__")
        data[section][key] = value
    path = tmp_path / "study.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"split__dev": ["fox", "shaw"]}, "both dev and held_out"),
        ({"split__dev": []}, "dev"),
        ({"split__frozen": "yes"}, "frozen"),
        ({"sampling__sample_size": 0}, "sample_size"),
        ({"sampling__stratify": "balanced"}, "stratify"),
        ({"sampling__seed": "1"}, "seed"),
        ({"variants__random_reference": ["nope"]}, "random_reference"),
    ],
)
def test_bad_config_raises(tmp_path: Path, changes: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        load_study_config(write_config(tmp_path, **changes))


def test_config_is_immutable() -> None:
    config = load_study_config()
    assert isinstance(config, StudyConfig)
    with pytest.raises(AttributeError):
        config.split.dev = ("fox",)  # type: ignore[misc]
