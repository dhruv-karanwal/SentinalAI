import json
from pathlib import Path

import pytest

from app.ingestion.mappings import AIT_ADS_SCENARIOS
from app.study.cases import dev_case_report
from app.study.config import (
    DEFAULT_STUDY_CONFIG,
    HeldOutScenarioError,
    StudyConfig,
    load_study_config,
)
from app.study.variants import dev_triage_report

HELD_OUT = ("fox", "harrison", "santos", "wardbeck", "wheeler", "wilson")


def test_committed_config_is_the_frozen_decision() -> None:
    config = load_study_config()
    assert DEFAULT_STUDY_CONFIG.name == "study.json"
    assert config.split.dev == ("russellmitchell", "shaw")
    assert config.split.held_out == HELD_OUT
    assert config.split.frozen
    assert set(config.split.dev) | set(config.split.held_out) == set(AIT_ADS_SCENARIOS)
    assert config.shuffled_reference == ("wazuh", "suricata", "aminer")
    assert config.manifest_only_shuffled_reference == ("fused",)
    assert config.noise_reference == ("wazuh", "suricata", "aminer")
    assert config.variant_seed == 20261031
    cases = config.cases
    assert (cases.seed, cases.padding_seconds, cases.max_alerts, cases.truncation,
            cases.benign_per_attack) == (20261031, 0, 100, "spread", 1)
    baselines = config.baselines
    assert (baselines.top_k, baselines.detector_order, baselines.quote_chars) == (
        5, ("aminer", "wazuh", "suricata"), 60)
    assert config.pilot_scenarios == ("russellmitchell", "shaw")  # dev only


@pytest.mark.parametrize("scenario", HELD_OUT)
def test_held_out_scenario_is_refused_by_dev_only_code(scenario: str, tmp_path: Path) -> None:
    config = load_study_config()
    with pytest.raises(HeldOutScenarioError, match=scenario):
        config.split.require_dev(scenario)
    # The guards run before any file is touched, so missing inputs cannot mask them.
    with pytest.raises(HeldOutScenarioError):
        dev_triage_report(tmp_path, scenario, config)
    with pytest.raises(HeldOutScenarioError):
        dev_case_report(tmp_path, tmp_path / "labels.csv", scenario, config)


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
        ({"variants__seed": "1"}, "seed"),
        ({"variants__shuffled_reference": ["nope"]}, "shuffled_reference"),
        ({"variants__manifest_only_shuffled_reference": ["wazuh"]}, "both"),
        ({"cases__max_alerts": 0}, "max_alerts"),
        ({"cases__padding_seconds": -1}, "padding_seconds"),
        ({"cases__truncation": "random"}, "truncation"),
        ({"cases__benign_per_attack": 0}, "benign_per_attack"),
        ({"cases__truncation": "earliest"}, None),
        ({"variants__noise_reference": ["fused"]}, "noise_reference"),
        ({"baselines__top_k": 0}, "top_k"),
        ({"baselines__detector_order": ["aminer", "wazuh"]}, "detector_order"),
        ({"baselines__quote_chars": 7}, "quote_chars"),
        ({"pilot__scenarios": ["fox"]}, "pilot"),
    ],
)
def test_bad_config_raises(tmp_path: Path, changes: dict[str, object], message: str | None) -> None:
    if message is None:  # a valid alternative, accepted
        load_study_config(write_config(tmp_path, **changes))
        return
    with pytest.raises(ValueError, match=message):
        load_study_config(write_config(tmp_path, **changes))


def test_config_is_immutable() -> None:
    config = load_study_config()
    assert isinstance(config, StudyConfig)
    with pytest.raises(AttributeError):
        config.split.dev = ("fox",)  # type: ignore[misc]
