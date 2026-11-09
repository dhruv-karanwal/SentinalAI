import json
from pathlib import Path

import pytest

from app.ingestion.mappings import AIT_ADS_SCENARIOS
from app.study.cases import dev_case_report
from app.study.config import (
    DEFAULT_STUDY_CONFIG,
    FROZEN_DETECTOR_ORDER,
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
        (5, 10), ("aminer", "wazuh", "suricata"), 60)
    assert config.pilot_scenarios == ("russellmitchell", "shaw")  # dev only
    assert config.pilot_truncations == ("spread", "earliest")  # reported side by side


def test_detector_order_is_frozen() -> None:
    """The cite-top-k-detector-order ranking was frozen on 2026-11-07 (M4b decision 5).

    It was derived from dev triage precision; changing it after the freeze
    would tune a baseline after the protocol was fixed. Do not edit this test
    or study.json's detector_order.
    """
    baselines = load_study_config().baselines
    assert baselines.detector_order_frozen
    assert baselines.detector_order == FROZEN_DETECTOR_ORDER == ("aminer", "wazuh", "suricata")
    raw = json.loads(DEFAULT_STUDY_CONFIG.read_text(encoding="utf-8"))["baselines"]
    assert raw["detector_order"] == ["aminer", "wazuh", "suricata"]
    assert raw["detector_order_frozen_on"] == "2026-11-07"


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
        ({"baselines__top_k": [5, 0]}, "top_k"),
        ({"baselines__top_k": []}, "top_k"),
        ({"baselines__top_k": [5, 5]}, "top_k"),
        ({"baselines__top_k": 3}, None),
        ({"baselines__detector_order": ["wazuh", "aminer", "suricata"]}, "frozen"),
        ({"baselines__detector_order_frozen": "yes"}, "detector_order_frozen"),
        ({"pilot__truncation": ["random"]}, "truncation"),
        ({"pilot__truncation": []}, "truncation"),
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


# sha256 of the frozen sections of experiments/config/study.json (canonical JSON,
# sorted keys): the whole "split" and the frozen detector order. Committed
# 2026-11-09 (Wave B-rest). If this test fails, a frozen section changed: revert it.
FROZEN_SECTIONS_SHA256 = "3421f54bdb2646ba2fa871df6664664e7ad008598e82ee90149d02c89bbe93cd"


def frozen_sections_digest(path: Path = DEFAULT_STUDY_CONFIG) -> str:
    import hashlib
    data = json.loads(path.read_text(encoding="utf-8"))
    frozen = {"split": data["split"],
              "baselines.detector_order": {k: data["baselines"][k] for k in
                                           ("detector_order", "detector_order_frozen",
                                            "detector_order_frozen_on")}}
    return hashlib.sha256(json.dumps(frozen, sort_keys=True, separators=(",", ":"))
                          .encode()).hexdigest()


def test_frozen_sections_are_unchanged() -> None:
    assert frozen_sections_digest() == FROZEN_SECTIONS_SHA256


def test_frozen_digest_detects_a_change(tmp_path: Path) -> None:
    changed = write_config(tmp_path, split__held_out=["fox", "harrison", "santos", "wardbeck",
                                                      "wheeler"])
    assert frozen_sections_digest(changed) != FROZEN_SECTIONS_SHA256


def test_extra_detectors_default_empty_and_validated(tmp_path: Path) -> None:
    assert load_study_config().extra_detectors == ()
    assert load_study_config(write_config(tmp_path, variants__extra_detectors=["sigma"])
                             ).extra_detectors == ("sigma",)
    with pytest.raises(ValueError, match="extra_detectors"):
        load_study_config(write_config(tmp_path, variants__extra_detectors=["wazuh"]))
