"""Protocol freeze + the logged held-out permit (final study)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.study.config import HeldOutScenarioError, load_study_config
from app.study.freeze import (
    FreezeError,
    authorize_held_out,
    compute_freeze,
    verify_freeze,
    write_freeze,
)
from tests.test_cases import synthetic_config


def held_out_config(tmp_path: Path) -> Path:
    """'synthetic' as a held-out scenario (dev = russellmitchell)."""
    data = json.loads(synthetic_config(tmp_path).read_text(encoding="utf-8"))
    data["split"]["dev"] = ["russellmitchell"]
    data["split"]["held_out"] = ["synthetic"]
    data["pilot"]["scenarios"] = ["russellmitchell"]
    path = tmp_path / "held_out_study.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _freeze(tmp_path: Path, cfg: Path, model: str = "qwen2.5:7b-instruct") -> Path:
    stats = tmp_path / "statistics.json"
    if not stats.exists():
        stats.write_text(json.dumps({"seed": 1, "resamples": 100, "confidence": 0.95, "family": []}),
                         encoding="utf-8")
    plan = tmp_path / "final_study.json"
    if not plan.exists():
        plan.write_text(json.dumps({"scenarios": ["synthetic"]}), encoding="utf-8")
    manifest = compute_freeze(study_config=cfg, statistics_config=stats, final_plan=plan,
                              model_id=model)
    return write_freeze(manifest, tmp_path / "protocol-freeze.json")


def test_freeze_records_every_protocol_hash(tmp_path: Path) -> None:
    cfg = held_out_config(tmp_path)
    data = json.loads(_freeze(tmp_path, cfg).read_text(encoding="utf-8"))
    h = data["hashes"]
    for key in ("study_config", "statistics_config", "final_plan", "relevance_set",
                "single_system_prompt", "graph_prompts", "tool_and_study_code", "model_id", "seeds"):
        assert key in h, key
    assert h["model_id"] == "qwen2.5:7b-instruct"
    assert data["seeds"]["variants"] == 20261031
    assert len(data["freeze_sha256"]) == 64
    assert "git_commit" in data and "created_utc" in data


def test_permit_requires_a_matching_freeze(tmp_path: Path) -> None:
    cfg = held_out_config(tmp_path)
    config = load_study_config(cfg)
    log = tmp_path / "access.jsonl"
    with pytest.raises(FreezeError, match="no protocol freeze"):
        authorize_held_out(tmp_path / "missing.json", study_config=cfg,
                           statistics_config=tmp_path / "statistics.json",
                           final_plan=tmp_path / "final_study.json", model_id="m", access_log=log,
                           reason="test")
    freeze = _freeze(tmp_path, cfg, model="m")
    permit = authorize_held_out(freeze, study_config=cfg, statistics_config=tmp_path / "statistics.json",
                                final_plan=tmp_path / "final_study.json", model_id="m",
                                access_log=log, reason="test")
    assert permit.check(config, "synthetic") == "synthetic"
    assert permit.check(config, "russellmitchell") == "russellmitchell"
    with pytest.raises(ValueError):
        permit.check(config, "not-a-scenario")
    events = [json.loads(x) for x in log.read_text(encoding="utf-8").splitlines()]
    assert [e["event"] for e in events] == ["refused", "authorized"]
    assert events[1]["freeze_sha256"] == permit.freeze_sha256


def test_changed_model_or_config_breaks_the_permit(tmp_path: Path) -> None:
    cfg = held_out_config(tmp_path)
    freeze = _freeze(tmp_path, cfg, model="m")
    kw = dict(statistics_config=tmp_path / "statistics.json", final_plan=tmp_path / "final_study.json",
              access_log=tmp_path / "access.jsonl", reason="test")
    with pytest.raises(FreezeError, match="model_id"):
        authorize_held_out(freeze, study_config=cfg, model_id="other", **kw)  # type: ignore[arg-type]
    cfg.write_text(cfg.read_text(encoding="utf-8").replace('"max_tool_calls": 12',
                                                           '"max_tool_calls": 13'), encoding="utf-8")
    assert "study_config" in verify_freeze(freeze, study_config=cfg,
                                           statistics_config=tmp_path / "statistics.json",
                                           final_plan=tmp_path / "final_study.json", model_id="m")
    with pytest.raises(FreezeError, match="study_config"):
        authorize_held_out(freeze, study_config=cfg, model_id="m", **kw)  # type: ignore[arg-type]


def test_prepare_run_refuses_held_out_without_a_permit(processed: Path, samples_dir: Path,  # noqa: F811
                                                       tmp_path: Path) -> None:
    from app.agent.runner import prepare_run
    cfg = held_out_config(tmp_path)
    config = load_study_config(cfg)
    labels = samples_dir / "synthetic_ait_ads" / "synthetic_labels.csv"
    with pytest.raises(HeldOutScenarioError):
        prepare_run(processed, labels, "synthetic", "fused", config, limit=2)
    freeze = _freeze(tmp_path, cfg, model="m")
    permit = authorize_held_out(freeze, study_config=cfg, statistics_config=tmp_path / "statistics.json",
                                final_plan=tmp_path / "final_study.json", model_id="m",
                                access_log=tmp_path / "access.jsonl", reason="test")
    prep = prepare_run(processed, labels, "synthetic", "fused", config, limit=2, permit=permit)
    assert prep.scenario == "synthetic" and len(prep.cases) == 2


from tests.test_variants import processed  # noqa: E402,F401  (fixture)
