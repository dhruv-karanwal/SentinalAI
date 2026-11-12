"""Final-study run plan: phases, repeats, per-scenario checkpoints, per-case rows (FakeClient only)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.agent.client import FakeClient
from app.study.final_runs import FinalPlan, case_rows, load_final_plan, plan_runs, run_final
from tests.test_freeze import _freeze, held_out_config
from tests.test_variants import processed  # noqa: F401  (fixture)
from tests.test_wave_c_graph import route


def _plan(tmp_path: Path) -> Path:
    path = tmp_path / "final_study.json"
    path.write_text(json.dumps({
        "scenarios": ["synthetic"], "variants": ["fused", "wazuh"], "select": "reachable",
        "retrieval": "none",
        "phases": [{"name": "i", "truncation": "spread", "repeats": [1]},
                   {"name": "ii", "truncation": "spread", "repeats": [2, 3]},
                   {"name": "iii", "truncation": "earliest", "repeats": [1]}]}), encoding="utf-8")
    return path


def test_repo_plan_covers_every_held_out_scenario_and_phase() -> None:
    from app.study.config import load_study_config
    plan = load_final_plan()
    assert set(plan.scenarios) == set(load_study_config().split.held_out)
    assert [(p.name, p.truncation, p.repeats) for p in plan.phases] == [
        ("i", "spread", (1,)), ("ii", "spread", (2, 3)), ("iii", "earliest", (1,))]
    assert plan.variants == ("wazuh", "suricata", "aminer", "fused", "oracle", "noise-wazuh")


def test_plan_order_is_phase_repeat_scenario_variant(tmp_path: Path) -> None:
    plan = load_final_plan(_plan(tmp_path))
    units = plan_runs(plan)
    assert [(u.phase, u.repeat, u.truncation, u.scenario, u.variant) for u in units] == [
        ("i", 1, "spread", "synthetic", "fused"), ("i", 1, "spread", "synthetic", "wazuh"),
        ("ii", 2, "spread", "synthetic", "fused"), ("ii", 2, "spread", "synthetic", "wazuh"),
        ("ii", 3, "spread", "synthetic", "fused"), ("ii", 3, "spread", "synthetic", "wazuh"),
        ("iii", 1, "earliest", "synthetic", "fused"), ("iii", 1, "earliest", "synthetic", "wazuh")]
    assert [u.phase for u in plan_runs(plan, phases=["ii"])] == ["ii"] * 4


def test_unknown_phase_or_bad_plan_is_an_error(tmp_path: Path) -> None:
    plan = load_final_plan(_plan(tmp_path))
    with pytest.raises(ValueError):
        plan_runs(plan, phases=["iv"])
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"scenarios": [], "variants": ["fused"], "select": "reachable",
                               "retrieval": "none", "phases": []}), encoding="utf-8")
    with pytest.raises(ValueError):
        load_final_plan(bad)


def _clients() -> dict[str, FakeClient]:
    from tests.test_agent_runner import LIST
    final = json.dumps({"action": "final", "verdict": "benign", "findings": []})
    return {"single": FakeClient([LIST, final] * 50),
            "graph": FakeClient([route("report_generation"), final] * 50)}


def test_run_final_checkpoints_per_scenario_and_resumes(processed: Path, samples_dir: Path,  # noqa: F811
                                                        tmp_path: Path) -> None:
    from app.agent.config import load_agent_settings
    from app.study.freeze import authorize_held_out
    cfg = held_out_config(tmp_path)
    plan_path = _plan(tmp_path)
    freeze = _freeze(tmp_path, cfg, model="fake")
    permit = authorize_held_out(freeze, study_config=cfg, statistics_config=tmp_path / "statistics.json",
                                final_plan=plan_path, model_id="fake",
                                access_log=tmp_path / "access.jsonl", reason="test")
    labels = samples_dir / "synthetic_ait_ads" / "synthetic_labels.csv"
    plan: FinalPlan = load_final_plan(plan_path)
    out = tmp_path / "final"
    common = dict(plan=plan, permit=permit, study_config_path=cfg, processed_dir=processed,
                  labels_path=labels, output_dir=out, settings=load_agent_settings(cfg),
                  retriever=None, repo=None, limit=2)
    report = run_final(clients_factory=_clients, phases=["i"], **common)  # type: ignore[arg-type]
    assert [r["event"] for r in report] == ["done", "done", "scenario_checkpoint"]
    ckpt = out / "checkpoints" / "i-r1-spread" / "synthetic.json"
    assert ckpt.exists()
    data = json.loads(ckpt.read_text(encoding="utf-8"))
    assert data["complete"] is True and set(data["runs"]) == {"fused", "wazuh"}
    scores = json.loads((out / data["runs"]["fused"] / "scores.json").read_text(encoding="utf-8"))
    assert scores["scenario_split"] == "held-out" and scores["study_part"] == "held-out"
    assert scores["repeat"] == 1 and "HELD-OUT" in scores["note"]
    # second call: nothing re-runs, the scenario checkpoint is reused
    again = run_final(clients_factory=_clients, phases=["i"], **common)  # type: ignore[arg-type]
    assert [r["event"] for r in again] == ["scenario_skipped"]
    # repeats get their own run directories
    rep = run_final(clients_factory=_clients, phases=["ii"], **common)  # type: ignore[arg-type]
    ids = {r["run_id"] for r in rep if r["event"] == "done"}
    assert len(ids) == 4 and not ids & set(data["runs"].values())
    log = [json.loads(x) for x in (out / "final-progress.jsonl").read_text().splitlines()]
    assert {e["event"] for e in log} >= {"start", "done", "scenario_checkpoint", "scenario_skipped"}

    rows = case_rows(out)
    assert rows and {r["study_part"] for r in rows} == {"held-out"}
    assert {r["repeat"] for r in rows} == {1, 2, 3}
    assert {r["arm"] for r in rows} == {"single", "single+verifier", "graph", "graph+verifier"}
    one = rows[0]
    for key in ("scenario", "variant", "truncation", "case_key", "kind", "coverage_event_reachable",
                "citation_precision_event", "unsupported_claim_rate", "verdict_correct"):
        assert key in one
    attack = [r for r in rows if r["kind"] == "attack" and r["reachable"]]
    assert all(r["coverage_event_reachable"] in (0.0, 1.0) for r in attack)
    assert all(r["coverage_event_reachable"] is None for r in rows if r["kind"] == "benign")
    # the same case pairs across variants and arms
    keys = {(r["variant"], r["arm"]): set() for r in rows}
    for r in rows:
        keys[(r["variant"], r["arm"])].add(r["case_key"])
    assert len({frozenset(v) for v in keys.values()}) == 1


def test_run_final_refuses_without_a_permit(processed: Path, samples_dir: Path,  # noqa: F811
                                            tmp_path: Path) -> None:
    from app.agent.config import load_agent_settings
    from app.study.config import HeldOutScenarioError
    cfg = held_out_config(tmp_path)
    plan = load_final_plan(_plan(tmp_path))
    with pytest.raises(HeldOutScenarioError):
        run_final(plan=plan, permit=None, study_config_path=cfg, processed_dir=processed,
                  labels_path=samples_dir / "synthetic_ait_ads" / "synthetic_labels.csv",
                  output_dir=tmp_path / "final", settings=load_agent_settings(cfg), retriever=None,
                  repo=None, clients_factory=_clients, limit=2)
