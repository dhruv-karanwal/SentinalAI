"""Wave C (C3): matched-budget runner and the dry-run pilot estimate (FakeClient only)."""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.agent.client import FakeClient
from app.agent.config import load_agent_settings
from tests.test_variants import processed  # noqa: F401  (fixture)
from tests.test_wave_c_graph import route


# ---------------------------------------------------------------- matched runner

def test_matched_runner_same_budgets_same_scoring(processed: Path, samples_dir: Path,  # noqa: F811
                                                  tmp_path: Path) -> None:
    from app.agent.matched import estimate_matched, run_matched
    from tests.test_agent_runner import LIST, cite_everything, prepared
    config_path, prep = prepared(processed, samples_dir, tmp_path, limit=2)
    settings = load_agent_settings(config_path)
    final = json.dumps({"action": "final", "verdict": "benign", "findings": []})
    clients = {"single": FakeClient([LIST, cite_everything] * 2),
               "graph": FakeClient([route("report_generation"), final] * 2)}
    report = run_matched(prep, settings, clients, output_dir=tmp_path / "runs",
                         study_config_path=config_path,
                         now=datetime(2026, 11, 9, tzinfo=timezone.utc))
    man, scores = report["manifest"], report["scores"]
    assert man["agent_budgets_both_arms"] == dataclasses.asdict(settings.agent)
    assert set(scores["arms"]) == {"single", "single+verifier", "graph", "graph+verifier"}
    assert "baselines" in scores and scores["matched_k"] >= 1
    for rec in man["cases"]:
        for arm in ("single", "graph"):
            r = rec[arm]
            for key in ("input_tokens", "output_tokens", "tool_calls", "latency_seconds",
                        "parse_status", "budget_hit", "verification"):
                assert key in r
    assert man["cases"][0]["single"]["verification"]["claims_dropped"] == 0
    assert (Path(report["run_dir"]) / "cases" / "000.graph.json").exists()
    est = estimate_matched(prep, settings)
    assert est["token_bound_per_arm"] == 2 * settings.agent.max_tokens_per_case
    assert "3 characters per token" in est["method"]


def test_matched_cli_dry_run_calls_no_model(processed: Path, samples_dir: Path, tmp_path: Path,  # noqa: F811
                                            capsys: pytest.CaptureFixture[str]) -> None:
    from app.main import main
    from tests.test_cases import synthetic_config
    cfg = synthetic_config(tmp_path)
    labels = samples_dir / "synthetic_ait_ads" / "synthetic_labels.csv"
    assert main(["pilot-estimate", "--scenarios", "synthetic", "--variants", "fused", "--limit", "2",
                 "--processed-dir", str(processed), "--labels", str(labels),
                 "--study-config", str(cfg)]) == 0
    out = capsys.readouterr().out
    assert "no model was called" in out.lower() and "3 characters per token" in out
    assert main(["pilot-estimate", "--scenarios", "fox", "--study-config", str(cfg)]) == 2


# ---------------------------------------------------------------- resume + pilot config (2026-11-10)

def _clients(n: int) -> dict[str, FakeClient]:
    from tests.test_agent_runner import LIST, cite_everything
    final = json.dumps({"action": "final", "verdict": "benign", "findings": []})
    return {"single": FakeClient([LIST, cite_everything] * n),
            "graph": FakeClient([route("report_generation"), final] * n)}


def test_resume_continues_after_an_interruption(processed: Path, samples_dir: Path,  # noqa: F811
                                                tmp_path: Path) -> None:
    from app.agent.matched import run_matched
    from tests.test_agent_runner import prepared
    config_path, prep = prepared(processed, samples_dir, tmp_path, limit=2)
    settings = load_agent_settings(config_path)
    out = tmp_path / "runs"

    def boom(i: int, arm: str, run: object) -> None:
        if i == 0 and arm == "graph":
            raise KeyboardInterrupt  # the machine went to sleep after case 0

    with pytest.raises(KeyboardInterrupt):
        run_matched(prep, settings, _clients(2), output_dir=out, study_config_path=config_path,
                    resume=True, on_case=boom)
    (run_dir,) = list(out.iterdir())
    assert (run_dir / "cases" / "000.checkpoint.json").exists()
    assert not (run_dir / "scores.json").exists()
    # second process: only one case worth of replies; case 0 must come from the checkpoint
    report = run_matched(prep, settings, _clients(1), output_dir=out, study_config_path=config_path,
                         resume=True)
    assert report["run_dir"] == str(run_dir) and report["resumed_cases"] == [0]
    assert len(report["manifest"]["cases"]) == 2
    fresh = run_matched(prep, settings, _clients(2), output_dir=tmp_path / "fresh",
                        study_config_path=config_path)
    for arm in ("single", "single+verifier", "graph", "graph+verifier"):
        got, want = report["scores"]["arms"][arm], fresh["scores"]["arms"][arm]
        assert {k: v for k, v in got.items() if k != "runs"} == {k: v for k, v in want.items() if k != "runs"}
        assert got["runs"]["input_tokens"] == want["runs"]["input_tokens"]
    assert report["scores"]["baselines"] == fresh["scores"]["baselines"]


def test_resume_skips_a_completed_run_without_calling_a_model(processed: Path,  # noqa: F811
                                                              samples_dir: Path, tmp_path: Path) -> None:
    from app.agent.matched import run_matched
    from tests.test_agent_runner import prepared
    config_path, prep = prepared(processed, samples_dir, tmp_path, limit=2)
    settings = load_agent_settings(config_path)
    first = run_matched(prep, settings, _clients(2), output_dir=tmp_path / "runs",
                        study_config_path=config_path, resume=True)
    again = run_matched(prep, settings, _clients(0), output_dir=tmp_path / "runs",
                        study_config_path=config_path, resume=True)
    assert again["skipped"] is True and again["run_id"] == first["run_id"]
    assert again["scores"] == first["scores"]


def test_retrieval_mode_is_part_of_the_config_hash(processed: Path, samples_dir: Path,  # noqa: F811
                                                   tmp_path: Path) -> None:
    from app.agent.graph import GraphSettings
    from app.agent.matched import matched_hash
    from tests.test_agent_runner import prepared
    config_path, prep = prepared(processed, samples_dir, tmp_path, limit=2)
    settings = load_agent_settings(config_path)
    ids = {"single": "m", "graph": "m"}
    hashes = {matched_hash(prep, settings, ids, config_path, GraphSettings(), retrieval=r)
              for r in (None, "dense", "hybrid")}
    assert len(hashes) == 3


def test_pilot_config_names_the_six_variants_and_reachable_cases() -> None:
    from app.study.config import load_study_config
    cfg = load_study_config()
    assert cfg.pilot_variants == ("wazuh", "suricata", "aminer", "fused", "oracle", "noise-wazuh")
    assert cfg.pilot_select == "reachable"
    assert cfg.pilot_truncations[0] == "spread"
    assert cfg.pilot_retrieval == "hybrid"


def test_run_pilot_cli_resumes_and_logs_progress(processed: Path, samples_dir: Path,  # noqa: F811
                                                 tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from app.main import main
    from tests.test_agent_runner import LIST
    from tests.test_cases import synthetic_config
    cfg = synthetic_config(tmp_path)
    labels = samples_dir / "synthetic_ait_ads" / "synthetic_labels.csv"
    final = json.dumps({"action": "final", "verdict": "benign", "findings": []})
    single, graph = tmp_path / "s.json", tmp_path / "g.json"
    single.write_text(json.dumps([LIST, final] * 4), encoding="utf-8")
    graph.write_text(json.dumps([route("report_generation"), final] * 4), encoding="utf-8")
    common = ["--variants", "fused", "wazuh", "--truncations", "spread", "--limit", "1",
              "--processed-dir", str(processed), "--labels", str(labels), "--study-config", str(cfg),
              "--output-dir", str(tmp_path / "runs"), "--no-retrieval",
              "--data-dir", str(tmp_path / "platform"),  # never the repo's data/platform
              "--fake-single", str(single), "--fake-graph", str(graph)]
    assert main(["run-pilot", "--dry-run", *common]) == 0
    out = capsys.readouterr().out
    assert "DRY RUN" in out and "no model was called" in out.lower()
    assert not (tmp_path / "runs").exists()
    assert main(["run-pilot", "--confirm", *common]) == 0
    log = [json.loads(x) for x in (tmp_path / "runs" / "pilot-progress.jsonl").read_text().splitlines()]
    assert [e["event"] for e in log] == ["start", "done", "start", "done"]
    assert {e["variant"] for e in log} == {"fused", "wazuh"}
    assert main(["run-pilot", "--confirm", *common]) == 0  # second time: everything is skipped
    log = [json.loads(x) for x in (tmp_path / "runs" / "pilot-progress.jsonl").read_text().splitlines()]
    assert [e["event"] for e in log[4:]] == ["skipped", "skipped"]
    assert main(["run-pilot", "--scenarios", "fox", "--dry-run", "--study-config", str(cfg)]) == 2
