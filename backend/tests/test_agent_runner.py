"""Agent runs over cases: selection, run log, scoring next to baselines, budgets, CLI.

All runs use the scripted FakeClient on the synthetic sample (scenario
"synthetic" made a dev scenario in a temporary study config). No network.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.agent.client import FakeClient
from app.agent.config import load_agent_settings
from app.agent.runner import estimate_run, prepare_run, run_agent
from app.main import main
from app.study.config import HeldOutScenarioError, load_study_config
from tests.test_cases import synthetic_config
from tests.test_variants import processed  # noqa: F401  (fixture)

NOW = datetime(2026, 11, 7, 12, 0, 0, tzinfo=timezone.utc)


def labels(samples_dir: Path) -> Path:
    return samples_dir / "synthetic_ait_ads" / "synthetic_labels.csv"


def cite_everything(messages: list[dict[str, str]]) -> str:
    """Second step of the script: cite every alert the list_alerts result showed."""
    listed = json.loads(messages[-1]["content"].split("\n", 1)[1])
    ids = [a["alert_id"] for a in listed["alerts"]]
    findings = [{"summary": "all alerts", "alert_ids": ids,
                 "claims": [{"alert_id": i, "kind": "field_value", "field": "detector",
                             "value": a["detector"]} for i, a in zip(ids, listed["alerts"])]}]
    return json.dumps({"action": "final", "verdict": "attack" if ids else "benign",
                       "findings": findings if ids else []})


LIST = json.dumps({"action": "call_tool", "tool": "list_alerts", "arguments": {}})


def prepared(processed: Path, samples_dir: Path, tmp_path: Path, limit: int | None = 2,  # noqa: F811
             variant: str = "fused", truncation: str | None = None):  # type: ignore[no-untyped-def]
    config_path = synthetic_config(tmp_path)
    config = load_study_config(config_path)
    return config_path, prepare_run(processed, labels(samples_dir), "synthetic", variant, config,
                                    limit=limit, truncation=truncation)


def test_limit_interleaves_attack_and_benign(processed: Path, samples_dir: Path, tmp_path: Path) -> None:  # noqa: F811
    _, prep = prepared(processed, samples_dir, tmp_path, limit=2)
    assert [c.kind.value for c in prep.cases] == ["attack", "benign"]
    _, every = prepared(processed, samples_dir, tmp_path, limit=None)
    assert [c.kind.value for c in every.cases] == ["attack", "benign"] * 3
    assert every.cases[0].case_id == "synthetic:attack:dnsteal"


def test_held_out_and_unknown_variants_are_refused(processed: Path, samples_dir: Path,  # noqa: F811
                                                    tmp_path: Path) -> None:
    config = load_study_config()
    with pytest.raises(HeldOutScenarioError):
        prepare_run(tmp_path, tmp_path / "labels.csv", "wilson", "fused", config, limit=2)
    with pytest.raises(ValueError, match="variant"):
        prepared(processed, samples_dir, tmp_path, variant="shuffled-fused")


def test_run_writes_manifest_transcripts_and_scores(processed: Path, samples_dir: Path,  # noqa: F811
                                                    tmp_path: Path) -> None:
    config_path, prep = prepared(processed, samples_dir, tmp_path, limit=4)
    settings = load_agent_settings(config_path, env={})
    client = FakeClient([LIST, cite_everything] * 4)
    report = run_agent(prep, settings, client, output_dir=tmp_path / "runs",
                       study_config_path=config_path, now=NOW)
    run_dir = tmp_path / "runs" / report["run_id"]
    assert report["run_id"].startswith("20261107T120000Z-")
    manifest = json.loads((run_dir / "manifest.json").read_text("utf-8"))
    assert manifest["model"]["model_id"] == "fake" and manifest["model"]["temperature"] == 0.0
    assert (manifest["scenario"], manifest["variant"], manifest["scenario_split"]) == (
        "synthetic", "fused", "dev")
    assert manifest["config_hash"] == report["config_hash"] and len(manifest["config_hash"]) == 64
    assert len(manifest["cases"]) == 4
    first = manifest["cases"][0]
    for key in ("case_id", "kind", "input_tokens", "output_tokens", "usage_reported", "tool_calls",
                "requests", "latency_seconds", "parse_status", "status", "verdict", "transcript_file"):
        assert key in first
    transcript = json.loads((run_dir / first["transcript_file"]).read_text("utf-8"))
    assert [m["role"] for m in transcript["messages"]][:2] == ["system", "user"]
    assert set(transcript["id_map"].values()) <= {a for c in manifest["cases"] for a in c["alert_ids"]}
    scores = json.loads((run_dir / "scores.json").read_text("utf-8"))
    agent = scores["agent"]
    # This script cites every alert, so it reaches cite-all's coverage on the same cases.
    cite_all = scores["baselines"]["cite-all"]
    assert agent["coverage"] == cite_all["coverage"]
    assert agent["alerts_cited"]["total"] == cite_all["alerts_cited"]["total"]
    assert agent["unsupported_claim_rate"] == 0.0 and agent["claims"] > 0
    k = scores["matched_k"]
    assert f"cite-top-k-detector-order@k{k}-matched" in scores["baselines"]
    assert "cite-top-k-detector-order@k1" in scores["baselines"]  # synthetic config: top_k [1, 2]
    assert agent["runs"]["status"] == {"ok": 4}
    assert agent["runs"]["parse_status"] == {"ok": 4}
    assert agent["verdict"]["failed"] == 0
    assert "DEV" in scores["note"]


def test_failures_are_counted_not_hidden(processed: Path, samples_dir: Path, tmp_path: Path) -> None:  # noqa: F811
    config_path, prep = prepared(processed, samples_dir, tmp_path, limit=2)
    settings = load_agent_settings(config_path, env={})
    client = FakeClient(["garbage", "still garbage", LIST, cite_everything])
    report = run_agent(prep, settings, client, output_dir=tmp_path / "runs",
                       study_config_path=config_path, now=NOW)
    agent = report["scores"]["agent"]
    assert agent["runs"]["status"] == {"failed": 1, "ok": 1}
    assert agent["runs"]["parse_status"] == {"unparseable": 1, "ok": 1}
    assert agent["verdict"]["failed"] == 1


def test_config_hash_is_deterministic(processed: Path, samples_dir: Path, tmp_path: Path) -> None:  # noqa: F811
    config_path, prep = prepared(processed, samples_dir, tmp_path, limit=1)
    settings = load_agent_settings(config_path, env={})
    runs = [run_agent(prep, settings, FakeClient([LIST, cite_everything]), output_dir=tmp_path / "runs",
                      study_config_path=config_path, now=NOW) for _ in range(2)]
    assert runs[0]["config_hash"] == runs[1]["config_hash"]
    assert runs[0]["run_id"] != runs[1]["run_id"]  # same second: a suffix keeps both runs


def test_estimate_is_a_bound_from_the_budgets(processed: Path, samples_dir: Path, tmp_path: Path) -> None:  # noqa: F811
    config_path, prep = prepared(processed, samples_dir, tmp_path, limit=2)
    settings = load_agent_settings(config_path, env={})
    estimate = estimate_run(prep, settings)
    per_case = settings.agent.max_tokens_per_case
    assert estimate["cases"] == 2 and estimate["token_bound"] == 2 * per_case
    assert estimate["cost_bound_usd"] == 0.0  # local model prices are 0 in the committed config
    assert estimate["needs_confirm"] == (2 * per_case > settings.agent.run_token_budget)
    assert estimate["first_prompt_tokens_estimate"] > 0


def cli(processed: Path, samples_dir: Path, tmp_path: Path, *extra: str) -> list[str]:  # noqa: F811
    return ["run-agent", "--scenario", "synthetic", "--variant", "fused", "--processed-dir", str(processed),
            "--labels", str(labels(samples_dir)), "--study-config", str(synthetic_config(tmp_path)),
            "--output-dir", str(tmp_path / "runs"), *extra]


def test_cli_dry_run_calls_no_model(processed: Path, samples_dir: Path, tmp_path: Path,  # noqa: F811
                                    capsys: pytest.CaptureFixture[str]) -> None:
    assert main(cli(processed, samples_dir, tmp_path, "--limit", "2", "--dry-run")) == 0
    out = capsys.readouterr().out
    assert "DRY RUN" in out and "token bound" in out and "no model was called" in out
    assert not (tmp_path / "runs").exists()


def test_cli_requires_an_endpoint_or_fake(processed: Path, samples_dir: Path, tmp_path: Path,  # noqa: F811
                                          capsys: pytest.CaptureFixture[str],
                                          monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SENTINEL_LLM_BASE_URL", raising=False)
    monkeypatch.delenv("SENTINEL_LLM_MODEL", raising=False)
    assert main(cli(processed, samples_dir, tmp_path, "--limit", "2")) == 2
    assert "no model endpoint configured" in capsys.readouterr().err


def test_cli_budget_needs_confirm(processed: Path, samples_dir: Path, tmp_path: Path,  # noqa: F811
                                  capsys: pytest.CaptureFixture[str]) -> None:
    script = tmp_path / "script.json"
    script.write_text(json.dumps([LIST, json.dumps({"action": "final", "verdict": "benign",
                                                    "findings": []})] * 6), encoding="utf-8")
    args = cli(processed, samples_dir, tmp_path, "--fake-responses", str(script))  # 6 cases > budget
    assert main(args) == 2
    assert "--confirm" in capsys.readouterr().err
    assert main([*args, "--confirm"]) == 0


def test_cli_fake_run_never_writes_the_api_key(processed: Path, samples_dir: Path, tmp_path: Path,  # noqa: F811
                                               capsys: pytest.CaptureFixture[str],
                                               monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "sk-test-secret-value"
    monkeypatch.setenv("SENTINEL_LLM_API_KEY", secret)
    script = tmp_path / "script.json"
    final = json.dumps({"action": "final", "verdict": "benign", "findings": []})
    script.write_text(json.dumps([LIST, final, LIST, final]), encoding="utf-8")
    assert main(cli(processed, samples_dir, tmp_path, "--limit", "2", "--fake-responses", str(script))) == 0
    out = capsys.readouterr().out
    assert "agent (fake)" in out and "cite-all" in out and "DEV-SCENARIO AGENT RUN" in out
    for path in (tmp_path / "runs").rglob("*"):
        if path.is_file():
            assert secret not in path.read_text("utf-8")
    assert secret not in out
    assert main(["run-agent", "--scenario", "wilson", "--variant", "fused", "--dry-run"]) == 2


# --- M6: case selection options -------------------------------------------------------------

def test_select_cases_reachable_keeps_reachable_phases_and_their_benign_matches() -> None:
    from app.agent.runner import select_cases
    from app.study.cases import Case, CaseKind
    t = NOW

    def case(kind: CaseKind, phase: str) -> Case:
        return Case(f"s:{kind.value}:{phase}", "s", kind, phase, t, t, 0)

    cases = [case(CaseKind.ATTACK, "scan"), case(CaseKind.ATTACK, "dirb"),
             case(CaseKind.BENIGN, "scan"), case(CaseKind.BENIGN, "dirb")]
    assert select_cases(cases, None) == [0, 2, 1, 3]
    assert select_cases(cases, None, mode="reachable", reachable=("dirb",)) == [1, 3]
    assert select_cases(cases, 1, mode="reachable", reachable=("dirb",)) == [1]
    assert select_cases(cases, None, case_ids=["s:benign:scan", "s:attack:dirb"]) == [2, 1]
    with pytest.raises(ValueError, match="unknown case id"):
        select_cases(cases, None, case_ids=["nope"])
    with pytest.raises(ValueError, match="mode"):
        select_cases(cases, None, mode="random")


def test_prepare_run_passes_selection_through(processed: Path, samples_dir: Path,  # noqa: F811
                                              tmp_path: Path) -> None:
    config_path = synthetic_config(tmp_path)
    config = load_study_config(config_path)
    every = prepare_run(processed, labels(samples_dir), "synthetic", "fused", config, limit=None)
    first = every.cases[1].case_id
    one = prepare_run(processed, labels(samples_dir), "synthetic", "fused", config, limit=None,
                      case_ids=[first])
    assert [c.case_id for c in one.cases] == [first]
    reach = prepare_run(processed, labels(samples_dir), "synthetic", "fused", config, limit=None,
                        selection="reachable")
    assert all(c.phase in reach.reachable for c in reach.cases)
