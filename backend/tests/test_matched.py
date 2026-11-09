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
