"""Prompt-revision selection for study-stats and export-paper-assets (analysis only, synthetic run files)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.study.revisions import choose_revision, revision_key, run_revision, select_rows
from tests.test_paper_assets import _stats, write_run


def manifest(runs: Path, name: str, single: str, graph: str) -> None:
    (runs / name / "manifest.json").write_text(
        json.dumps({"prompt_versions": {"single": single, "graph": graph}}), encoding="utf-8")


def two_revisions(runs: Path) -> None:
    write_run(runs, "matched-old", "pilot", "shaw", "fused", [0.0, 0.0])
    manifest(runs, "matched-old", "m5-v2", "wave-c-v1")
    write_run(runs, "matched-new", "pilot", "shaw", "fused", [1.0, 1.0])
    manifest(runs, "matched-new", "m5-v3", "wave-c-v2")


def test_run_revision_reads_the_manifest_and_marks_missing_ones(tmp_path: Path) -> None:
    two_revisions(tmp_path)
    write_run(tmp_path, "matched-bare", "pilot", "shaw", "fused", [1.0])
    assert run_revision(tmp_path / "matched-new") == "m5-v3+wave-c-v2"
    assert run_revision(tmp_path / "matched-bare") == "unknown"


def test_revision_order_is_numeric_not_lexical() -> None:
    assert revision_key("m5-v10+wave-c-v2") > revision_key("m5-v9+wave-c-v2")
    assert revision_key("m5-v3+wave-c-v2") > revision_key("m5-v2+wave-c-v1")
    assert revision_key("unknown") < revision_key("m5-v1+wave-c-v1")


def test_default_is_latest_and_warns_when_mixed() -> None:
    c = choose_revision({"m5-v2+wave-c-v1": 12, "m5-v3+wave-c-v2": 12}, None)
    assert c.chosen == "m5-v3+wave-c-v2"
    assert c.warning is not None and "mixed" in c.warning
    assert "m5-v2+wave-c-v1 (12 runs)" in c.warning and "m5-v3+wave-c-v2" in c.warning


def test_single_revision_has_no_warning() -> None:
    c = choose_revision({"m5-v3+wave-c-v2": 12}, None)
    assert c.chosen == "m5-v3+wave-c-v2" and c.warning is None


def test_all_keeps_every_run_and_still_warns() -> None:
    c = choose_revision({"a-v1+b-v1": 1, "a-v2+b-v1": 1}, "all")
    assert c.chosen is None and c.warning is not None and "same case keys" in c.warning


def test_component_or_full_label_selects_and_unknown_label_fails() -> None:
    present = {"m5-v2+wave-c-v1": 12, "m5-v3+wave-c-v2": 12}
    assert choose_revision(present, "m5-v2").chosen == "m5-v2+wave-c-v1"
    assert choose_revision(present, "m5-v3+wave-c-v2").chosen == "m5-v3+wave-c-v2"
    assert choose_revision(present, "m5-v2").warning is None
    with pytest.raises(ValueError, match="m5-v9"):
        choose_revision(present, "m5-v9")


def test_select_rows_keeps_only_the_chosen_revision(tmp_path: Path) -> None:
    from app.study.final_runs import case_rows

    two_revisions(tmp_path)
    rows = case_rows(tmp_path, ["pilot"])
    kept, choice = select_rows(rows, tmp_path, None)
    assert {r["run_id"] for r in kept} == {"matched-new"}
    assert choice.present == {"m5-v2+wave-c-v1": 1, "m5-v3+wave-c-v2": 1}
    old, _ = select_rows(rows, tmp_path, "m5-v2")
    assert {r["run_id"] for r in old} == {"matched-old"}
    every, _ = select_rows(rows, tmp_path, "all")
    assert len(every) == len(rows)


def test_export_uses_latest_revision_records_it_and_warns(tmp_path: Path) -> None:
    from app.study.paper_assets import export_paper_assets

    runs = tmp_path / "runs"
    two_revisions(runs)
    warnings: list[str] = []
    export_paper_assets(runs, tmp_path / "out", statistics_config=_stats(tmp_path), on_warning=warnings.append)
    prov = json.loads((tmp_path / "out" / "pilot" / "provenance.json").read_text(encoding="utf-8"))
    assert prov["run_ids"] == ["matched-new"]
    assert prov["prompt_revision"] == "m5-v3+wave-c-v2"
    assert prov["prompt_revisions_present"] == {"m5-v2+wave-c-v1": 1, "m5-v3+wave-c-v2": 1}
    assert len(warnings) == 1 and "mixed" in warnings[0]
    readme = (tmp_path / "out" / "README.md").read_text(encoding="utf-8")
    assert "m5-v3+wave-c-v2" in readme


def test_stats_cli_filters_and_warns(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    import argparse

    from app.cli_final import dispatch

    runs = tmp_path / "runs"
    two_revisions(runs)
    args = argparse.Namespace(command="study-stats", part="pilot", pilot_runs_dir=runs, runs_dir=tmp_path / "none",
                              statistics_config=_stats(tmp_path), prompt_version=None)
    assert dispatch(args) == 0
    out = capsys.readouterr()
    assert "mixed" in out.err and "prompt revision m5-v3+wave-c-v2" in out.out
    args.prompt_version = "m5-v9"
    assert dispatch(args) == 2
    assert "m5-v9" in capsys.readouterr().err
