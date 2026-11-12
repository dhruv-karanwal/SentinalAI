"""export-paper-assets: CSV, LaTeX and SVG straight from run files (synthetic run files only)."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from app.study.paper_assets import export_paper_assets

ARMS = ("single", "single+verifier", "graph", "graph+verifier")


def _score(cov: float | None, cited: int = 2, attack_cited: int = 1, claims: int = 2,
           unsupported: int = 0) -> dict[str, object]:
    return {"case_id": "x", "variant": "v", "load": 10, "coverage_time": cov, "coverage_event": cov,
            "citation_precision_event": attack_cited / cited if cited else None,
            "citation_precision_time": attack_cited / cited if cited else None,
            "unsupported_claim_rate": unsupported / claims if claims else None, "cited": cited,
            "cited_not_in_case": 0, "cited_event_attack": attack_cited, "cited_in_phase": attack_cited,
            "claims": claims, "unsupported_claims": unsupported, "verdict": "attack",
            "status": "ok", "input_tokens": 100, "output_tokens": 10, "tool_calls": 2,
            "latency_seconds": 1.0}


def write_run(runs: Path, name: str, part: str, scenario: str, variant: str, covered: list[float],
              truncation: str = "spread", repeat: int | None = None, unsupported: int = 0) -> None:
    per_case = []
    for i, c in enumerate(covered):
        per_case.append({"index": i, "case_id": f"{scenario}:attack:p{i}", "kind": "attack",
                         "phase": f"p{i}", "reachable": True,
                         "rows": {a: _score(c, unsupported=unsupported if a in ("single", "graph") else 0)
                                  for a in ARMS}})
    d = runs / name
    d.mkdir(parents=True)
    (d / "scores.json").write_text(json.dumps({
        "study_part": part, "scenario": scenario, "variant": variant, "truncation": truncation,
        "repeat": repeat, "per_case": per_case, "arms": {}}), encoding="utf-8")


def _stats(tmp_path: Path) -> Path:
    p = tmp_path / "statistics.json"
    p.write_text(json.dumps({
        "seed": 3, "resamples": 500, "confidence": 0.95, "stratify_by": "scenario",
        "primary_truncation": "spread", "primary_repeat": 1,
        "family": [
            {"name": "src", "metric": "coverage_event_reachable",
             "a": {"variant": "wazuh", "arm": "graph+verifier"},
             "b": {"variant": "fused", "arm": "graph+verifier"}},
            {"name": "ver", "metric": "unsupported_claim_rate",
             "a": {"variant": "fused", "arm": "graph"}, "b": {"variant": "fused", "arm": "graph+verifier"}}]}),
        encoding="utf-8")
    return p


def test_export_writes_tables_and_figures_from_run_files(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    write_run(runs, "matched-a", "held-out", "fox", "fused", [1.0, 1.0, 0.0, 1.0], unsupported=1)
    write_run(runs, "matched-b", "held-out", "fox", "wazuh", [0.0, 1.0, 0.0, 0.0])
    write_run(runs, "matched-c", "pilot", "shaw", "fused", [1.0, 0.0])
    write_run(runs, "matched-d", "adhoc", "shaw", "fused", [1.0, 1.0])  # ignored: not a study part
    out = tmp_path / "results"
    written = export_paper_assets(runs, out, statistics_config=_stats(tmp_path))
    held = out / "held_out"
    for name in ("per_case.csv", "summary.csv", "summary.tex", "comparisons.csv", "comparisons.tex",
                 "coverage.svg", "provenance.json"):
        assert (held / name).exists(), name
    assert (out / "pilot" / "summary.csv").exists() and (out / "README.md").exists()
    assert set(written) >= {str(held / "summary.csv")}

    with (held / "summary.csv").open(encoding="utf-8") as fh:
        summary = {(r["variant"], r["arm"]): r for r in csv.DictReader(fh)}
    assert float(summary[("fused", "graph+verifier")]["coverage_event_reachable"]) == pytest.approx(0.75)
    assert int(summary[("fused", "graph+verifier")]["cases_reachable"]) == 4
    assert float(summary[("wazuh", "graph+verifier")]["coverage_event_reachable"]) == pytest.approx(0.25)
    assert float(summary[("fused", "graph")]["unsupported_claim_rate"]) == pytest.approx(0.5)
    assert float(summary[("fused", "graph+verifier")]["unsupported_claim_rate"]) == 0.0

    with (held / "comparisons.csv").open(encoding="utf-8") as fh:
        comp = {r["name"]: r for r in csv.DictReader(fh)}
    assert float(comp["src"]["difference"]) == pytest.approx(0.5)
    assert float(comp["ver"]["difference"]) == pytest.approx(-0.5)
    assert comp["src"]["p_holm"] != ""

    tex = (held / "summary.tex").read_text(encoding="utf-8")
    assert "0.750" in tex and "\\begin{tabular}" in tex
    svg = (held / "coverage.svg").read_text(encoding="utf-8")
    assert svg.startswith("<svg") and "fused" in svg and "<title>" in svg
    pilot_tex = (out / "pilot" / "summary.tex").read_text(encoding="utf-8")
    assert "pilot, not paper results" in pilot_tex
    readme = (out / "README.md").read_text(encoding="utf-8")
    assert "never typed in" in readme and "matched-a" in (held / "provenance.json").read_text()
    assert "matched-d" not in (out / "pilot" / "provenance.json").read_text()


def test_export_with_no_runs_says_so(tmp_path: Path) -> None:
    out = tmp_path / "results"
    export_paper_assets(tmp_path / "empty", out, statistics_config=_stats(tmp_path))
    readme = (out / "README.md").read_text(encoding="utf-8")
    assert "no finished runs" in readme
