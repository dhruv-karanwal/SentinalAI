"""Pilot preflight (2026-11-15): cheap checks before an expensive matched pilot. No network:
the model listing and the one-request smoke use injected callables / FakeClient."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.agent.client import FakeClient
from app.study.preflight import Check, preflight, schema_smoke


class Retr:
    def __init__(self, hits: int) -> None:
        self.hits = hits

    def search(self, text: str, k: int = 5) -> list[dict[str, Any]]:
        return [{"technique_id": "T1110", "name": "n", "tactics": [], "score": 1.0, "text": "t"}][: self.hits]


def by_name(checks: list[Check]) -> dict[str, Check]:
    return {c.name: c for c in checks}


def test_all_checks_pass_with_good_inputs(tmp_path: Path) -> None:
    for name in ("russellmitchell.alerts.jsonl", "russellmitchell.ground_truth.jsonl"):
        (tmp_path / name).write_text("{}\n", encoding="utf-8")
    labels = tmp_path / "labels.csv"
    labels.write_text("x\n", encoding="utf-8")
    checks = preflight(scenarios=["russellmitchell"], dev=["russellmitchell", "shaw"],
                       processed_dir=tmp_path, labels=labels, retriever=Retr(1),
                       model_id="m", list_models=lambda: ["m", "other"])
    assert all(c.ok for c in checks), [c for c in checks if not c.ok]
    names = by_name(checks)
    assert names["prompt versions"].detail == "single m5-v5, graph wave-c-v2"
    assert "search_attack" in names["tool access"].detail


def test_failures_are_reported_not_raised(tmp_path: Path) -> None:
    checks = by_name(preflight(scenarios=["fox"], dev=["russellmitchell", "shaw"],
                               processed_dir=tmp_path, labels=tmp_path / "missing.csv",
                               retriever=Retr(0), model_id=None, list_models=lambda: []))
    assert not checks["dev scenarios only"].ok and "fox" in checks["dev scenarios only"].detail
    assert not checks["inputs present"].ok
    assert not checks["ATT&CK retrieval"].ok
    assert not checks["model endpoint"].ok


def test_held_out_scenario_files_are_never_looked_at(tmp_path: Path) -> None:
    (tmp_path / "fox.alerts.jsonl").write_text("{}\n", encoding="utf-8")
    checks = by_name(preflight(scenarios=["fox"], dev=["shaw"], processed_dir=tmp_path,
                               labels=tmp_path / "l.csv", retriever=None, model_id="m",
                               list_models=lambda: ["m"]))
    assert "not checked" in checks["inputs present"].detail


def test_model_not_listed_and_retrieval_off(tmp_path: Path) -> None:
    checks = by_name(preflight(scenarios=["shaw"], dev=["shaw"], processed_dir=tmp_path,
                               labels=tmp_path / "l.csv", retriever=None, model_id="m",
                               list_models=lambda: ["other"]))
    assert not checks["model endpoint"].ok and "not listed" in checks["model endpoint"].detail
    assert not checks["ATT&CK retrieval"].ok and "off" in checks["ATT&CK retrieval"].detail


def test_schema_smoke_parses_a_final_answer() -> None:
    good = FakeClient([json.dumps({"action": "final", "verdict": "benign", "findings": []})])
    assert schema_smoke(good, max_tokens=50).ok
    bad = FakeClient(["```json\n{}\n```"])
    check = schema_smoke(bad, max_tokens=50)
    assert not check.ok and "not valid JSON" in check.detail
    assert good.calls[0][0]["role"] == "system"
