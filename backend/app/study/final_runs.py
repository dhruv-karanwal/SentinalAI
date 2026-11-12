"""Resumable run plan of the final (held-out) study, with per-scenario checkpoints.

Why: the held-out study is many hours of local-model time and the machine
may sleep or the session may end. The plan (``experiments/config/final_study.json``,
hashed into the protocol freeze) lists phases; each phase has one truncation
rule and one or more repeats. Units run phase -> repeat -> scenario ->
variant, each through :func:`app.agent.matched.run_matched` with
``resume=True`` and ``repeat`` in the config hash, so

- a finished unit is skipped (its ``scores.json`` exists),
- an interrupted unit continues from its per-case checkpoints,
- when every variant of a scenario is finished, a scenario checkpoint
  ``<out>/checkpoints/<phase>-r<repeat>-<truncation>/<scenario>.json`` lists
  the run ids; a later call skips the whole scenario.

Every start / done / skip goes to ``<out>/final-progress.jsonl``. Held-out
scenarios need a :class:`~app.study.freeze.HeldOutPermit` (``prepare_run``
refuses them otherwise).

:func:`case_rows` flattens the ``per_case`` blocks of finished runs into one
row per (case, variant, score row) for the statistics and the paper exporter.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.study.config import TRUNCATION_CHOICES

REPO = Path(__file__).resolve().parents[3]
DEFAULT_FINAL_PLAN = REPO / "experiments" / "config" / "final_study.json"


@dataclass(frozen=True)
class Phase:
    name: str
    truncation: str
    repeats: tuple[int, ...]


@dataclass(frozen=True)
class FinalPlan:
    scenarios: tuple[str, ...]
    variants: tuple[str, ...]
    select: str
    retrieval: str | None
    phases: tuple[Phase, ...]


@dataclass(frozen=True)
class Unit:
    phase: str
    repeat: int
    truncation: str
    scenario: str
    variant: str


def load_final_plan(path: str | Path = DEFAULT_FINAL_PLAN) -> FinalPlan:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    phases = tuple(Phase(str(p["name"]), str(p["truncation"]), tuple(int(r) for r in p["repeats"]))
                   for p in data["phases"])
    if not data["scenarios"] or not data["variants"] or not phases:
        raise ValueError("final plan needs scenarios, variants and phases")
    for p in phases:
        if p.truncation not in TRUNCATION_CHOICES or not p.repeats or min(p.repeats) < 1:
            raise ValueError(f"bad phase {p}")
    if len({p.name for p in phases}) != len(phases):
        raise ValueError("phase names must be unique")
    if data["select"] not in ("reachable", "interleaved"):
        raise ValueError("select must be reachable or interleaved")
    retrieval = data.get("retrieval")
    return FinalPlan(tuple(data["scenarios"]), tuple(data["variants"]), str(data["select"]),
                     None if retrieval in (None, "none") else str(retrieval), phases)


def plan_runs(plan: FinalPlan, phases: Sequence[str] | None = None,
              scenarios: Sequence[str] | None = None) -> list[Unit]:
    names = [p.name for p in plan.phases]
    for name in phases or ():
        if name not in names:
            raise ValueError(f"unknown phase {name!r}; plan has {', '.join(names)}")
    for s in scenarios or ():
        if s not in plan.scenarios:
            raise ValueError(f"scenario {s!r} is not in the final plan")
    units: list[Unit] = []
    for p in plan.phases:
        if phases and p.name not in phases:
            continue
        for r in p.repeats:
            for s in plan.scenarios:
                if scenarios and s not in scenarios:
                    continue
                units.extend(Unit(p.name, r, p.truncation, s, v) for v in plan.variants)
    return units


def checkpoint_path(output_dir: Path, unit: Unit) -> Path:
    return output_dir / "checkpoints" / f"{unit.phase}-r{unit.repeat}-{unit.truncation}" / f"{unit.scenario}.json"


def _log(path: Path, event: str, unit: Unit, **extra: Any) -> dict[str, Any]:
    row = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, "phase": unit.phase,
           "repeat": unit.repeat, "truncation": unit.truncation, "scenario": unit.scenario,
           "variant": unit.variant, **extra}
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")
    return row


def run_final(*, plan: FinalPlan, permit: Any, study_config_path: str | Path, processed_dir: Path,
              labels_path: Path, output_dir: Path, settings: Any, retriever: Any, repo: Any,
              clients_factory: Callable[[], dict[str, Any]], phases: Sequence[str] | None = None,
              scenarios: Sequence[str] | None = None, limit: int | None = None,
              echo: Callable[[str], None] = lambda _: None) -> list[dict[str, Any]]:
    """Run (or resume) the plan; returns the events of this call (also appended to the log)."""
    from app.agent.matched import run_matched
    from app.agent.runner import prepare_run
    from app.study.config import load_study_config

    config = load_study_config(study_config_path)
    out = Path(output_dir)
    progress = out / "final-progress.jsonl"
    events: list[dict[str, Any]] = []
    units = plan_runs(plan, phases, scenarios)
    groups: dict[tuple[str, int, str, str], list[Unit]] = {}
    for u in units:
        groups.setdefault((u.phase, u.repeat, u.truncation, u.scenario), []).append(u)
    for n, ((ph, rep, trunc, scen), members) in enumerate(groups.items(), 1):
        ckpt = checkpoint_path(out, members[0])
        if ckpt.exists() and json.loads(ckpt.read_text(encoding="utf-8")).get("complete"):
            events.append(_log(progress, "scenario_skipped", members[0], variant="*",
                               checkpoint=str(ckpt)))
            echo(f"[{n}/{len(groups)}] phase {ph} repeat {rep} {trunc} {scen}: checkpoint exists, skipped")
            continue
        run_ids: dict[str, str] = {}
        for u in members:
            prep = prepare_run(processed_dir, labels_path, u.scenario, u.variant, config, limit=limit,
                               truncation=u.truncation, selection=plan.select, permit=permit)
            _log(progress, "start", u, cases=len(prep.cases))
            started = time.perf_counter()
            report = run_matched(prep, settings, clients_factory(), output_dir=out,
                                 study_config_path=study_config_path, retriever=retriever, repo=repo,
                                 vectors=getattr(retriever, "store", None),
                                 embedder=getattr(retriever, "embedder", None), resume=True,
                                 retrieval_mode=plan.retrieval, repeat=u.repeat,
                                 study_part="held-out" if u.scenario in config.split.held_out
                                 else "final-dev")
            wall = round(time.perf_counter() - started, 1)
            arms = report["scores"]["arms"]
            events.append(_log(progress, "done", u, run_id=report["run_id"], wall_seconds=wall,
                               skipped=report["skipped"], cases=len(prep.cases),
                               tokens={a: arms[a]["runs"]["input_tokens"] + arms[a]["runs"]["output_tokens"]
                                       for a in ("single", "graph")}))
            run_ids[u.variant] = report["run_id"]
            echo(f"  {ph} r{rep} {trunc} {scen} {u.variant}: done in {wall} s ({report['run_id']})")
        ckpt.parent.mkdir(parents=True, exist_ok=True)
        ckpt.write_text(json.dumps({"complete": True, "phase": ph, "repeat": rep, "truncation": trunc,
                                    "scenario": scen, "runs": run_ids,
                                    "written_utc": datetime.now(timezone.utc).isoformat(),
                                    "freeze_sha256": getattr(permit, "freeze_sha256", None)},
                                   indent=2) + "\n", encoding="utf-8")
        events.append(_log(progress, "scenario_checkpoint", members[0], variant="*",
                           checkpoint=str(ckpt)))
    return events


def _verdict_correct(kind: str, verdict: str | None) -> float:
    # a failed case (no verdict) counts as not correct: failures are never silent successes
    return 1.0 if verdict == kind else 0.0


def case_rows(runs_dir: str | Path, parts: Iterable[str] = ("held-out",)) -> list[dict[str, Any]]:
    """One row per (case, variant, score row) of every finished run in ``runs_dir`` of ``parts``."""
    wanted = set(parts)
    rows: list[dict[str, Any]] = []
    for scores_path in sorted(Path(runs_dir).glob("*/scores.json")):
        data = json.loads(scores_path.read_text(encoding="utf-8"))
        if data.get("study_part") not in wanted or "per_case" not in data:
            continue
        repeat = data.get("repeat") or 1
        for case in data["per_case"]:
            attack_reach = case["kind"] == "attack" and case["reachable"]
            for arm, r in case["rows"].items():
                rows.append({
                    "study_part": data["study_part"], "scenario": data["scenario"],
                    "truncation": data["truncation"], "repeat": repeat, "variant": data["variant"],
                    "arm": arm, "run_id": scores_path.parent.name,
                    "case_key": f"{data['scenario']}/{data['truncation']}/r{repeat}/{case['case_id']}",
                    "case_id": case["case_id"], "kind": case["kind"], "phase": case["phase"],
                    "reachable": case["reachable"],
                    "coverage_event_reachable": (1.0 if r["coverage_event"] == 1.0 else 0.0)
                    if attack_reach else None,
                    "coverage_time_reachable": (1.0 if r["coverage_time"] == 1.0 else 0.0)
                    if attack_reach else None,
                    "citation_precision_event": r["citation_precision_event"],
                    "citation_precision_time": r["citation_precision_time"],
                    "unsupported_claim_rate": r["unsupported_claim_rate"],
                    "verdict": r["verdict"], "verdict_correct": _verdict_correct(case["kind"], r["verdict"]),
                    "status": r["status"], "cited": r["cited"], "claims": r["claims"],
                    "unsupported_claims": r["unsupported_claims"], "load": r["load"],
                    "input_tokens": r["input_tokens"], "output_tokens": r["output_tokens"],
                    "tool_calls": r["tool_calls"], "latency_seconds": r["latency_seconds"],
                })
    return rows
