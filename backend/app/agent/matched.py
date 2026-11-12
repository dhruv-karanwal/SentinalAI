"""Matched-budget comparison: M5 single agent vs the multi-agent graph on the same cases (Wave C).

Both arms get **identical per-case budgets** from the one ``agent`` section
of study.json (``max_tokens_per_case``, ``max_tool_calls``,
``repair_retries``), enforced in code with a hard stop (M5 loop:
:func:`app.agent.agent.investigate`; graph: :mod:`app.agent.graph`). Both are
scored by the same :func:`score_case` against the same baselines, and both
pass through the same :func:`~app.agent.verifier.verify_answer`.

Scores are reported twice per arm, **before** and **after** the verifier
(``<arm>`` and ``<arm>+verifier``): which one is the headline is a study
decision left to the user; both are recorded so neither is lost.

Run log (git-ignored ``data/processed/runs/<run_id>/``): ``manifest.json``
(config hash, budgets, prompt versions, per case and arm: status, parse
status, tokens in/out, requests, tool calls, latency, budget hit, citations
and claims kept/dropped), ``cases/<n>.<arm>.json`` (transcripts, request
logs, id maps, verifier detail), ``scores.json``.

Resume (2026-11-10, ``resume=True``): the run directory is
``matched-<config hash[:16]>`` (stable for one configuration, so a restart
finds it). After each case both arms' summaries and the inputs of the four
score rows (cited ids and claims) go to ``cases/<n>.checkpoint.json``; a
restart reloads checkpointed cases instead of calling the model again and
re-scores them with the same ``score_case``. A directory that already holds
``scores.json`` is a completed run: it is returned unchanged (``skipped``)
and no model is called. Only one process may write a run directory at a time.

Dry run (:func:`estimate_matched`): token bound = cases x
``max_tokens_per_case`` per arm (no request may start that could exceed it;
prompts estimated at 3 characters per token), tool calls bound = cases x
``max_tool_calls`` per arm, first-prompt estimate = system prompt + case
brief at 3 characters per token. No model is called.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.agent.agent import CaseRun, conservative_tokens, investigate
from app.agent.client import ChatClient
from app.agent.config import AgentSettings
from app.agent.graph import (
    AGENTS,
    GRAPH_PROMPT_VERSION,
    PROMPTS,
    PROMPTS_SHA256,
    SUPERVISOR_PROMPT,
    GraphRun,
    GraphSettings,
    run_graph,
)
from app.agent.multi_tools import CaseMemory, MultiAgentToolkit, session_id_for
from app.agent.protocol import PROMPT_VERSION, SYSTEM_PROMPT
from app.agent.rag_tool import AttackSearchTool, Retriever
from app.agent.runner import PreparedRun, _dump, _run_dir, _toolkit, _verdicts
from app.agent.verifier import verify_answer
from app.evaluation.case_scoring import CaseScore, alert_claim_index, alert_quote_index, score_case
from app.evaluation.metrics import Claim
from app.rag.embedding import Embedder
from app.rag.vector_store import VectorStore
from app.storage.repository import Repository
from app.study.baselines import matched_k
from app.study.cases import baseline_summaries, summarize_scores

ARMS = ("single", "graph")
SCORE_ROWS = ("single", "single+verifier", "graph", "graph+verifier")
BUDGET_STATUSES = ("token_budget_exceeded", "tool_budget_exceeded")
_SUMMARY_FIELDS = ("status", "parse_status", "verdict", "input_tokens", "output_tokens",
                   "usage_reported", "requests", "tool_calls", "repairs", "latency_seconds",
                   "wall_seconds", "error")


def estimate_matched(prep: PreparedRun, settings: AgentSettings,
                     graph: GraphSettings = GraphSettings()) -> dict[str, Any]:
    a = settings.agent
    first_single = first_graph = 0
    for i, view in enumerate(prep.views):
        kit = _toolkit(prep, i, [prep.pool.alert(e) for e in view.entries], settings, "estimate")
        brief = {"role": "user", "content": kit.brief()}
        first_single += conservative_tokens([{"role": "system", "content": SYSTEM_PROMPT}, brief])
        first_graph += conservative_tokens([{"role": "system", "content": SUPERVISOR_PROMPT}, brief])
    n = len(prep.cases)
    per_arm = n * a.max_tokens_per_case
    return {
        "cases": n, "arms": list(ARMS),
        "token_bound_per_case": a.max_tokens_per_case,
        "token_bound_per_arm": per_arm, "token_bound_total": per_arm * len(ARMS),
        "tool_call_bound_per_case": a.max_tool_calls,
        "tool_call_bound_total": n * a.max_tool_calls * len(ARMS),
        "max_requests_per_case": {
            "single": a.max_tool_calls + a.repair_retries + 2,
            "graph": "bounded by the token budget (supervisor steps <= "
                     f"{graph.max_supervisor_steps}, tool calls <= {a.max_tool_calls})"},
        "first_prompt_tokens_estimate": {"single": first_single, "graph_supervisor": first_graph},
        "run_token_budget": a.run_token_budget,
        "needs_confirm": per_arm * len(ARMS) > a.run_token_budget,
        "method": ("upper bounds: cases x max_tokens_per_case per arm (no request may start that "
                   "could exceed the per-case budget; prompts estimated at 3 characters per token); "
                   "tool calls: cases x max_tool_calls per arm; first prompts: system prompt + case "
                   "brief at 3 characters per token. No model is called."),
    }


def matched_hash(prep: PreparedRun, settings: AgentSettings, model_ids: dict[str, str],
                 study_config_path: str | Path, graph: GraphSettings,
                 retrieval: str | None = None, repeat: int | None = None) -> str:
    payload: dict[str, Any] = {
        "retrieval": retrieval,
        "study_config_sha256": hashlib.sha256(Path(study_config_path).read_bytes()).hexdigest(),
        "model": settings.model.public(), "model_ids": model_ids, "agent": asdict(settings.agent),
        "graph": asdict(graph), "prompt_version": PROMPT_VERSION,
        "graph_prompt_version": GRAPH_PROMPT_VERSION, "graph_prompts_sha256": PROMPTS_SHA256,
        "system_prompt_sha256": hashlib.sha256(SYSTEM_PROMPT.encode()).hexdigest(),
        "scenario": prep.scenario, "variant": prep.variant, "truncation": prep.truncation,
        "case_ids": [c.case_id for c in prep.cases],
    }
    if repeat is not None:  # final study repeats; absent for the pilot, so its hashes are unchanged
        payload["repeat"] = repeat
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def resume_run_id(prep: PreparedRun, settings: AgentSettings, model_ids: dict[str, str],
                  study_config_path: str | Path, graph: GraphSettings = GraphSettings(),
                  retrieval: str | None = None, repeat: int | None = None) -> str:
    """The stable run directory name a resumable run of this configuration uses."""
    digest = matched_hash(prep, settings, model_ids, study_config_path, graph, retrieval, repeat)
    return f"matched-{digest[:16]}"


def _record(run: CaseRun, verification: dict[str, Any]) -> dict[str, Any]:
    return {"status": run.status, "parse_status": run.parse_status, "verdict": run.verdict,
            "error": run.error, "input_tokens": run.input_tokens, "output_tokens": run.output_tokens,
            "usage_reported": run.usage_reported, "requests": run.requests,
            "tool_calls": run.tool_calls, "repairs": run.repairs,
            "latency_seconds": run.latency_seconds, "wall_seconds": run.wall_seconds,
            "budget_hit": run.status if run.status in BUDGET_STATUSES else None,
            "verification": {k: v for k, v in verification.items()
                             if k not in ("dropped_citations", "dropped_claims")}}


def _arm_row(prep: PreparedRun, scores: list[CaseScore], runs: Sequence[CaseRun]) -> dict[str, Any]:
    row = summarize_scores(prep.cases, scores, prep.reachable)
    row["runs"] = {
        "status": dict(sorted(Counter(r.status for r in runs).items())),
        "parse_status": dict(sorted(Counter(str(r.parse_status) for r in runs).items())),
        "input_tokens": sum(r.input_tokens for r in runs),
        "output_tokens": sum(r.output_tokens for r in runs),
        "tool_calls": sum(r.tool_calls for r in runs),
        "latency_seconds": sum(r.latency_seconds for r in runs),
        "budget_hit": sum(1 for r in runs if r.status in BUDGET_STATUSES),
    }
    row["verdict"] = _verdicts(prep.cases, runs)
    return row


def _per_case(prep: PreparedRun, scores: dict[str, list[CaseScore]],
              runs: dict[str, list[CaseRun]]) -> list[dict[str, Any]]:
    """One row per case: kind, reachability, and every score row's per-case score + verdict.

    Lets the statistics pair cases across arms and variants without re-running anything.
    """
    out = []
    for i, case in enumerate(prep.cases):
        rows = {}
        for name, sc in scores.items():
            run = runs[name.split("+")[0]][i]
            rows[name] = {**asdict(sc[i]), "verdict": run.verdict, "status": run.status,
                          "input_tokens": run.input_tokens, "output_tokens": run.output_tokens,
                          "tool_calls": run.tool_calls, "latency_seconds": run.latency_seconds}
        out.append({"index": i, "case_id": case.case_id, "kind": case.kind.value,
                    "phase": case.phase, "reachable": case.phase in prep.reachable, "rows": rows})
    return out


def run_matched(prep: PreparedRun, settings: AgentSettings, clients: dict[str, ChatClient], *,
                output_dir: str | Path, study_config_path: str | Path,
                retriever: Retriever | None = None, repo: Repository | None = None,
                vectors: VectorStore | None = None, embedder: Embedder | None = None,
                graph: GraphSettings = GraphSettings(), now: datetime | None = None,
                on_case: Callable[[int, str, CaseRun], None] | None = None,
                resume: bool = False, retrieval_mode: str | None = None,
                repeat: int | None = None, study_part: str = "adhoc") -> dict[str, Any]:
    started = now or datetime.now(timezone.utc)
    model_ids = {arm: clients[arm].model_id for arm in ARMS}
    retrieval = (retrieval_mode or "dense") if retriever is not None else None
    digest = matched_hash(prep, settings, model_ids, study_config_path, graph, retrieval, repeat)
    split = "held-out" if prep.scenario in prep.config.split.held_out else "dev"
    if resume:
        run_id = resume_run_id(prep, settings, model_ids, study_config_path, graph, retrieval, repeat)
        run_dir = Path(output_dir) / run_id
        if (run_dir / "scores.json").exists():
            return {"run_id": run_id, "run_dir": str(run_dir), "config_hash": digest, "skipped": True,
                    "resumed_cases": [],
                    "manifest": json.loads((run_dir / "manifest.json").read_text(encoding="utf-8")),
                    "scores": json.loads((run_dir / "scores.json").read_text(encoding="utf-8"))}
        run_dir.mkdir(parents=True, exist_ok=True)
    else:
        run_id, run_dir = _run_dir(Path(output_dir), started, digest)
        run_dir.mkdir(parents=True)
    scores: dict[str, list[CaseScore]] = {k: [] for k in SCORE_ROWS}
    runs: dict[str, list[CaseRun]] = {arm: [] for arm in ARMS}
    records = []
    resumed: list[int] = []
    for i, (case, view) in enumerate(zip(prep.cases, prep.views)):
        alerts = [prep.pool.alert(e) for e in view.entries]
        index, quotes = alert_claim_index(alerts), alert_quote_index(alerts)

        def score(cited: Sequence[str], claims: Sequence[Any]) -> CaseScore:
            return score_case(case, view, cited, claims=claims, claim_index=index, quote_index=quotes)

        checkpoint = run_dir / f"cases/{i:03d}.checkpoint.json"
        if resume and checkpoint.exists():
            cp = json.loads(checkpoint.read_text(encoding="utf-8"))
            if cp.get("config_hash") == digest and cp.get("case_id") == case.case_id:
                for row in SCORE_ROWS:
                    inp = cp["score_inputs"][row]
                    scores[row].append(score(inp["cited"], [Claim(**c) for c in inp["claims"]]))
                runs["single"].append(CaseRun(**cp["runs"]["single"]))
                runs["graph"].append(GraphRun(**cp["runs"]["graph"]))
                records.append(cp["record"])
                resumed.append(i)
                continue

        kit = _toolkit(prep, i, alerts, settings, f"{digest}:single")
        single = investigate(clients["single"], kit, settings.agent, settings.model)
        checked = verify_answer(single.cited_alert_ids, single.claims, alerts)
        single_ver = {**checked.summary(), "dropped_citations": checked.dropped_citations,
                      "dropped_claims": checked.dropped_claims}
        scores["single"].append(score(single.cited_alert_ids, single.claims))
        scores["single+verifier"].append(score(checked.cited, checked.claims))
        runs["single"].append(single)

        salt = f"{digest}:graph:{i}"
        gkit = _toolkit(prep, i, alerts, settings, f"{digest}:graph")
        memory = CaseMemory(session_id_for(salt), repo, vectors, embedder)
        mkit = MultiAgentToolkit(gkit, memory, AttackSearchTool(retriever) if retriever else None)
        g: GraphRun = run_graph(clients["graph"], mkit, alerts, settings.agent, settings.model, graph)
        scores["graph"].append(score(g.raw_cited_alert_ids, g.raw_claims))
        scores["graph+verifier"].append(score(g.cited_alert_ids, g.claims))
        runs["graph"].append(g)

        _dump(run_dir / f"cases/{i:03d}.single.json", {
            "case_id": case.case_id, "messages": single.transcript, "requests": single.request_log,
            "final": single.final, "id_map": kit.id_map, "verification": single_ver})
        _dump(run_dir / f"cases/{i:03d}.graph.json", {
            "case_id": case.case_id, "messages": g.transcript, "requests": g.request_log,
            "final": g.final, "id_map": gkit.id_map, "trace": g.trace, "notes": memory.recall(),
            "verification": g.verification, "forced_report": g.forced_report,
            "turns_without_note": g.turns_without_note, "memory_session": memory.session_id})
        record = {"index": i, "case_id": case.case_id, "kind": case.kind.value,
                  "phase": case.phase, "alerts": len(alerts),
                  "single": _record(single, single_ver),
                  "graph": {**_record(g, g.verification), "trace": g.trace, "notes": g.notes}}
        records.append(record)
        inputs = {"single": (single.cited_alert_ids, single.claims),
                  "single+verifier": (checked.cited, checked.claims),
                  "graph": (g.raw_cited_alert_ids, g.raw_claims),
                  "graph+verifier": (g.cited_alert_ids, g.claims)}
        _dump(checkpoint, {
            "config_hash": digest, "case_id": case.case_id, "record": record,
            "score_inputs": {row: {"cited": list(c), "claims": [asdict(x) for x in cl]}
                             for row, (c, cl) in inputs.items()},
            "runs": {"single": {f: getattr(single, f) for f in _SUMMARY_FIELDS},
                     "graph": {**{f: getattr(g, f) for f in _SUMMARY_FIELDS}, "trace": g.trace,
                               "notes": g.notes}}})
        for arm, r in (("single", single), ("graph", g)):
            if on_case:
                on_case(i, arm, r)

    k = matched_k(sum(s.cited for s in scores["graph+verifier"] + scores["single+verifier"])
                  / max(1, 2 * len(prep.cases)))
    rows = {name: _arm_row(prep, s, runs[name.split("+")[0]]) for name, s in scores.items()}
    note = ("DEV-SCENARIO MATCHED-BUDGET RUN (pilot material on a dev scenario; not held-out "
            "results). Both arms and the baselines are scored on the same cases."
            if split == "dev" else
            "HELD-OUT MATCHED-BUDGET RUN (final study, after the protocol freeze). Both arms and "
            "the baselines are scored on the same cases.")
    score_report = {
        "note": note, "scenario_split": split, "study_part": study_part, "repeat": repeat,
        "scenario": prep.scenario, "variant": prep.variant, "truncation": prep.truncation,
        "headline": "coverage by event_label on alert-reachable phases; time_label = sensitivity",
        "verifier_note": "each arm is reported before and after the evidence verifier",
        "matched_k": k, "arms": rows,
        "baselines": baseline_summaries(prep.cases, prep.views, prep.pool, prep.config.baselines,
                                        prep.reachable, matched=k),
        "per_case": _per_case(prep, scores, runs),
    }
    manifest = {
        "run_id": run_id, "config_hash": digest, "started_utc": started.isoformat(),
        "scenario": prep.scenario, "scenario_split": split, "study_part": study_part,
        "repeat": repeat, "variant": prep.variant,
        "truncation": prep.truncation, "study_config": Path(study_config_path).name,
        "model": {"model_ids": model_ids, **settings.model.public()},
        "agent_budgets_both_arms": asdict(settings.agent), "graph_settings": asdict(graph),
        "prompt_versions": {"single": PROMPT_VERSION, "graph": GRAPH_PROMPT_VERSION},
        "graph_agents": list(AGENTS), "graph_prompts_sha256": PROMPTS_SHA256,
        "graph_prompt_chars": {k: len(v) for k, v in PROMPTS.items()},
        "retrieval": retriever is not None, "retrieval_mode": retrieval,
        "estimate": estimate_matched(prep, settings, graph),
        "resumed_cases": resumed, "cases": records,
    }
    _dump(run_dir / "manifest.json", manifest)
    _dump(run_dir / "scores.json", score_report)
    return {"run_id": run_id, "run_dir": str(run_dir), "config_hash": digest, "skipped": False,
            "resumed_cases": resumed, "manifest": manifest, "scores": score_report}
