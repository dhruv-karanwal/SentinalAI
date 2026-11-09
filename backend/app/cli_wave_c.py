"""Wave C CLI commands: ``rag-index``, ``rag-eval``, ``pilot-estimate``, ``run-matched``, ``run-pilot``.

``run-pilot`` (2026-11-10) runs every (pilot scenario, pilot variant,
truncation) from ``study.json`` ``pilot``, spread first, through
``run_matched(resume=True)``: completed runs are skipped, interrupted ones
continue from their per-case checkpoints, and every start / done / skip is
appended to ``<output-dir>/pilot-progress.jsonl``.

Kept apart from app/main.py so the Wave C surface is in one place; main.py
registers them with :func:`add_parsers` and dispatches with :func:`dispatch`.
Every process sets ``HF_HUB_OFFLINE`` / ``TRANSFORMERS_OFFLINE``; nothing here
downloads. ``pilot-estimate`` and ``run-matched --dry-run`` never call a model.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
DEFAULT_PROCESSED = REPO / "data" / "processed"
DEFAULT_PLATFORM = REPO / "data" / "platform"
DEFAULT_LABELS = REPO / "data" / "raw" / "ait_ads" / "labels.csv"
DEFAULT_STIX = REPO / "data" / "raw" / "mitre" / "enterprise-attack.json"
COMMANDS = ("rag-index", "rag-eval", "pilot-estimate", "run-matched", "run-pilot")


def _offline() -> None:
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"


def add_parsers(sub: Any, study_config: Path, positive_int: Any) -> None:
    idx = sub.add_parser("rag-index", help="Wave C: embed the ATT&CK chunks (local bge-small) into "
                                           "the vector table")
    idx.add_argument("--stix", type=Path, default=DEFAULT_STIX)
    idx.add_argument("--data-dir", type=Path, default=DEFAULT_PLATFORM)

    ev = sub.add_parser("rag-eval", help="Wave C: recall@1/3/5 on the frozen relevance set")
    ev.add_argument("--stix", type=Path, default=DEFAULT_STIX)
    ev.add_argument("--data-dir", type=Path, default=DEFAULT_PLATFORM)
    ev.add_argument("--relevance-set", type=Path, default=None)
    ev.add_argument("--output", type=Path, default=DEFAULT_PROCESSED / "rag" / "relevance_eval.json")
    ev.add_argument("--modes", nargs="+", default=["dense", "lexical", "hybrid"],
                    choices=("dense", "lexical", "hybrid"), help="retrieval modes to evaluate")
    ev.add_argument("--alpha", type=float, default=0.5, help="hybrid dense weight (default 0.5)")

    for name, help_text in (("pilot-estimate", "Wave C: token / call bound of a matched pilot on "
                             "dev scenarios; calls no model"),
                            ("run-matched", "Wave C: M5 single agent vs multi-agent graph, matched "
                             "budgets, same cases and baselines"),
                            ("run-pilot", "Wave C: the whole matched pilot from study.json, resumable")):
        p = sub.add_parser(name, help=help_text)
        if name in ("pilot-estimate", "run-pilot"):
            p.add_argument("--scenarios", nargs="+", default=None,
                           help="dev scenarios (default: pilot.scenarios)")
            p.add_argument("--variants", nargs="+", default=None,
                           help="experiment variants (default: pilot.variants, else all of them)")
            p.add_argument("--truncations", nargs="+", default=None,
                           help="default: pilot.truncation (spread first)")
        else:
            p.add_argument("--scenario", required=True)
            p.add_argument("--variant", required=True)
            p.add_argument("--truncation", default=None)
        if name in ("run-matched", "run-pilot"):
            p.add_argument("--resume", action="store_true", default=name == "run-pilot",
                           help="stable run directory per config hash; skip completed runs and cases"
                                + (" (always on)" if name == "run-pilot" else ""))
            p.add_argument("--retrieval-mode", choices=("dense", "lexical", "hybrid"), default=None,
                           help="search_attack mode of the graph arm (default: pilot.retrieval)")
            p.add_argument("--dry-run", action="store_true")
            p.add_argument("--confirm", action="store_true")
            p.add_argument("--fake-single", type=Path, default=None,
                           help="JSON list of scripted replies for the single agent (FakeClient)")
            p.add_argument("--fake-graph", type=Path, default=None,
                           help="JSON list of scripted replies for the graph (FakeClient)")
            p.add_argument("--no-retrieval", action="store_true",
                           help="run the graph without the ATT&CK vector index")
            p.add_argument("--output-dir", type=Path, default=DEFAULT_PROCESSED / "runs")
            p.add_argument("--data-dir", type=Path, default=DEFAULT_PLATFORM)
        p.add_argument("--limit", type=positive_int, default=None)
        p.add_argument("--select", choices=("interleaved", "reachable"), default=None,
                       help="case selection (default: pilot.select for pilot commands, else interleaved)")
        p.add_argument("--processed-dir", type=Path, default=DEFAULT_PROCESSED)
        p.add_argument("--labels", type=Path, default=DEFAULT_LABELS)
        p.add_argument("--study-config", type=Path, default=study_config)


def dispatch(args: argparse.Namespace) -> int:
    _offline()
    handler = {"rag-index": _rag_index, "rag-eval": _rag_eval, "pilot-estimate": _pilot_estimate,
               "run-matched": _run_matched, "run-pilot": _run_pilot}[args.command]
    return handler(args)


def _retriever(data_dir: Path, mode: str = "dense", kb: Any = None, alpha: float = 0.5) -> Any:
    from app.rag.embedding import DIM, FastEmbedEmbedder
    from app.rag.retriever import AttackRetriever
    from app.rag.vector_store import open_vector_store

    return AttackRetriever(open_vector_store(data_dir, DIM), FastEmbedEmbedder(), mode=mode, kb=kb,
                           alpha=alpha)


def _rag_index(args: argparse.Namespace) -> int:
    from app.intel.attack import AttackKB
    from app.rag.embedding import EmbeddingUnavailable

    try:
        t0 = time.perf_counter()
        retriever = _retriever(args.data_dir)
        kb = AttackKB.from_stix(args.stix)
        n = retriever.index(kb)
    except (EmbeddingUnavailable, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"ATT&CK index: {len(kb.techniques)} techniques (bundle {kb.version}), {n} chunks embedded "
          f"with {retriever.embedder.model_id} (dim {retriever.embedder.dim}) in "
          f"{time.perf_counter() - t0:.1f} s; collection {retriever.collection!r}")
    return 0


def _rag_eval(args: argparse.Namespace) -> int:
    from app.intel.attack import AttackKB
    from app.rag.embedding import EmbeddingUnavailable
    from app.rag.retriever import DEFAULT_RELEVANCE_SET, evaluate, load_relevance_set

    results: dict[str, Any] = {}
    try:
        kb = AttackKB.from_stix(args.stix)
        rel = load_relevance_set(args.relevance_set or DEFAULT_RELEVANCE_SET)
        for mode in args.modes:
            retriever = _retriever(args.data_dir, mode, kb, args.alpha)
            if retriever.store.count(retriever.collection) == 0:
                print("error: the ATT&CK index is empty; run rag-index first", file=sys.stderr)
                return 1
            results[mode] = {"mode": mode, "alpha": args.alpha if mode == "hybrid" else None,
                             **evaluate(retriever, rel, kb)}
    except (EmbeddingUnavailable, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    first = next(iter(results.values()))
    print(f"Relevance set {first['relevance_set']}: {first['queries']} queries (measured, local "
          f"bge-small + BM25; the set is small and was already tried against)")
    for mode, res in results.items():
        cells = "  ".join(f"recall@{k} {res[f'recall@{k}']:.4f} ({res['hits'][f'@{k}']}/{res['queries']})"
                          for k in (1, 3, 5))
        extra = f" alpha {res['alpha']}" if res["alpha"] is not None else ""
        print(f"  {mode:8s}{extra:10s} {cells}")
    for i, q in enumerate(first["per_query"]):
        ranks = "  ".join(f"{m} {results[m]['per_query'][i]['rank']}" for m in results)
        print(f"  {q['id']} expected {q['expected']} ranks: {ranks}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    out = results if len(results) > 1 else first
    args.output.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    return 0


def _prepare(args: argparse.Namespace, scenario: str, variant: str, truncation: str | None) -> Any:
    from app.agent.runner import prepare_run
    from app.study.config import load_study_config

    config = load_study_config(args.study_config)
    select = args.select or (config.pilot_select if args.command in ("pilot-estimate", "run-pilot")
                             else "interleaved")
    return prepare_run(args.processed_dir, args.labels, scenario, variant, config, limit=args.limit,
                       truncation=truncation, selection=select)


def _plan(args: argparse.Namespace) -> list[tuple[str, str, str]]:
    """(scenario, variant, truncation) of the pilot, truncation-major (spread first)."""
    from app.study.config import load_study_config
    from app.study.variants import AlertPool, experiment_variants

    config = load_study_config(args.study_config)
    scenarios = args.scenarios or list(config.pilot_scenarios)
    for s in scenarios:
        config.split.require_dev(s)  # before any file is read
    truncations = args.truncations or list(config.pilot_truncations)
    plan: list[tuple[str, str, str]] = []
    for t in truncations:
        for s in scenarios:
            variants = args.variants or list(config.pilot_variants) or list(experiment_variants(
                AlertPool.from_processed(args.processed_dir, s), config))
            plan.extend((s, v, t) for v in variants)
    return plan


def _retrieval_mode(args: argparse.Namespace) -> str | None:
    from app.study.config import load_study_config

    if args.no_retrieval:
        return None
    mode = args.retrieval_mode or load_study_config(args.study_config).pilot_retrieval
    return None if mode == "none" else str(mode)


def _pilot_estimate(args: argparse.Namespace) -> int:
    from app.agent.config import load_agent_settings
    from app.agent.matched import estimate_matched
    from app.ingestion.records import IngestionError
    from app.study.config import HeldOutScenarioError, load_study_config

    try:
        load_study_config(args.study_config)
        settings = load_agent_settings(args.study_config)
        rows = [(s, v, t, estimate_matched(_prepare(args, s, v, t), settings)) for s, v, t in _plan(args)]
    except (HeldOutScenarioError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except IngestionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print("PILOT ESTIMATE (dev scenarios only; no model was called)")
    print(f"method: {rows[0][3]['method'] if rows else 'n/a'}")
    print(f"{'scenario':16s} {'variant':18s} {'trunc':9s} {'cases':>5s} {'tok bound':>11s} "
          f"{'tool calls':>10s} {'1st prompts single/graph':>26s}")
    total_tok = total_calls = total_cases = 0
    for s, v, t, e in rows:
        fp = e["first_prompt_tokens_estimate"]
        print(f"{s:16s} {v:18s} {t:9s} {e['cases']:>5d} {e['token_bound_total']:>11d} "
              f"{e['tool_call_bound_total']:>10d} {fp['single']:>12d}/{fp['graph_supervisor']:<12d}")
        total_tok += e["token_bound_total"]
        total_calls += e["tool_call_bound_total"]
        total_cases += e["cases"]
    print(f"TOTAL: {len(rows)} runs, {total_cases} cases x 2 arms = {2 * total_cases} case runs, "
          f"token bound {total_tok}, tool-call bound {total_calls}")
    return 0


def _client(path: Path | None, settings: Any) -> Any:
    from app.agent.client import FakeClient, OpenAICompatibleClient
    from app.agent.config import api_key

    if path is not None:
        return FakeClient(json.loads(path.read_text(encoding="utf-8")))
    if not settings.model.configured:
        raise ValueError("no model endpoint configured; set SENTINEL_LLM_BASE_URL / "
                         "SENTINEL_LLM_MODEL (or use --dry-run / --fake-*)")
    return OpenAICompatibleClient(settings.model, api_key=api_key(settings.model))


def _run_matched(args: argparse.Namespace) -> int:
    from app.agent.config import load_agent_settings
    from app.agent.matched import estimate_matched, resume_run_id, run_matched
    from app.ingestion.records import IngestionError
    from app.platform.bootstrap import open_stores
    from app.rag.embedding import EmbeddingUnavailable
    from app.study.config import HeldOutScenarioError

    try:
        settings = load_agent_settings(args.study_config)
        prep = _prepare(args, args.scenario, args.variant, args.truncation)
    except (HeldOutScenarioError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except IngestionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    est = estimate_matched(prep, settings)
    print(f"DEV-SCENARIO MATCHED RUN - {prep.scenario} / {prep.variant} / {prep.truncation}: "
          f"{est['cases']} cases x 2 arms; token bound {est['token_bound_total']}; tool-call bound "
          f"{est['tool_call_bound_total']}\nmethod: {est['method']}")
    if args.dry_run:
        print("DRY RUN: no model was called")
        return 0
    if est["needs_confirm"] and not args.confirm:
        print(f"error: token bound exceeds agent.run_token_budget {est['run_token_budget']}; "
              "use --confirm or a smaller --limit", file=sys.stderr)
        return 2
    try:
        clients = {"single": _client(args.fake_single, settings),
                   "graph": _client(args.fake_graph, settings)}
        mode = _retrieval_mode(args)
        retriever = _graph_retriever(args, mode)
        stores = open_stores(args.data_dir)
    except (ValueError, OSError, EmbeddingUnavailable) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    report = run_matched(prep, settings, clients, output_dir=args.output_dir,
                         study_config_path=args.study_config, retriever=retriever,
                         repo=stores.repo, vectors=retriever.store if retriever else None,
                         embedder=retriever.embedder if retriever else None,
                         resume=args.resume, retrieval_mode=mode)
    if report["skipped"]:
        print(f"already complete (resume): {report['run_dir']}; nothing was run")
    for name, row in report["scores"]["arms"].items():
        print(f"  {name:16s} runs {row['runs']['status']} tokens {row['runs']['input_tokens']}+"
              f"{row['runs']['output_tokens']} tool calls {row['runs']['tool_calls']} budget hit "
              f"{row['runs']['budget_hit']}")
    print(f"Wrote run log to {report['run_dir']}")
    return 0


def _graph_retriever(args: argparse.Namespace, mode: str | None) -> Any:
    if mode is None:
        return None
    kb = None
    if mode != "dense":
        from app.intel.attack import AttackKB
        kb = AttackKB.from_stix(DEFAULT_STIX)
    return _retriever(args.data_dir, mode, kb)


def _run_pilot(args: argparse.Namespace) -> int:
    from app.agent.config import load_agent_settings
    from app.agent.matched import estimate_matched, resume_run_id, run_matched
    from app.ingestion.records import IngestionError
    from app.platform.bootstrap import open_stores
    from app.rag.embedding import EmbeddingUnavailable
    from app.study.config import HeldOutScenarioError

    try:
        settings = load_agent_settings(args.study_config)
        plan = _plan(args)
        preps = [(s, v, t, _prepare(args, s, v, t)) for s, v, t in plan]
    except (HeldOutScenarioError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except IngestionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    ests = [estimate_matched(p, settings) for *_, p in preps]
    total_tok = sum(e["token_bound_total"] for e in ests)
    cases = sum(e["cases"] for e in ests)
    mode = _retrieval_mode(args)
    print(f"DEV-SCENARIO MATCHED PILOT (pilot material, not paper results): {len(plan)} runs, "
          f"{cases} cases x 2 arms = {2 * cases} case runs; token bound {total_tok}; retrieval "
          f"{mode or 'off'}; resume on")
    if args.dry_run:
        for (s, v, t, _), e in zip(preps, ests):
            print(f"  {s:16s} {v:14s} {t:9s} cases {e['cases']:>3d} token bound {e['token_bound_total']}")
        print("DRY RUN: no model was called")
        return 0
    if total_tok > settings.agent.run_token_budget and not args.confirm:
        print(f"error: token bound {total_tok} exceeds agent.run_token_budget "
              f"{settings.agent.run_token_budget}; use --confirm", file=sys.stderr)
        return 2
    try:
        retriever = _graph_retriever(args, mode)
        stores = open_stores(args.data_dir)
        out = Path(args.output_dir)
        out.mkdir(parents=True, exist_ok=True)
    except (ValueError, OSError, EmbeddingUnavailable) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    progress = out / "pilot-progress.jsonl"

    def log(event: str, s: str, v: str, t: str, **extra: Any) -> None:
        from datetime import datetime, timezone
        row = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, "scenario": s,
               "variant": v, "truncation": t, **extra}
        with progress.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row) + "\n")

    for n, (s, v, t, prep) in enumerate(preps, 1):
        clients = {"single": _client(args.fake_single, settings),
                   "graph": _client(args.fake_graph, settings)}
        run_id = resume_run_id(prep, settings, {a: c.model_id for a, c in clients.items()},
                               args.study_config, retrieval=mode)
        if (out / run_id / "scores.json").exists():
            log("skipped", s, v, t, run_id=run_id)
            print(f"[{n}/{len(preps)}] {s} {v} {t}: already complete, skipped")
            continue
        log("start", s, v, t, run_id=run_id,
            checkpoints=len(list((out / run_id / "cases").glob("*.checkpoint.json")))
            if (out / run_id / "cases").exists() else 0)
        started = time.perf_counter()
        report = run_matched(prep, settings, clients, output_dir=out, study_config_path=args.study_config,
                             retriever=retriever, repo=stores.repo,
                             vectors=retriever.store if retriever else None,
                             embedder=retriever.embedder if retriever else None,
                             resume=True, retrieval_mode=mode)
        wall = round(time.perf_counter() - started, 1)
        arms = report["scores"]["arms"]
        log("done", s, v, t, run_id=report["run_id"], wall_seconds=wall,
            tokens={a: arms[a]["runs"]["input_tokens"] + arms[a]["runs"]["output_tokens"]
                    for a in ("single", "graph")})
        print(f"[{n}/{len(preps)}] {s} {v} {t}: done in {wall} s ({report['run_dir']})")
    print(f"progress log: {progress}")
    return 0
