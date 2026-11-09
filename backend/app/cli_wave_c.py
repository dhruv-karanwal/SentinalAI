"""Wave C CLI commands: ``rag-index``, ``rag-eval``, ``pilot-estimate``, ``run-matched``.

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
COMMANDS = ("rag-index", "rag-eval", "pilot-estimate", "run-matched")


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

    for name, help_text in (("pilot-estimate", "Wave C: token / call bound of a matched pilot on "
                             "dev scenarios; calls no model"),
                            ("run-matched", "Wave C: M5 single agent vs multi-agent graph, matched "
                             "budgets, same cases and baselines")):
        p = sub.add_parser(name, help=help_text)
        if name == "pilot-estimate":
            p.add_argument("--scenarios", nargs="+", default=None,
                           help="dev scenarios (default: pilot.scenarios)")
            p.add_argument("--variants", nargs="+", default=None,
                           help="experiment variants (default: all of them)")
            p.add_argument("--truncations", nargs="+", default=None,
                           help="default: pilot.truncation")
        else:
            p.add_argument("--scenario", required=True)
            p.add_argument("--variant", required=True)
            p.add_argument("--truncation", default=None)
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
        p.add_argument("--select", choices=("interleaved", "reachable"), default="interleaved")
        p.add_argument("--processed-dir", type=Path, default=DEFAULT_PROCESSED)
        p.add_argument("--labels", type=Path, default=DEFAULT_LABELS)
        p.add_argument("--study-config", type=Path, default=study_config)


def dispatch(args: argparse.Namespace) -> int:
    _offline()
    handler = {"rag-index": _rag_index, "rag-eval": _rag_eval, "pilot-estimate": _pilot_estimate,
               "run-matched": _run_matched}[args.command]
    return handler(args)


def _retriever(data_dir: Path) -> Any:
    from app.rag.embedding import DIM, FastEmbedEmbedder
    from app.rag.retriever import AttackRetriever
    from app.rag.vector_store import open_vector_store

    return AttackRetriever(open_vector_store(data_dir, DIM), FastEmbedEmbedder())


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

    try:
        retriever = _retriever(args.data_dir)
        if retriever.store.count(retriever.collection) == 0:
            print("error: the ATT&CK index is empty; run rag-index first", file=sys.stderr)
            return 1
        kb = AttackKB.from_stix(args.stix)
        rel = load_relevance_set(args.relevance_set or DEFAULT_RELEVANCE_SET)
        res = evaluate(retriever, rel, kb)
    except (EmbeddingUnavailable, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"Relevance set {res['relevance_set']}: {res['queries']} queries (measured, local "
          f"{retriever.embedder.model_id})")
    for k in (1, 3, 5):
        print(f"  recall@{k}: {res[f'recall@{k}']:.4f} ({res['hits'][f'@{k}']}/{res['queries']})")
    for q in res["per_query"]:
        print(f"  {q['id']} rank {q['rank']} expected {q['expected']} top5 {q['retrieved']}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
    return 0


def _prepare(args: argparse.Namespace, scenario: str, variant: str, truncation: str | None) -> Any:
    from app.agent.runner import prepare_run
    from app.study.config import load_study_config

    return prepare_run(args.processed_dir, args.labels, scenario, variant,
                       load_study_config(args.study_config), limit=args.limit,
                       truncation=truncation, selection=args.select)


def _pilot_estimate(args: argparse.Namespace) -> int:
    from app.agent.config import load_agent_settings
    from app.agent.matched import estimate_matched
    from app.ingestion.records import IngestionError
    from app.study.config import HeldOutScenarioError, load_study_config
    from app.study.variants import AlertPool, experiment_variants

    try:
        config = load_study_config(args.study_config)
        settings = load_agent_settings(args.study_config)
        scenarios = args.scenarios or list(config.pilot_scenarios)
        for s in scenarios:
            config.split.require_dev(s)
        truncations = args.truncations or list(config.pilot_truncations)
        rows = []
        for s in scenarios:
            variants = args.variants or list(experiment_variants(
                AlertPool.from_processed(args.processed_dir, s), config))
            for v in variants:
                for t in truncations:
                    est = estimate_matched(_prepare(args, s, v, t), settings)
                    rows.append((s, v, t, est))
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
    print(f"TOTAL: {len(rows)} runs, {total_cases} cases x 2 arms, token bound {total_tok}, tool-call "
          f"bound {total_calls}")
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
    from app.agent.matched import estimate_matched, run_matched
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
        retriever = None if args.no_retrieval else _retriever(args.data_dir)
        stores = open_stores(args.data_dir)
    except (ValueError, OSError, EmbeddingUnavailable) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    report = run_matched(prep, settings, clients, output_dir=args.output_dir,
                         study_config_path=args.study_config, retriever=retriever,
                         repo=stores.repo, vectors=retriever.store if retriever else None,
                         embedder=retriever.embedder if retriever else None)
    for name, row in report["scores"]["arms"].items():
        print(f"  {name:16s} runs {row['runs']['status']} tokens {row['runs']['input_tokens']}+"
              f"{row['runs']['output_tokens']} tool calls {row['runs']['tool_calls']} budget hit "
              f"{row['runs']['budget_hit']}")
    print(f"Wrote run log to {report['run_dir']}")
    return 0
