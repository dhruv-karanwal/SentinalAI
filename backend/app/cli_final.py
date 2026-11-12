"""Final-study CLI: ``protocol-freeze``, ``final-plan``, ``run-final``, ``study-stats``,
``export-paper-assets``.

- ``protocol-freeze`` writes experiments/freeze/protocol-freeze.json (see
  :mod:`app.study.freeze`); the model id comes from the configured endpoint
  (``SENTINEL_LLM_MODEL`` or study.json), the optional digest from
  ``--model-digest`` (e.g. ``ollama list``).
- ``run-final`` runs the plan of experiments/config/final_study.json phase by
  phase. Held-out scenarios need ``--allow-held-out``, which works only when
  the freeze exists and every hash still matches; every attempt is logged to
  ``<output-dir>/held-out-access.jsonl``. ``--dry-run`` prints the plan and
  the token bound and calls nothing (it still needs the permit, because it
  reads the held-out alert files).
- ``study-stats`` prints the declared comparison family on the run files.
- ``export-paper-assets`` writes results/ (:mod:`app.study.paper_assets`).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
DEFAULT_PROCESSED = REPO / "data" / "processed"
DEFAULT_PLATFORM = REPO / "data" / "platform"
DEFAULT_LABELS = REPO / "data" / "raw" / "ait_ads" / "labels.csv"
DEFAULT_FINAL_RUNS = DEFAULT_PROCESSED / "runs" / "final"
COMMANDS = ("protocol-freeze", "final-plan", "run-final", "study-stats", "export-paper-assets")


def add_parsers(sub: Any, study_config: Path, positive_int: Any) -> None:
    from app.study.freeze import DEFAULT_FINAL_PLAN, DEFAULT_FREEZE, DEFAULT_STATISTICS

    fr = sub.add_parser("protocol-freeze", help="final study: hash the protocol before held-out runs")
    fr.add_argument("--output", type=Path, default=DEFAULT_FREEZE)
    fr.add_argument("--model-digest", default=None, help="model digest, e.g. from `ollama list`")
    fr.add_argument("--force", action="store_true", help="overwrite an existing freeze")

    for name, help_text in (("final-plan", "final study: print the plan and token bound (no model)"),
                            ("run-final", "final study: run / resume the held-out plan")):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--phases", nargs="+", default=None, help="default: every phase in order")
        p.add_argument("--scenarios", nargs="+", default=None)
        p.add_argument("--allow-held-out", action="store_true",
                       help="needed for held-out scenarios; only valid with a matching protocol freeze")
        p.add_argument("--limit", type=positive_int, default=None)
        p.add_argument("--output-dir", type=Path, default=DEFAULT_FINAL_RUNS)
        p.add_argument("--data-dir", type=Path, default=DEFAULT_PLATFORM)
        p.add_argument("--processed-dir", type=Path, default=DEFAULT_PROCESSED)
        p.add_argument("--labels", type=Path, default=DEFAULT_LABELS)
        p.add_argument("--final-plan", type=Path, default=DEFAULT_FINAL_PLAN)
        p.add_argument("--freeze", type=Path, default=DEFAULT_FREEZE)
        if name == "run-final":
            p.add_argument("--confirm", action="store_true")
            p.add_argument("--dry-run", action="store_true")

    for name in ("study-stats", "export-paper-assets"):
        p = sub.add_parser(name, help="final study: " + ("declared comparisons on run files"
                                                         if name == "study-stats" else
                                                         "write results/ from run files"))
        p.add_argument("--runs-dir", type=Path, default=DEFAULT_FINAL_RUNS,
                       help="held-out run directory (default runs/final)")
        p.add_argument("--pilot-runs-dir", type=Path, default=DEFAULT_PROCESSED / "runs")
        p.add_argument("--freeze", type=Path, default=DEFAULT_FREEZE)
        if name == "export-paper-assets":
            p.add_argument("--results-dir", type=Path, default=REPO / "results")
        else:
            p.add_argument("--part", choices=("pilot", "held-out"), default="held-out")

    for name in COMMANDS:
        p = sub.choices[name]
        p.add_argument("--study-config", type=Path, default=study_config)
        p.add_argument("--statistics-config", type=Path, default=DEFAULT_STATISTICS)


def dispatch(args: argparse.Namespace) -> int:
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    return {"protocol-freeze": _freeze, "final-plan": _final, "run-final": _final,
            "study-stats": _stats, "export-paper-assets": _export}[args.command](args)


def _model_id(args: argparse.Namespace) -> str | None:
    from app.agent.config import load_agent_settings
    settings = load_agent_settings(args.study_config)
    return settings.model.model if settings.model.configured else None


def _freeze(args: argparse.Namespace) -> int:
    from app.study.freeze import compute_freeze, write_freeze

    model = _model_id(args)
    if model is None:
        print("error: no model endpoint configured (SENTINEL_LLM_BASE_URL / SENTINEL_LLM_MODEL); "
              "the freeze records the model id", file=sys.stderr)
        return 2
    if args.output.exists() and not args.force:
        print(f"error: {args.output} exists; a freeze is written once (use --force only to redo "
              "it before any held-out run)", file=sys.stderr)
        return 2
    from app.study.freeze import DEFAULT_FINAL_PLAN
    manifest = compute_freeze(study_config=args.study_config, statistics_config=args.statistics_config,
                              final_plan=DEFAULT_FINAL_PLAN, model_id=model,
                              model_digest=args.model_digest)
    path = write_freeze(manifest, args.output)
    print(f"PROTOCOL FREEZE {manifest['freeze_sha256']}\nmodel {model} digest {args.model_digest}\n"
          f"git commit {manifest['git_commit']}\nwrote {path}")
    for k, v in manifest["hashes"].items():
        print(f"  {k:22s} {v}")
    return 0


def _final(args: argparse.Namespace) -> int:
    from app.agent.config import load_agent_settings
    from app.agent.matched import estimate_matched
    from app.agent.runner import prepare_run
    from app.ingestion.records import IngestionError
    from app.study.config import HeldOutScenarioError, load_study_config
    from app.study.final_runs import load_final_plan, plan_runs, run_final
    from app.study.freeze import FreezeError, authorize_held_out

    config = load_study_config(args.study_config)
    settings = load_agent_settings(args.study_config)
    plan = load_final_plan(args.final_plan)
    try:
        units = plan_runs(plan, args.phases, args.scenarios)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    permit = None
    if any(u.scenario in config.split.held_out for u in units):
        if not args.allow_held_out:
            print("error: the plan contains held-out scenarios; pass --allow-held-out (needs a "
                  "matching protocol freeze)", file=sys.stderr)
            return 2
        model = settings.model.model if settings.model.configured else ""
        try:
            permit = authorize_held_out(args.freeze, study_config=args.study_config,
                                        statistics_config=args.statistics_config,
                                        final_plan=args.final_plan, model_id=model or "",
                                        access_log=args.output_dir / "held-out-access.jsonl",
                                        reason=f"{args.command} phases={args.phases} "
                                               f"scenarios={args.scenarios} limit={args.limit}")
        except FreezeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if args.command == "final-plan" or getattr(args, "dry_run", False):
        total = cases = 0
        try:
            for u in units:
                prep = prepare_run(args.processed_dir, args.labels, u.scenario, u.variant, config,
                                   limit=args.limit, truncation=u.truncation, selection=plan.select,
                                   permit=permit)
                e = estimate_matched(prep, settings)
                total += e["token_bound_total"]
                cases += e["cases"]
                print(f"  {u.phase:4s} r{u.repeat} {u.truncation:9s} {u.scenario:10s} {u.variant:12s} "
                      f"cases {e['cases']:>3d} token bound {e['token_bound_total']}")
        except (IngestionError, HeldOutScenarioError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(f"FINAL PLAN: {len(units)} runs, {cases} cases x 2 arms = {2 * cases} case runs; token "
              f"bound {total}. DRY RUN: no model was called")
        return 0
    if not settings.model.configured:
        print("error: no model endpoint configured", file=sys.stderr)
        return 2
    if not args.confirm:
        print("error: run-final calls the model for many hours; pass --confirm", file=sys.stderr)
        return 2
    from app.agent.client import OpenAICompatibleClient
    from app.agent.config import api_key
    from app.cli_wave_c import _graph_retriever
    from app.platform.bootstrap import open_stores

    mode_args = argparse.Namespace(data_dir=args.data_dir)
    retriever = _graph_retriever(mode_args, plan.retrieval)
    stores = open_stores(args.data_dir)

    def clients() -> dict[str, Any]:
        return {arm: OpenAICompatibleClient(settings.model, api_key=api_key(settings.model))
                for arm in ("single", "graph")}

    try:
        events = run_final(plan=plan, permit=permit, study_config_path=args.study_config,
                           processed_dir=args.processed_dir, labels_path=args.labels,
                           output_dir=args.output_dir, settings=settings, retriever=retriever,
                           repo=stores.repo, clients_factory=clients, phases=args.phases,
                           scenarios=args.scenarios, limit=args.limit,
                           echo=lambda m: print(m, flush=True))
    except (IngestionError, HeldOutScenarioError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    done = sum(1 for e in events if e["event"] == "done")
    print(f"run-final: {done} runs finished or reused; progress log "
          f"{args.output_dir / 'final-progress.jsonl'}")
    return 0


def _stats(args: argparse.Namespace) -> int:
    from app.study.final_runs import case_rows
    from app.study.stats import compare_family, load_statistics_config

    cfg = load_statistics_config(args.statistics_config)
    raw = json.loads(Path(args.statistics_config).read_text(encoding="utf-8"))
    runs = args.runs_dir if args.part == "held-out" else args.pilot_runs_dir
    rows = [r for r in case_rows(runs, [args.part])
            if r["truncation"] == raw.get("primary_truncation", "spread")
            and r["repeat"] == raw.get("primary_repeat", 1)]
    if not rows:
        print(f"no finished {args.part} runs in {runs}")
        return 1
    label = "pilot, not paper results" if args.part == "pilot" else "held-out"
    print(f"DECLARED COMPARISONS ({label}); paired bootstrap, Holm over the family")
    for r in compare_family(rows, cfg):
        print(f"  {r['name']}: n {r['n']} diff {r['difference']} CI [{r['ci_low']}, {r['ci_high']}] "
              f"p {r['p_value']} p_holm {r['p_holm']}")
    return 0


def _export(args: argparse.Namespace) -> int:
    import shutil
    import tempfile

    from app.study.paper_assets import export_paper_assets

    # pilot and held-out runs live in different folders: link both into one view by copying the
    # scores.json files only (small) into a temporary directory
    with tempfile.TemporaryDirectory() as tmp:
        view = Path(tmp)
        for src in (args.pilot_runs_dir, args.runs_dir):
            if not Path(src).exists():
                continue
            for scores in Path(src).glob("*/scores.json"):
                dest = view / scores.parent.name
                dest.mkdir(exist_ok=True)
                shutil.copyfile(scores, dest / "scores.json")
        written = export_paper_assets(view, args.results_dir, statistics_config=args.statistics_config,
                                      freeze_path=args.freeze)
    for w in written:
        print(f"wrote {w}")
    return 0
