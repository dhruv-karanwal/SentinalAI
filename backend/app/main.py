"""Command-line entry point.

    python -m app.main ingest ../data/samples/synthetic_cicids2017_format.csv \
        --mapping cicids2017 --dataset-name synthetic-cicids2017-format
    python -m app.main ingest-alerts --data-dir ../data/raw/ait_ads --scenario russellmitchell
    python -m app.main variants --scenario russellmitchell      # dev scenarios only
    python -m app.main cases --scenario russellmitchell         # dev scenarios only
    python -m app.main run-agent --scenario russellmitchell --variant fused --limit 2 --dry-run

This is a local research tool: it reads whatever path it is given. Do not
expose it behind a network API without validating paths against an
allow-listed data directory.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import re
import sys
import time
from collections.abc import Sequence
from datetime import timedelta, timezone, tzinfo
from pathlib import Path
from typing import Any

from app.agent.client import ChatClient, FakeClient, OpenAICompatibleClient
from app.agent.config import api_key, load_agent_settings
from app.api.auth import Role
from app.agent.runner import SELECTION_MODES, estimate_run, prepare_run, run_agent
from app.alert_pipeline import AitAdsInputs, run_alert_ingest
from app.ingestion.mappings import AIT_ADS_DATASET_NAME, MAPPINGS, get_mapping
from app.ingestion.records import IngestionError
from app.pipeline import FORMATS, run_pipeline
from app.study.config import (
    DEFAULT_STUDY_CONFIG,
    SHUFFLED_REFERENCE_CHOICES,
    TRUNCATION_CHOICES,
    HeldOutScenarioError,
    load_study_config,
)
from app.study.cases import dev_case_report
from app.study.variants import dev_triage_report

DEFAULT_LABELS = Path(__file__).resolve().parents[2] / "data" / "raw" / "ait_ads" / "labels.csv"

DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parents[2] / "data" / "processed"
DEFAULT_PLATFORM_DIR = Path(__file__).resolve().parents[2] / "data" / "platform"
DEFAULT_SIGMA_RULES = Path(__file__).resolve().parents[2] / "data" / "raw" / "sigma" / "repo"

_OFFSET_RE = re.compile(r"([+-])(\d{2}):?(\d{2})")


def parse_timezone(value: str) -> tzinfo | None:
    """``"UTC"``, ``"+HH:MM"``/``"-HH:MM"``, or ``"none"`` (reject naive)."""
    text = value.strip()
    if text.casefold() == "none":
        return None
    if text.casefold() in ("utc", "z"):
        return timezone.utc
    match = _OFFSET_RE.fullmatch(text)
    if not match:
        raise argparse.ArgumentTypeError(
            f"invalid timezone {value!r}; use UTC, +HH:MM, -HH:MM or none")
    sign, hours, minutes = match.groups()
    offset = timedelta(hours=int(hours), minutes=int(minutes))
    if offset >= timedelta(hours=24):
        raise argparse.ArgumentTypeError(f"offset out of range: {value!r}")
    if sign == "-":
        offset = -offset
    return timezone(offset)


def _positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinelai", description="SentinelAI Phase 1 data pipeline")
    sub = parser.add_subparsers(dest="command", required=True)
    ingest = sub.add_parser("ingest", help="load, normalize and profile one CSV/JSON/JSONL file")
    ingest.add_argument("path", type=Path, help="input file")
    ingest.add_argument("--mapping", default="generic", choices=sorted(MAPPINGS),
                        help="dataset mapping (default: generic)")
    ingest.add_argument("--format", dest="fmt", default="auto", choices=FORMATS,
                        help="input format (default: from file extension)")
    ingest.add_argument("--limit", type=_positive_int, default=None,
                        help="read at most N input records")
    ingest.add_argument("--encoding", default="utf-8", help="file encoding (default: utf-8)")
    ingest.add_argument("--dataset-name", default=None,
                        help="dataset name for records that do not carry one")
    ingest.add_argument("--assume-timezone", type=parse_timezone, default=argparse.SUPPRESS,
                        metavar="TZ", help="timezone for naive timestamps: UTC, +HH:MM, -HH:MM "
                        "or none (default: the mapping's own assumption)")
    ingest.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR,
                        help=f"where to write outputs (default: {DEFAULT_OUTPUT_DIR})")
    ingest.add_argument("--no-output", action="store_true",
                        help="only print the summary; write no files")

    alerts = sub.add_parser("ingest-alerts", help="ingest one AIT-ADS scenario (alerts + ground truth)")
    alerts.add_argument("--data-dir", type=Path, required=True,
                        help="directory holding <scenario>_wazuh.json, <scenario>_aminer.json, labels.csv")
    alerts.add_argument("--scenario", required=True, help="scenario name, e.g. russellmitchell")
    alerts.add_argument("--labels", type=Path, default=None,
                        help="attack-interval labels CSV (default: <data-dir>/labels.csv)")
    alerts.add_argument("--event-labels", type=Path, default=None,
                        help="alerts_csv file with event labels (default: "
                        "<data-dir>/alerts_csv/alerts_csv/<scenario>_alerts.txt if present)")
    alerts.add_argument("--dataset-name", default=AIT_ADS_DATASET_NAME,
                        help=f"dataset name recorded on alerts (default: {AIT_ADS_DATASET_NAME})")
    alerts.add_argument("--limit", type=_positive_int, default=None,
                        help="read at most N input records (Wazuh first, then AMiner)")
    alerts.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR,
                        help=f"where to write outputs (default: {DEFAULT_OUTPUT_DIR})")
    alerts.add_argument("--no-output", action="store_true",
                        help="only print the summary; write no files")

    variants = sub.add_parser(
        "variants", help="build alert-source variants + study sample and print dev triage scores")
    variants.add_argument("--scenario", required=True, help="a dev scenario (held-out ones are refused)")
    variants.add_argument("--processed-dir", type=Path, default=DEFAULT_OUTPUT_DIR,
                          help=f"where ingest-alerts wrote its outputs (default: {DEFAULT_OUTPUT_DIR})")
    variants.add_argument("--study-config", type=Path, default=DEFAULT_STUDY_CONFIG,
                          help=f"study config (default: {DEFAULT_STUDY_CONFIG})")
    variants.add_argument("--shuffled-reference", action="append", choices=SHUFFLED_REFERENCE_CHOICES,
                          default=None, help="variant a shuffled-pool control is size-matched to; "
                          "repeatable (default: from the study config)")
    variants.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR / "variants",
                          help="where to write variants, manifests and the dev report "
                          f"(default: {DEFAULT_OUTPUT_DIR / 'variants'})")
    variants.add_argument("--no-output", action="store_true", help="only print; write no files")

    cases = sub.add_parser(
        "cases", help="build attack/benign cases per variant and print dev coverage ceilings")
    cases.add_argument("--scenario", required=True, help="a dev scenario (held-out ones are refused)")
    cases.add_argument("--processed-dir", type=Path, default=DEFAULT_OUTPUT_DIR,
                       help=f"where ingest-alerts wrote its outputs (default: {DEFAULT_OUTPUT_DIR})")
    cases.add_argument("--labels", type=Path, default=DEFAULT_LABELS,
                       help=f"attack-interval labels CSV (default: {DEFAULT_LABELS})")
    cases.add_argument("--study-config", type=Path, default=DEFAULT_STUDY_CONFIG,
                       help=f"study config (default: {DEFAULT_STUDY_CONFIG})")
    cases.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR / "cases",
                       help=f"where to write case manifests (default: {DEFAULT_OUTPUT_DIR / 'cases'})")
    cases.add_argument("--no-output", action="store_true", help="only print; write no files")

    agent = sub.add_parser("run-agent", help="run the M5 single tool-using agent on dev cases")
    agent.add_argument("--scenario", required=True, help="a dev scenario (held-out ones are refused)")
    agent.add_argument("--variant", required=True, help="experiment variant, e.g. fused, aminer")
    agent.add_argument("--limit", type=_positive_int, default=None,
                       help="first N cases, attack and benign interleaved (default: all)")
    agent.add_argument("--select", choices=SELECTION_MODES, default="interleaved",
                       help="case selection: interleaved (all) or reachable (attack cases on "
                            "alert-reachable phases + their benign matches)")
    agent.add_argument("--case-id", action="append", default=None, dest="case_ids",
                       help="investigate exactly this case (repeatable; overrides --select)")
    agent.add_argument("--truncation", choices=TRUNCATION_CHOICES, default=None,
                       help="case cap rule (default: cases.truncation in the study config)")
    agent.add_argument("--dry-run", action="store_true",
                       help="print the token and cost bound; call no model")
    agent.add_argument("--confirm", action="store_true",
                       help="allow a run whose token bound exceeds agent.run_token_budget")
    agent.add_argument("--fake-responses", type=Path, default=None,
                       help="JSON list of scripted replies (FakeClient; for demos, no model)")
    agent.add_argument("--processed-dir", type=Path, default=DEFAULT_OUTPUT_DIR,
                       help=f"where ingest-alerts wrote its outputs (default: {DEFAULT_OUTPUT_DIR})")
    agent.add_argument("--labels", type=Path, default=DEFAULT_LABELS,
                       help=f"attack-interval labels CSV (default: {DEFAULT_LABELS})")
    agent.add_argument("--study-config", type=Path, default=DEFAULT_STUDY_CONFIG,
                       help=f"study config (default: {DEFAULT_STUDY_CONFIG})")
    agent.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR / "runs",
                       help=f"where run logs go (default: {DEFAULT_OUTPUT_DIR / 'runs'})")

    plat = sub.add_parser("platform-ingest", help="replay a dev scenario into the platform stores")
    plat.add_argument("--scenario", required=True, help="a dev scenario (held-out ones are refused)")
    plat.add_argument("--limit", type=_positive_int, default=None, help="first N alerts only")
    plat.add_argument("--processed-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    plat.add_argument("--study-config", type=Path, default=DEFAULT_STUDY_CONFIG)
    plat.add_argument("--data-dir", type=Path, default=DEFAULT_PLATFORM_DIR,
                      help=f"SQLite fallback stores (default: {DEFAULT_PLATFORM_DIR})")

    sig = sub.add_parser("sigma", help="Sigma rules over alert evidence lines (dev only) + dev "
                                       "detection baseline")
    sig.add_argument("--scenario", required=True, help="a dev scenario (held-out ones are refused)")
    sig.add_argument("--rules-dir", type=Path, default=DEFAULT_SIGMA_RULES)
    sig.add_argument("--processed-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    sig.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR / "sigma")
    sig.add_argument("--study-config", type=Path, default=DEFAULT_STUDY_CONFIG)
    sig.add_argument("--data-dir", type=Path, default=DEFAULT_PLATFORM_DIR,
                     help="platform stores; the dev baseline reads labels from their truth area")
    sig.add_argument("--no-score", action="store_true", help="skip the dev detection baseline")

    tri = sub.add_parser("triage", help="B3: build incidents from the stored alerts of a dev "
                                        "scenario (+ descriptive dev check)")
    tri.add_argument("--scenario", required=True, help="a dev scenario (held-out ones are refused)")
    tri.add_argument("--gap-seconds", type=_positive_int, default=300,
                     help="max gap between linked alerts on one entity (default: 300)")
    tri.add_argument("--max-span-seconds", type=_positive_int, default=3600,
                     help="cut incidents spanning longer than this into segments (default: 3600)")
    tri.add_argument("--no-span-cap", action="store_true", help="disable the span cap (B3 behaviour)")
    tri.add_argument("--include-sigma", action="store_true",
                     help="add <scenario>.sigma.alerts.jsonl from --sigma-dir (written by `sigma`)")
    tri.add_argument("--sigma-dir", type=Path, default=DEFAULT_OUTPUT_DIR / "sigma")
    tri.add_argument("--ioc-file", type=Path, default=None,
                     help="local indicator JSON (feeds are disabled; default: none)")
    tri.add_argument("--labels", type=Path, default=DEFAULT_LABELS,
                     help="labels.csv, read ONLY by the descriptive dev check")
    tri.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR / "triage")
    tri.add_argument("--study-config", type=Path, default=DEFAULT_STUDY_CONFIG)
    tri.add_argument("--data-dir", type=Path, default=DEFAULT_PLATFORM_DIR)

    mlb = sub.add_parser("ml-baselines", help="B4: IsolationForest + HistGradientBoosting detection "
                                              "baselines on dev scenarios")
    mlb.add_argument("--scenarios", nargs="+", default=["russellmitchell", "shaw"],
                     help="dev scenarios (held-out ones are refused)")
    mlb.add_argument("--processed-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    mlb.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR / "ml")
    mlb.add_argument("--study-config", type=Path, default=DEFAULT_STUDY_CONFIG)
    mlb.add_argument("--data-dir", type=Path, default=DEFAULT_PLATFORM_DIR,
                     help="platform stores; labels come from their truth area")

    fbr = sub.add_parser("feedback-report", help="Wave D: offline summary of analyst feedback "
                                                 "(no retraining)")
    fbr.add_argument("--data-dir", type=Path, default=DEFAULT_PLATFORM_DIR)
    fbr.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_DIR / "feedback" / "feedback_report.json")

    from app.cli_wave_c import add_parsers as add_wave_c_parsers

    add_wave_c_parsers(sub, DEFAULT_STUDY_CONFIG, _positive_int)

    from app.cli_final import add_parsers as add_final_parsers

    add_final_parsers(sub, DEFAULT_STUDY_CONFIG, _positive_int)

    user = sub.add_parser("create-user", help="create or replace a platform user")
    user.add_argument("--username", required=True)
    user.add_argument("--role", required=True, choices=[r.value for r in Role])
    user.add_argument("--data-dir", type=Path, default=DEFAULT_PLATFORM_DIR)

    serve = sub.add_parser("serve", help="run the HTTP API (uvicorn)")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    return parser


def _print_summary(report: dict[str, Any], output_paths: dict[str, Path]) -> None:
    counts = report["record_counts"]
    print(f"Source:     {report['source_file']} ({report['input_format']}, mapping={report['mapping']})")
    print(f"Records:    {counts['total_input']} input, {counts['normalized']} normalized, "
          f"{counts['rejected']} rejected")
    for reason, count in report["rejections"]["by_reason"].items():
        print(f"  rejected  {reason}: {count}")
    ts = report["timestamps"]
    print(f"Timestamps: {ts['parsed']} parsed, {ts['missing']} missing, "
          f"{ts['parse_failures']} parse failures")
    dup = report["duplicates"]
    print(f"Duplicates: {dup['duplicate_raw_records']} raw records, "
          f"{dup['duplicate_event_ids']} event ids, {dup['duplicate_feature_vectors']} feature vectors")
    labels = report["labels"]
    print(f"Labels:     {labels['labelled']} labelled, {labels['unlabelled']} unlabelled")
    for label, info in labels["distribution"].items():
        print(f"  {label}: {info['count']} ({info['proportion']:.2%})")
    print(f"Features:   {report['features']['feature_count']}")
    for kind, path in output_paths.items():
        print(f"Wrote {kind}: {path}")
    if counts["normalized"] == 0:
        print("WARNING: no records were normalized", file=sys.stderr)


def _print_alert_summary(report: dict[str, Any], output_paths: dict[str, Path]) -> None:
    counts = report["record_counts"]
    print(f"Scenario:   {report['scenario']} (dataset={report['dataset_name']})")
    print(f"Records:    {counts['total_input']} input, {counts['normalized']} normalized, "
          f"{counts['rejected']} rejected")
    for reason, count in report["rejections"]["by_reason"].items():
        print(f"  rejected  {reason}: {count}")
    for detector, info in report["detectors"].items():
        print(f"  {detector:9s} {info['alerts']} alerts, {info['training_mode']} training, "
              f"{info['aggregate']} aggregate, {info['duplicate_of_suricata']} fast.log duplicates, "
              f"{info['investigation_eligible']} investigation-eligible")
    dup = report["suricata_duplicates"]
    print(f"fast.log:   {dup['fast_log_matched_to_eve']}/{dup['fast_log_records']} matched to "
          f"eve.json, {dup['fast_log_unmatched']} unmatched")
    truth = report["ground_truth"]
    print(f"Intervals:  {truth['attack_intervals_within_alert_range']}/"
          f"{len(truth['attack_intervals'])} inside the alert time range")
    events = truth["event_labels"]
    print(f"Event labels: {events['link_status']}, {events['available']} available, "
          f"{events['unavailable']} unavailable")
    for kind, path in output_paths.items():
        print(f"Wrote {kind}: {path}")


def _ingest_alerts(args: argparse.Namespace) -> int:
    try:
        inputs = AitAdsInputs.from_layout(args.data_dir, args.scenario)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    overrides: dict[str, Any] = {}
    if args.labels is not None:
        overrides["labels"] = args.labels
    if args.event_labels is not None:
        overrides["event_labels"] = args.event_labels
    if overrides:
        inputs = dataclasses.replace(inputs, **overrides)
    try:
        result = run_alert_ingest(
            inputs,
            dataset_name=args.dataset_name,
            limit=args.limit,
            output_dir=None if args.no_output else args.output_dir,
            collect=False,
        )
    except IngestionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    _print_alert_summary(result.report, result.output_paths)
    return 0


def _fmt(value: float | None) -> str:
    return "  n/a" if value is None else f"{value:.4f}"


def _variants(args: argparse.Namespace) -> int:
    try:
        config = load_study_config(args.study_config)
        report = dev_triage_report(
            args.processed_dir, args.scenario, config,
            output_dir=None if args.no_output else args.output_dir,
            shuffled_references=args.shuffled_reference)
    except (HeldOutScenarioError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except IngestionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    pool = report["pool"]
    print(f"DEV-SCENARIO NUMBERS - scenario {report['scenario']} (dev split; not held-out results)")
    print(f"Pool: {pool['alerts']} investigation-eligible alerts "
          f"({pool['excluded_by_selection']} excluded by selection); verdict = alert in variant")
    for truth in ("event_label", "time_label"):
        role = "primary" if truth == report["truth"]["primary"] else "sensitivity"
        print(f"\nTruth: {truth} ({role})")
        print(f"{'variant':16s} {'alerts':>7s} {'share':>7s} {'TP':>6s} {'FP':>6s} {'FN':>6s} "
              f"{'TN':>6s} {'prec':>7s} {'recall':>7s} {'F1':>7s} {'FNR':>7s}")
        for name, info in report["variants"].items():
            s = info["triage"][truth]
            share = info["manifest"]["attack_share"][truth]["share"]
            flag = "  (degenerate: = pool)" if info["manifest"]["degenerate"] else ""
            print(f"{name:16s} {info['manifest']['alerts']:7d} {_fmt(share):>7s} {s['tp']:6d} "
                  f"{s['fp']:6d} {s['fn']:6d} {s['tn']:6d} {_fmt(s['precision']):>7s} "
                  f"{_fmt(s['recall']):>7s} {_fmt(s['f1']):>7s} {_fmt(s['fnr']):>7s}{flag}")
    for name, manifest in report["manifest_only"].items():
        print(f"\n{name}: manifest only ({manifest['alerts']} alerts, degenerate="
              f"{manifest['degenerate']}); not an experiment variant")
    if not args.no_output:
        print(f"Wrote variants, manifests and {report['scenario']}.dev_triage.json to "
              f"{Path(args.output_dir) / report['scenario']}")
    return 0


def _frac(rate: dict[str, Any]) -> str:
    return f"{rate['covered']}/{rate['cases']}"


def print_score_header() -> None:
    """Header of the shared score table (baselines and agent runs; headline column first)."""
    print("cov = phases covered by event_label (headline) / time (sensitivity), over reachable "
          "phases | all phases; prec = citation precision (event_label / time); "
          "unsup = unsupported-claim rate")
    print(f"{'variant':16s} {'citer':36s} {'cov e rch':>9s} {'cov e all':>9s} {'cov t rch':>9s} "
          f"{'cov t all':>9s} {'prec e':>7s} {'prec t':>7s} {'unsup':>7s} {'cited':>6s} {'per case':>9s}")


def print_score_row(variant: str, name: str, r: dict[str, Any]) -> None:
    cov, prec = r["coverage"], r["citation_precision"]
    print(f"{variant:16s} {name:36s} {_frac(cov['event_label']['reachable']):>9s} "
          f"{_frac(cov['event_label']['all']):>9s} {_frac(cov['time_label']['reachable']):>9s} "
          f"{_frac(cov['time_label']['all']):>9s} {_fmt(prec['event_label']):>7s} "
          f"{_fmt(prec['time_label']):>7s} {_fmt(r['unsupported_claim_rate']):>7s} "
          f"{r['alerts_cited']['total']:>6d} {_fmt(r['alerts_cited']['mean_per_case']):>9s}")


def _cases(args: argparse.Namespace) -> int:
    try:
        config = load_study_config(args.study_config)
        report = dev_case_report(args.processed_dir, args.labels, args.scenario, config,
                                 output_dir=None if args.no_output else args.output_dir)
    except (HeldOutScenarioError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except IngestionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    cfg, counts, log = report["case_config"], report["cases"], report["benign_sampling"]
    print(f"DEV-SCENARIO CEILINGS - scenario {report['scenario']} (dev split; ceilings, "
          "not agent results)")
    print(f"Cases: {counts['attack']} attack, {counts['benign']} benign "
          f"({len(log['unavailable'])} benign unavailable); padding {cfg['padding_seconds']} s, "
          f"cap {cfg['max_alerts']} ({cfg['truncation']}), seed {cfg['seed']}")
    print(f"Headline: coverage by {report['headline']['coverage']}; "
          f"{report['headline']['sensitivity']} is the sensitivity analysis")
    print(f"{'variant':16s} {'ceil event':>10s} {'ceil time':>10s} {'pre-cap e/t':>12s} "
          f"{'mean att':>9s} {'mean ben':>9s} {'trunc':>6s} {'dropped':>8s} {'drop atk e/t':>13s} "
          f"{'ben w/ atk':>10s}")
    for name, s in report["variants"].items():
        ceil, pre, mean, trunc = (s["coverage_ceiling"], s["coverage_ceiling_before_cap"],
                                  s["mean_alerts_per_case"], s["truncation"])
        print(f"{name:16s} {ceil['event_label']['covered']:>4d}/{ceil['event_label']['cases']:<5d} "
              f"{ceil['time_label']['covered']:>4d}/{ceil['time_label']['cases']:<5d} "
              f"{pre['event_label']['covered']:>5d}/{pre['time_label']['covered']:<6d} "
              f"{_fmt(mean['attack']):>9s} {_fmt(mean['benign']):>9s} "
              f"{trunc['cases_truncated']:>6d} {trunc['alerts_dropped']:>8d} "
              f"{trunc['cases_cap_dropped_event_attack']:>6d}/{trunc['cases_cap_dropped_time_attack']:<6d} "
              f"{s['benign_cases_with_event_attack_alert']:>10d}")
    phases = report["phases"]
    print(f"Phases: {len(phases['all'])} attack phases, {len(phases['reachable'])} alert-reachable; "
          f"unreachable: {', '.join(phases['unreachable']) or 'none'}")
    noise_rows = [(n, s["noise"]) for n, s in report["variants"].items() if s["noise"] is not None]
    for name, noise in noise_rows:
        print(f"  {name}: {noise['reference_count']} alerts matched, {noise['from_window']} from the "
              f"same window, {noise['from_fallback']} nearest outside it (max "
              f"{noise['fallback_max_distance_seconds']:.0f} s away), {noise['shortfall']} short")
    b = report["baseline_config"]
    frozen = " (frozen)" if b.get("detector_order_frozen") else ""
    print(f"\nDEV-SCENARIO BASELINES - deterministic non-LLM citers, not agent results "
          f"(top_k {b['top_k']}, detector order {', '.join(b['detector_order'])}{frozen})")
    print_score_header()
    for variant, rows in report["baselines"].items():
        for name, r in rows.items():
            print_score_row(variant, name, r)
    if not args.no_output:
        print(f"Wrote {report['scenario']}.cases.json and {report['scenario']}.case_ceilings.json to "
              f"{Path(args.output_dir) / report['scenario']}")
    return 0


def _fake_client(path: Path) -> FakeClient:
    script = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(script, list) or not all(isinstance(s, str) for s in script):
        raise ValueError("--fake-responses must be a JSON list of reply strings")
    return FakeClient(script)


def _run_agent(args: argparse.Namespace) -> int:
    try:
        config = load_study_config(args.study_config)
        settings = load_agent_settings(args.study_config)
        prep = prepare_run(args.processed_dir, args.labels, args.scenario, args.variant, config,
                           limit=args.limit, truncation=args.truncation, selection=args.select,
                           case_ids=args.case_ids)
    except (HeldOutScenarioError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except IngestionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    est = estimate_run(prep, settings)
    kinds = ", ".join(f"{c.kind.value}" for c in prep.cases)
    print(f"DEV-SCENARIO AGENT RUN - scenario {prep.scenario}, variant {prep.variant}, truncation "
          f"{prep.truncation}; {est['cases']} case(s): {kinds}")
    print(f"Budget: token bound {est['token_bound']} ({est['token_bound_per_case']} per case), cost "
          f"bound ${est['cost_bound_usd']:.4f} at ${est['price_per_million_used']}/M tokens; first "
          f"prompts ~{est['first_prompt_tokens_estimate']} tokens; run budget {est['run_token_budget']}")
    if args.dry_run:
        print("DRY RUN: no model was called" + (" (a real run would need --confirm)"
                                                if est["needs_confirm"] else ""))
        return 0
    if est["needs_confirm"] and not args.confirm:
        print(f"error: token bound {est['token_bound']} exceeds agent.run_token_budget "
              f"{est['run_token_budget']}; re-run with --confirm or a smaller --limit", file=sys.stderr)
        return 2
    client: ChatClient
    try:
        if args.fake_responses is not None:
            client = _fake_client(args.fake_responses)
        elif not settings.model.configured:
            print("error: no model endpoint configured; set model.base_url and model.model in the "
                  "study config or SENTINEL_LLM_BASE_URL / SENTINEL_LLM_MODEL (or use --dry-run)",
                  file=sys.stderr)
            return 2
        else:
            client = OpenAICompatibleClient(settings.model, api_key=api_key(settings.model))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    report = run_agent(prep, settings, client, output_dir=args.output_dir,
                       study_config_path=args.study_config)
    for case in report["manifest"]["cases"]:
        print(f"  case {case['index']}: {case['kind']:6s} alerts {case['alerts']:3d} status "
              f"{case['status']} parse {case['parse_status']} verdict {case['verdict']} tokens "
              f"{case['input_tokens']}+{case['output_tokens']}"
              f"{'' if case['usage_reported'] else ' (estimated)'} tool calls {case['tool_calls']} "
              f"latency {case['latency_seconds']:.2f} s" + (f" error: {case['error']}" if case['error'] else ""))
    scores = report["scores"]
    print(f"\nAgent vs baselines on the same cases (DEV, not held-out); matched k = {scores['matched_k']}")
    print_score_header()
    print_score_row(prep.variant, f"agent ({client.model_id})", scores["agent"])
    for name, row in scores["baselines"].items():
        print_score_row(prep.variant, name, row)
    verdict = scores["agent"]["verdict"]
    print(f"Verdicts: {verdict['correct']}/{verdict['cases']} correct, {verdict['failed']} failed "
          f"(tp {verdict['tp']}, fp {verdict['fp']}, fn {verdict['fn']}, tn {verdict['tn']})")
    print(f"Wrote run log to {report['run_dir']}")
    return 0


def _platform_ingest(args: argparse.Namespace) -> int:
    from app.platform.bootstrap import ingest_scenario, open_stores

    try:
        config = load_study_config(args.study_config)
        config.split.require_dev(args.scenario)
        report = ingest_scenario(open_stores(args.data_dir), args.processed_dir, args.scenario,
                                 config, limit=args.limit)
    except (HeldOutScenarioError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({k: v for k, v in report.items() if k != "rejections"}, indent=2))
    return 0


def _sigma(args: argparse.Namespace) -> int:
    from app.detection.labels import MissingTruthError, dev_labels
    from app.detection.sigma_report import run_sigma_scenario, sigma_dev_baseline
    from app.platform.bootstrap import open_stores

    try:
        config = load_study_config(args.study_config)
        report = run_sigma_scenario(args.processed_dir, args.scenario, config, args.rules_dir,
                                    args.output_dir)
    except (HeldOutScenarioError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    rules, stats = report["rules"], report["stats"]
    print(f"SIGMA over evidence lines - scenario {args.scenario} (dev scenario, not a paper result)")
    print(f"rules: {rules['total']} total, {rules['compiled']} compiled, {rules['skipped']} skipped")
    for reason, n in rules["skipped_by_reason"].items():
        print(f"  skipped {reason}: {n}")
    print(f"compiled by log type: {rules['compiled_by_log_type']}")
    print(f"source alerts {stats['source_alerts']}, without lines {stats['alerts_without_lines']}, "
          f"lines {stats['log_lines']}, unclassified lines {stats['lines_unclassified']}")
    print(f"events by log type: {stats['events_by_log_type']}")
    print(f"sigma alerts: {stats['sigma_alerts']} from {report['rules_with_hits']} rules; "
          f"runtime load {report['runtime_seconds']['load_rules']} s, "
          f"evaluate {report['runtime_seconds']['evaluate']} s")
    for rid, info in report["per_rule"].items():
        if info["hits"]:
            print(f"  {info['hits']:>7d} hits / {info['events_evaluated']:>7d} events  "
                  f"{info['title']}  ({info['file']})")
    if args.no_score:
        return 0
    try:
        labels = dev_labels(open_stores(args.data_dir).truth, args.scenario, config)
    except MissingTruthError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    base = sigma_dev_baseline(report["_pool_ids"], set(report["_flagged_source_ids"]), labels)
    print(f"\n{base['label']}: verdict = pool alert flagged by some Sigma rule")
    print(f"pool {base['pool_alerts']}, flagged {base['flagged']}, event_label unavailable "
          f"{base['event_label_unavailable']}")
    for truth in ("event_label", "time_label"):
        s = base[truth]
        print(f"  {truth:11s} TP {s['tp']} FP {s['fp']} FN {s['fn']} TN {s['tn']} "
              f"prec {_fmt(s['precision'])} recall {_fmt(s['recall'])} F1 {_fmt(s['f1'])} "
              f"FNR {_fmt(s['fnr'])}")
    if args.output_dir is not None:
        (Path(args.output_dir) / f"{args.scenario}.sigma.dev_baseline.json").write_text(
            json.dumps(base, indent=2) + "\n", encoding="utf-8")
    return 0


def _triage(args: argparse.Namespace) -> int:
    from app.alert_pipeline import iter_alert_file
    from app.detection.triage import TriageConfig, build_and_store
    from app.detection.triage_report import phase_overlap
    from app.intel.ioc import IocStore
    from app.platform.bootstrap import open_stores

    try:
        config = load_study_config(args.study_config)
        config.split.require_dev(args.scenario)
        stores = open_stores(args.data_dir)
        extra = []
        if args.include_sigma:
            extra = list(iter_alert_file(args.sigma_dir / f"{args.scenario}.sigma.alerts.jsonl"))
        iocs = IocStore.load(args.ioc_file) if args.ioc_file else None
        t0 = time.perf_counter()
        summary = build_and_store(stores.repo, args.scenario, TriageConfig(
            args.gap_seconds, max_span_seconds=None if args.no_span_cap else args.max_span_seconds),
                                  extra, iocs)
        summary["runtime_seconds"] = round(time.perf_counter() - t0, 2)
        summary["ioc_indicators"] = len(iocs) if iocs else 0
        incidents = stores.repo.list_incidents(args.scenario)
        check = phase_overlap(incidents, args.labels, args.scenario, config)
    except (HeldOutScenarioError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except IngestionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"TRIAGE - scenario {args.scenario} (dev scenario, not a paper result); "
          f"gap {summary['gap_seconds']} s, span cap {summary['max_span_seconds']} s, sigma alerts added {summary['extra_alerts']}, "
          f"IOC indicators {summary['ioc_indicators']}")
    print(json.dumps({k: v for k, v in summary.items() if k != "size_distribution"}, indent=2))
    print(f"\n{check['label']}: attack phases (labels.csv) overlapped in time by >= 1 incident: "
          f"{check['phases_overlapped']}/{check['phases']}")
    for ph in check["per_phase"]:
        print(f"  {ph['phase']:28s} {ph['overlapping_incidents']:>6d} incidents "
              f"{ph['overlapping_by_severity']}")
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{args.scenario}.triage.json").write_text(
        json.dumps({"summary": summary, "descriptive_dev_check": check}, indent=2) + "\n",
        encoding="utf-8")
    return 0


def _ml_baselines(args: argparse.Namespace) -> int:
    from app.detection.labels import MissingTruthError
    from app.detection.ml_baselines import run_ml_baselines
    from app.platform.bootstrap import open_stores

    try:
        config = load_study_config(args.study_config)
        for s in args.scenarios:
            config.split.require_dev(s)
        t0 = time.perf_counter()
        report = run_ml_baselines(args.processed_dir, open_stores(args.data_dir).truth, config,
                                  args.scenarios)
        report["runtime_seconds"] = round(time.perf_counter() - t0, 2)
    except (HeldOutScenarioError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except MissingTruthError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"ML DETECTION BASELINES - {report['label']}")
    for set_name, feats in report["feature_sets"].items():
        print(f"feature set {set_name} ({len(feats)}): {', '.join(feats)}")

    def row(model: str, res: dict[str, Any], indent: str = "  ") -> None:
        if "skipped" in res:
            print(f"{indent}{model:24s} skipped: {res['skipped']}")
            return
        for truth in ("event_label", "time_label"):
            s = res[truth]
            print(f"{indent}{model:24s} {truth:11s} TP {s['tp']:>6d} FP {s['fp']:>6d} FN {s['fn']:>6d} "
                  f"TN {s['tn']:>6d} prec {_fmt(s['precision'])} recall {_fmt(s['recall'])} "
                  f"F1 {_fmt(s['f1'])} FNR {_fmt(s['fnr'])}")

    print("\nPRIMARY: cross-scenario")
    for name, split in report["splits"].items():
        bal = split["class_balance"]
        print(f"\n{name}  train {bal['train']['n']} (event attack {bal['train']['event_label']['attack']}, "
              f"benign {bal['train']['event_label']['benign']}, unavailable "
              f"{bal['train']['event_label']['unavailable']})  test {bal['test']['n']} (event attack "
              f"{bal['test']['event_label']['attack']}, benign {bal['test']['event_label']['benign']}, "
              f"unavailable {bal['test']['event_label']['unavailable']})")
        for model, res in split["models"].items():
            row(model, res)
        imp = split["models"].get("hist_gradient_boosting", {}).get("permutation_importance")
        if isinstance(imp, list):
            print("  permutation importance (HistGB, test F1 drop): "
                  + ", ".join(f"{r['feature']} {r['mean']:.4f}" for r in imp))
    print("\nLEAVE-ONE-PHASE-OUT (test = alerts inside the held-out phase; pooled over folds)")
    for name, lo in report["lopo"].items():
        print(f"\n{name}  phases {len(lo['per_phase'])}")
        for model, res in lo["pooled"].items():
            row(model, res)
        for ph in lo["per_phase"]:
            hgb = ph["models"].get("hist_gradient_boosting", {})
            ev = hgb.get("event_label")
            print(f"    {ph['phase']:28s} n {ph['n_test']:>6d} event attack {ph['event_attack']:>6d} "
                  f"HistGB recall {_fmt(ev['recall']) if ev else 'skipped'}")
    print(f"\nruntime {report['runtime_seconds']} s")
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "ml_baselines.dev.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0


def _feedback_report(args: argparse.Namespace) -> int:
    from app.outputs.feedback_report import feedback_report
    from app.platform.bootstrap import open_stores

    try:
        report = feedback_report(open_stores(args.data_dir).repo)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"FEEDBACK REPORT - {report['note']}")
    print(f"entries {report['total']}, targets {report['targets']}, by verdict {report['by_verdict']}")
    for t, c in report["by_target_type"].items():
        print(f"  {t:10s} {c}")
    for d in report["most_disputed"]:
        print(f"  disputed {d['target']}: {d['verdicts']}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0


def _create_user(args: argparse.Namespace) -> int:
    """Password only from the environment (SENTINEL_NEW_USER_PASSWORD), never argv."""
    import os

    from app.api.auth import hash_password
    from app.platform.bootstrap import open_stores

    password = os.environ.get("SENTINEL_NEW_USER_PASSWORD", "")
    if len(password) < 8:
        print("error: set SENTINEL_NEW_USER_PASSWORD (>= 8 characters) in the environment",
              file=sys.stderr)
        return 2
    stores = open_stores(args.data_dir)
    stores.repo.put_user(args.username, hash_password(password), args.role)
    stores.repo.audit("cli", "admin", "user.create", args.username, {"role": args.role})
    print(f"user {args.username} ({args.role}) saved")
    return 0


def _serve(args: argparse.Namespace) -> int:
    import uvicorn

    from app.api.server import build_app

    uvicorn.run(build_app(), host=args.host, port=args.port)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    # Labels may contain non-ASCII characters; never crash on a narrow console.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    if args.command == "ingest-alerts":
        return _ingest_alerts(args)
    if args.command == "variants":
        return _variants(args)
    if args.command == "run-agent":
        return _run_agent(args)
    if args.command == "cases":
        return _cases(args)
    if args.command == "platform-ingest":
        return _platform_ingest(args)
    if args.command == "sigma":
        return _sigma(args)
    if args.command == "triage":
        return _triage(args)
    if args.command == "ml-baselines":
        return _ml_baselines(args)
    if args.command == "feedback-report":
        return _feedback_report(args)
    from app.cli_wave_c import COMMANDS as WAVE_C_COMMANDS
    from app.cli_wave_c import dispatch as wave_c_dispatch

    if args.command in WAVE_C_COMMANDS:
        return wave_c_dispatch(args)
    from app.cli_final import COMMANDS as FINAL_COMMANDS
    from app.cli_final import dispatch as final_dispatch

    if args.command in FINAL_COMMANDS:
        return final_dispatch(args)
    if args.command == "create-user":
        return _create_user(args)
    if args.command == "serve":
        return _serve(args)
    mapping = get_mapping(args.mapping)
    overrides: dict[str, Any] = {}
    if args.dataset_name is not None:
        overrides["dataset_name"] = args.dataset_name
    if hasattr(args, "assume_timezone"):
        overrides["naive_timezone"] = args.assume_timezone
    if overrides:
        mapping = dataclasses.replace(mapping, **overrides)

    try:
        result = run_pipeline(
            args.path,
            mapping,
            fmt=args.fmt,
            limit=args.limit,
            encoding=args.encoding,
            output_dir=None if args.no_output else args.output_dir,
            collect=False,
        )
    except IngestionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    _print_summary(result.report, result.output_paths)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
