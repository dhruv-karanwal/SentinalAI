"""Command-line entry point.

    python -m app.main ingest ../data/samples/synthetic_cicids2017_format.csv \
        --mapping cicids2017 --dataset-name synthetic-cicids2017-format
    python -m app.main ingest-alerts --data-dir ../data/raw/ait_ads --scenario russellmitchell
    python -m app.main variants --scenario russellmitchell      # dev scenarios only
    python -m app.main cases --scenario russellmitchell         # dev scenarios only

This is a local research tool: it reads whatever path it is given. Do not
expose it behind a network API without validating paths against an
allow-listed data directory.
"""

from __future__ import annotations

import argparse
import dataclasses
import re
import sys
from collections.abc import Sequence
from datetime import timedelta, timezone, tzinfo
from pathlib import Path
from typing import Any

from app.alert_pipeline import AitAdsInputs, run_alert_ingest
from app.ingestion.mappings import AIT_ADS_DATASET_NAME, MAPPINGS, get_mapping
from app.ingestion.records import IngestionError
from app.pipeline import FORMATS, run_pipeline
from app.study.config import (
    DEFAULT_STUDY_CONFIG,
    SHUFFLED_REFERENCE_CHOICES,
    HeldOutScenarioError,
    load_study_config,
)
from app.study.cases import dev_case_report
from app.study.variants import dev_triage_report

DEFAULT_LABELS = Path(__file__).resolve().parents[2] / "data" / "raw" / "ait_ads" / "labels.csv"

DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parents[2] / "data" / "processed"

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
    print(f"{'variant':16s} {'ceil time':>10s} {'ceil event':>10s} {'pre-cap t/e':>12s} "
          f"{'mean att':>9s} {'mean ben':>9s} {'trunc':>6s} {'dropped':>8s} {'drop atk e/t':>13s} "
          f"{'ben w/ atk':>10s}")
    for name, s in report["variants"].items():
        ceil, pre, mean, trunc = (s["coverage_ceiling"], s["coverage_ceiling_before_cap"],
                                  s["mean_alerts_per_case"], s["truncation"])
        print(f"{name:16s} {ceil['time_label']['covered']:>4d}/{ceil['time_label']['cases']:<5d} "
              f"{ceil['event_label']['covered']:>4d}/{ceil['event_label']['cases']:<5d} "
              f"{pre['time_label']['covered']:>5d}/{pre['event_label']['covered']:<6d} "
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
              f"same window, {noise['from_fallback']} from the scenario pool, "
              f"{noise['shortfall']} short")
    b = report["baseline_config"]
    print(f"\nDEV-SCENARIO BASELINES - deterministic non-LLM citers, not agent results "
          f"(top_k {b['top_k']}, detector order {', '.join(b['detector_order'])})")
    print("cov = phases covered (time / event_label) over all phases | over reachable phases; "
          "prec = citation precision (event_label / time); unsup = unsupported-claim rate")
    print(f"{'variant':16s} {'baseline':26s} {'cov t all':>9s} {'cov e all':>9s} {'cov t rch':>9s} "
          f"{'cov e rch':>9s} {'prec e':>7s} {'prec t':>7s} {'unsup':>7s} {'cited':>6s} {'per case':>9s}")
    for variant, rows in report["baselines"].items():
        for name, r in rows.items():
            cov, prec = r["coverage"], r["citation_precision"]
            print(f"{variant:16s} {name:26s} {_frac(cov['time_label']['all']):>9s} "
                  f"{_frac(cov['event_label']['all']):>9s} {_frac(cov['time_label']['reachable']):>9s} "
                  f"{_frac(cov['event_label']['reachable']):>9s} {_fmt(prec['event_label']):>7s} "
                  f"{_fmt(prec['time_label']):>7s} {_fmt(r['unsupported_claim_rate']):>7s} "
                  f"{r['alerts_cited']['total']:>6d} {_fmt(r['alerts_cited']['mean_per_case']):>9s}")
    if not args.no_output:
        print(f"Wrote {report['scenario']}.cases.json and {report['scenario']}.case_ceilings.json to "
              f"{Path(args.output_dir) / report['scenario']}")
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
    if args.command == "cases":
        return _cases(args)
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
